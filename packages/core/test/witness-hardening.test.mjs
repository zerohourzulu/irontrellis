// Hardening of the remote witness client and owner API (docs/WITNESS.md §3, §5, §6, §7), against the in-test fake
// witness: the registration at creation (refusals fail it, the binding is written with the first events and carries the
// witness's signed REGISTERED receipt), a later refusal as a sticky WITNESS_REJECTED state, a "not registered" answer that
// contradicts that receipt, addWitness checks before any binding, retired key files found by key (clash suffixes),
// rotation-recorded status per witness, accepting a remote loss with the owner key, plain-http URLs, and the out-of-band
// minimum policy (IRONTRELLIS_WITNESS_POLICY).
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startFakeWitness } from "./helpers/fake-witness.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { createLocalOwner: createLocalOwnerDefault, openLocalOwner: openLocalOwnerDefault, createLocalDomain: createLocalDomainDefault, verifyHistoryWithWitnesses } = await import("../src/owner.ts");
// These tests cover the format-1 (and legacy) owner API; the API writes format 2 by default (SPEC §19), so format 1 is named for every handle and domain made here.
const createLocalOwner = (options) => createLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const openLocalOwner = (options) => openLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const createLocalDomain = (options = {}) => createLocalDomainDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { createOwnerKeyFile, loadOwnerKeyFile, ownerKeyPathFor, retiredOwnerKeyPathFor, retiredOwnerKeyFilesFor } = await import("../src/signer.ts");
const { readWitnessState, witnessStatePathFor, minimumWitnessPolicy, WITNESS_POLICY_ENV } = await import("../src/witness-state.ts");
const { boundRegistrationOf, boundWitnessesOf, resetWitnessViews } = await import("../src/witness-session.ts");
const { normalizeWitnessConfig, isLoopbackHost } = await import("../src/witness-client.ts");

let clock = 5_000_000;
const now = () => (clock += 1);
const config = (w, extra = {}) => ({ url: w.url, verifierKey: w.verifierKey, ...extra });
const policyOf = (witnesses, extra = {}) => ({ witnesses: witnesses.map((w) => config(w)), ...extra });
const SUFFIXES = ["", ".head", ".anchors", ".witness.json"];

function space() {
  const directory = mkdtempSync(join(tmpdir(), "whard-"));
  return { directory, historyFile: join(directory, "history.jsonl"), domain: createLocalDomain() };
}
async function setup(witness, events = 2, extra = {}) {
  const s = space();
  const owner = await createLocalOwner({ historyFile: s.historyFile, domain: s.domain, owner: "owner", controller: "controller", now, ...(witness === undefined ? {} : { witness }), ...extra });
  for (let n = 0; n < events; n += 1) await owner.createAgent({ id: `agent:${n}` });
  const open = (options = {}) => openLocalOwner({ historyFile: s.historyFile, domain: s.domain, owner: "owner", controller: "controller", now, ...options });
  const disk = () => openHistoryStore(s.historyFile, { inspect: true, witness: false }).state();
  return { ...s, owner, open, disk, head: () => disk().head, historyId: () => disk().eventHistoryHashes[0] };
}
const snapshot = (historyFile) => Object.fromEntries(SUFFIXES.map((suffix) => [suffix, existsSync(historyFile + suffix) ? readFileSync(historyFile + suffix) : undefined]));
const restore = (historyFile, snap) => {
  resetWitnessViews();
  for (const [suffix, bytes] of Object.entries(snap)) {
    if (bytes === undefined) rmSync(historyFile + suffix, { force: true });
    else writeFileSync(historyFile + suffix, bytes, { mode: 0o600 });
  }
};
const withEnv = async (name, value, run) => {
  const before = process.env[name];
  if (value === undefined) delete process.env[name]; else process.env[name] = value;
  try { return await run(); } finally { if (before === undefined) delete process.env[name]; else process.env[name] = before; }
};

// ---------------------------------------------------------------- creation (items 4, 11)

test("creation: the genesis is registered before the file exists; the binding is event 2, written with the first events, and carries the signed REGISTERED receipt", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup(policyOf([w], { mode: "sync" }), 0);
  const state = h.disk();
  // Genesis (with the next-key commitment), principal and the binding (position 2), in one write.
  assert.deepEqual(state.events.map((e) => e.type), ["DEPLOYMENT_INITIALIZED", "PRINCIPAL_CREATED", "WITNESSES_BOUND"]);
  assert.ok(state.events[0].data.nextKeyDigests !== undefined);
  assert.deepEqual(Object.keys(state.events[2].data).sort(), ["controlAuthorization", "policy", "witnesses"]);
  const pin = openHistoryStore(h.historyFile, { inspect: true, witness: false }).pinnedHead();
  assert.equal(pin.position, 2, "no pinned state of the history without the binding ever existed");
  const registration = boundRegistrationOf(state, w.verifierKey);
  assert.ok(registration !== undefined, "the binding carries a REGISTERED receipt that verifies with the witness key");
  assert.equal(registration.receipt.entry.historyId, h.historyId());
  assert.deepEqual(w.latest(h.historyId()), h.head(), "sync mode: the head (the binding) is witnessed when creation returns");
  // A receipt signed by another key, or for another history, is not evidence.
  assert.equal(boundRegistrationOf(state, "other+00000000+AQ=="), undefined);
});

test("creation: a witness that refuses the registration (no token, another key) fails createLocalOwner with WITNESS_REJECTED before any file exists; an unreachable one is bound and registered later", async (t) => {
  const locked = await startFakeWitness({ name: "locked", seed: 2, token: "itw_secret" });
  const other = await startFakeWitness({ name: "other", seed: 3 });
  t.after(() => Promise.all([locked.close(), other.close()]));
  for (const witness of [policyOf([locked]), { witnesses: [config(locked, { verifierKey: other.verifierKey })] }]) {
    const s = space();
    await assert.rejects(createLocalOwner({ historyFile: s.historyFile, domain: s.domain, owner: "owner", controller: "controller", now, witness }),
      (e) => e.code === "WITNESS_REJECTED" && /was not created/.test(e.message));
    assert.equal(existsSync(s.historyFile), false);
    assert.equal(existsSync(ownerKeyPathFor(s.historyFile)), false, "the key made for it is removed");
    assert.equal(existsSync(witnessStatePathFor(s.historyFile)), false);
  }
  assert.equal(locked.size, 0, "nothing registered");
  // With the token: registered, bound with the receipt.
  const ok = await setup({ witnesses: [config(locked, { token: "itw_secret" })], mode: "sync" }, 1);
  assert.ok(boundRegistrationOf(ok.disk(), locked.verifierKey) !== undefined);
  // Unreachable at creation: created and bound without a receipt; the queue registers it when it answers.
  other.down = true;
  const later = await setup(policyOf([other], { mode: "async" }), 0);
  assert.equal(later.disk().events[2].type, "WITNESSES_BOUND");
  assert.equal(boundRegistrationOf(later.disk(), other.verifierKey), undefined);
  other.down = false;
  await later.owner.flush();
  assert.deepEqual(other.latest(later.historyId()), later.head());
});

test("a registration refused later is a sticky WITNESS_REJECTED state: owner writes refuse (not WITNESS_UNAVAILABLE), status shows it, a policy change for that witness clears it", async (t) => {
  const open = await startFakeWitness({ name: "open", seed: 4 });
  const locked = await startFakeWitness({ name: "locked2", seed: 5, token: "itw_token" });
  t.after(() => Promise.all([open.close(), locked.close()]));
  const h = await setup(policyOf([open], { mode: "sync" }), 1);
  // A policy-only witness, configured without its token (the side file edited, or bound while it was unreachable).
  const path = witnessStatePathFor(h.historyFile);
  const doc = JSON.parse(readFileSync(path, "utf8"));
  writeFileSync(path, JSON.stringify({ ...doc, policy: { ...doc.policy, witnesses: [...doc.policy.witnesses, config(locked)] } }), { mode: 0o600 });
  resetWitnessViews();
  const owner = h.open();
  const before = h.head();
  await assert.rejects(owner.createAgent({ id: "agent:refused" }), (e) => e.code === "WITNESS_REJECTED" && e.detail.reason === "REGISTRATION_REFUSED" && e.detail.code === "UNAUTHORIZED");
  await assert.rejects(owner.createAgent({ id: "agent:again" }), (e) => e.code === "WITNESS_REJECTED", "sticky");
  assert.deepEqual(h.head(), before, "nothing was appended");
  const status = owner.witnessStatus();
  assert.equal(status.rejected.url, locked.url);
  assert.equal(status.witnesses.find((w) => w.verifierKey === locked.verifierKey).rejected.code, "WITNESS_REJECTED");
  // Another process that never registers (an inspecting reader) sees the side file's record for exactly this config.
  const inspect = openHistoryStore(h.historyFile, { inspect: true });
  assert.equal(inspect.witnessStatus().rejected.url, locked.url);
  inspect.close();
  // The policy change (the token) clears it.
  const fixed = await owner.addWitness(config(locked, { token: "itw_token" }));
  assert.equal(fixed.registered, true);
  await owner.createAgent({ id: "agent:after-fix" });
  assert.deepEqual(locked.latest(h.historyId()), h.head());
  assert.equal(owner.witnessStatus().rejected, undefined);
  assert.equal(openHistoryStore(h.historyFile, { inspect: true }).witnessStatus().rejected, undefined, "the record no longer matches the config");
});

// ---------------------------------------------------------------- a denied registration (item 5)

test("a bound witness that answers 'not registered' although the binding holds its signed REGISTERED receipt: verify fails REMOTE_WITNESS_INVALID, the requireOnOpen gate stays closed, writers refuse and never re-register; a policy-only witness's 404 is a note", async (t) => {
  const w = await startFakeWitness({ name: "forgetful", seed: 6 });
  t.after(() => w.close());
  const h = await setup(policyOf([w], { mode: "sync", requireOnOpen: true, cacheMs: 0 }), 2);
  const id = h.historyId();
  w.histories.delete(id); // the witness lost the history (a data directory restored from before it registered)
  const registrations = w.state.registrations;
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_INVALID") && /denies a registration it signed/.test(f)), report.failures.join("\n"));
  assert.equal(report.remoteWitnesses[0].registrationDenied, true);
  assert.equal((await verifyHistoryWithWitnesses(h.historyFile, { allowUnreachableWitness: true })).ok, false, "not unreachability");
  resetWitnessViews();
  const reader = openHistoryStore(h.historyFile);
  await assert.rejects(reader.checkWitnesses(), (e) => e.code === "WITNESS_INVALID_RESPONSE" && e.detail.reason === "REGISTRATION_DENIED");
  assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
  reader.close();
  const owner = h.open();
  const head = h.head();
  await assert.rejects(owner.createAgent({ id: "agent:x" }), (e) => e.detail?.reason === "REGISTRATION_DENIED");
  assert.deepEqual(h.head(), head);
  assert.equal(w.state.registrations, registrations, "never re-registered (that would hide the loss)");
  assert.equal(owner.witnessStatus().witnesses[0].registrationDenied.code, "WITNESS_INVALID_RESPONSE");
  // Only the owner can decide to drop it: a plain removal works (a denial is no rollback evidence).
  await owner.removeWitness(w.url);
  assert.equal(boundWitnessesOf(h.disk()).length, 0);
  // A witness only configured (never bound with a receipt): its 404 is a note.
  const plain = await setup(undefined, 1);
  const note = await verifyHistoryWithWitnesses(plain.historyFile, { witness: policyOf([w]) });
  assert.equal(note.ok, true, note.failures.join("\n"));
  assert.ok(note.notes.some((n) => n.startsWith("REMOTE_WITNESS_UNREGISTERED")));
});

// ---------------------------------------------------------------- addWitness checks (item 3)

test("addWitness checks everything before it binds: another key or a refusal → WITNESS_REJECTED, unreachable → WITNESS_UNAVAILABLE (allowOffline binds), a rotation head no key can sign → KEY_UNAVAILABLE; nothing is written", async (t) => {
  const first = await startFakeWitness({ name: "first", seed: 7 });
  const added = await startFakeWitness({ name: "added", seed: 8, token: "itw_add" });
  const impostor = await startFakeWitness({ name: "impostor", seed: 9 });
  t.after(() => Promise.all([first.close(), added.close(), impostor.close()]));
  const h = await setup(policyOf([first], { mode: "sync" }), 1);
  const unchanged = () => {
    assert.equal(h.disk().events.length, events, "no binding written");
    assert.ok(!(readWitnessState(witnessStatePathFor(h.historyFile)).policy?.witnesses ?? []).some((w) => w.verifierKey === added.verifierKey), "no policy written");
  };
  let events = h.disk().events.length;
  await assert.rejects(h.owner.addWitness(config(impostor, { verifierKey: added.verifierKey, token: "itw_add" })), (e) => e.code === "WITNESS_REJECTED" && e.detail.cause === "WITNESS_INVALID_RESPONSE");
  unchanged();
  await assert.rejects(h.owner.addWitness(config(added)), (e) => e.code === "WITNESS_REJECTED" && e.detail.code === "UNAUTHORIZED");
  unchanged();
  assert.equal(added.size, 0);
  // Rotate while the new witness is not there yet; a later process (which no longer holds the old key in memory) without the
  // retired key file cannot sign the rotation head the new witness needs.
  const rotated = await h.owner.rotateOwnerKey({ reason: "before the second witness" });
  h.owner.close();
  resetWitnessViews();
  const owner = h.open();
  events = h.disk().events.length;
  const retired = rotated.retiredKeyFile;
  renameSync(retired, `${h.directory}/elsewhere.json`);
  await assert.rejects(owner.addWitness(config(added, { token: "itw_add" })), (e) => e.code === "KEY_UNAVAILABLE" && e.detail.positions.includes(rotated.head.position));
  unchanged();
  renameSync(`${h.directory}/elsewhere.json`, retired);
  // Unreachable: refused without allowOffline, bound (no receipt) with it.
  added.down = true;
  await assert.rejects(owner.addWitness(config(added, { token: "itw_add" })), (e) => e.code === "WITNESS_UNAVAILABLE" && /nothing was written/.test(e.message));
  unchanged();
  const offline = await owner.addWitness(config(added, { token: "itw_add" }), {}, { allowOffline: true });
  assert.equal(offline.registered, false);
  assert.ok(boundWitnessesOf(h.disk()).some((b) => b.verifierKey === added.verifierKey));
  added.down = false;
  await owner.flush();
  assert.deepEqual(added.latest(h.historyId()), h.head(), "registered and brought through the rotation later (the retired key file signs head r)");
  assert.deepEqual(added.histories.get(h.historyId()).epochs.map((e) => e.fromPosition), [0, rotated.head.position + 1]);
  // Adding it again records the registration receipt the offline binding lacked.
  const again = await owner.addWitness(config(added, { token: "itw_add" }));
  assert.equal(again.registered, true);
  assert.ok(boundRegistrationOf(h.disk(), added.verifierKey) !== undefined);
});

test("addWitness refuses a witness that holds a head this copy lacks (ROLLBACK_DETECTED), before binding", async (t) => {
  const w = await startFakeWitness({ name: "ahead", seed: 10 });
  t.after(() => w.close());
  const h = await setup(undefined, 1);
  const old = snapshot(h.historyFile); // before the witness: no binding, no side file
  await h.owner.addWitness(config(w), { mode: "sync" });
  await h.owner.createAgent({ id: "agent:witnessed" });
  h.owner.close();
  restore(h.historyFile, old);
  const owner = h.open();
  const events = h.disk().events.length;
  await assert.rejects(owner.addWitness(config(w)), (e) => e.code === "ROLLBACK_DETECTED" && e.detail.reason === "WITNESS_AHEAD" && /nothing was written/.test(e.message));
  assert.equal(h.disk().events.length, events);
  assert.equal(readWitnessState(witnessStatePathFor(h.historyFile)).policy, undefined);
});

// ---------------------------------------------------------------- retired key files found by key (item 2)

test("the rotation-head statement is signed from an archived key file with a clash suffix (-2), matched by key id AND public key, never by its name", async (t) => {
  const w = await startFakeWitness({ name: "suffix", seed: 11 });
  t.after(() => w.close());
  const h = await setup(policyOf([w], { mode: "sync" }), 1);
  const oldKey = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile));
  // A file already holds the unsuffixed name, with the same key id but another key (planted, or an earlier history's).
  const planted = retiredOwnerKeyPathFor(h.historyFile, oldKey.keyId);
  createOwnerKeyFile(planted, oldKey.keyId);
  w.down = true;
  const rotated = await h.owner.rotateOwnerKey({ reason: "clash", emergency: true });
  assert.match(rotated.retiredKeyFile, /-2\.retired\.json$/);
  assert.deepEqual(retiredOwnerKeyFilesFor(h.historyFile), [planted, rotated.retiredKeyFile]);
  h.owner.close();
  // A fresh process with no queue: the statement for head r must be signed now, by the key in the -2 file.
  rmSync(witnessStatePathFor(h.historyFile));
  w.down = false;
  resetWitnessViews();
  const next = h.open();
  await next.flush();
  const id = h.historyId(), r = rotated.head.position;
  const statement = w.heads(id).find((s) => s.statement.head.position === r);
  assert.equal(statement.keyId, oldKey.keyId);
  assert.equal(statement.statement.head.hash, h.disk().eventHistoryHashes[r]);
  assert.deepEqual(w.histories.get(id).epochs.map((e) => e.fromPosition), [0, r + 1]);
});

// ---------------------------------------------------------------- rotation recorded, per witness (item 1)

test("witnessStatus shows per witness how many owner key rotations it has not recorded (null when not asked)", async (t) => {
  const w = await startFakeWitness({ name: "rotations", seed: 12 });
  t.after(() => w.close());
  const h = await setup(policyOf([w], { mode: "sync" }), 1);
  assert.equal(h.owner.witnessStatus().keyRotations, 0);
  w.down = true;
  await h.owner.rotateOwnerKey({ emergency: true });
  h.owner.close();
  w.down = false;
  resetWitnessViews();
  const inspect = openHistoryStore(h.historyFile, { inspect: true });
  assert.equal(inspect.witnessStatus().keyRotations, 1);
  assert.equal(inspect.witnessStatus().witnesses[0].pendingRotations, null, "not asked yet");
  await inspect.verifyWithWitnesses();
  assert.equal(inspect.witnessStatus().witnesses[0].pendingRotations, 1, "the witness has not recorded it: keep the retired key");
  inspect.close();
  const owner = h.open();
  await owner.flush();
  assert.equal(owner.witnessStatus().witnesses[0].pendingRotations, 0);
});

// ---------------------------------------------------------------- accepting a remote loss (item 7)

test("accepting a remote loss: owner key only, only for witnesses whose own answer shows the loss, other witnesses' alarms stay, the reason is recorded, the history continues", async (t) => {
  const a = await startFakeWitness({ name: "loss-a", seed: 13 });
  const b = await startFakeWitness({ name: "loss-b", seed: 14 });
  t.after(() => Promise.all([a.close(), b.close()]));
  const h = await setup(policyOf([a, b], { mode: "sync" }), 1);
  const old = snapshot(h.historyFile);
  await h.owner.createAgent({ id: "agent:lost-1" });
  await h.owner.createAgent({ id: "agent:lost-2" });
  const lost = h.head();
  h.owner.close();
  // A real loss: every surviving copy is the old one; both witnesses hold heads it lacks.
  restore(h.historyFile, old);
  // Without witnessRecovery the recorded finding (side file) fails the open; with it the handle opens and still refuses.
  const owner = h.open({ witnessRecovery: true });
  await assert.rejects(owner.createAgent({ id: "agent:x" }), (e) => e.code === "ROLLBACK_DETECTED");
  // A handle without the owner key cannot accept anything.
  const key = ownerKeyPathFor(h.historyFile);
  renameSync(key, `${key}.away`);
  resetWitnessViews();
  const keyless = h.open({ witnessRecovery: true });
  await assert.rejects(keyless.removeWitness(a.url, { acceptRemoteLoss: true, reason: "restored the last backup" }), (e) => e.code === "KEY_UNAVAILABLE");
  keyless.close();
  renameSync(`${key}.away`, key);
  // The reason is required.
  await assert.rejects(owner.removeWitness(a.url, { acceptRemoteLoss: true }), (e) => e.code === "INVALID_INPUT");
  // Accepting A's loss alone does not clear B's alarm: the unbinding write is refused by B, and A's alarm comes back.
  const events = h.disk().events.length;
  await assert.rejects(owner.removeWitness(a.url, { acceptRemoteLoss: true, reason: "restored the last backup" }), (e) => e.code === "ROLLBACK_DETECTED" && e.detail.witness === b.url);
  assert.equal(h.disk().events.length, events, "nothing written");
  await assert.rejects(owner.createAgent({ id: "agent:y" }), (e) => e.code === "ROLLBACK_DETECTED");
  // Both at once: recorded with the reason and the heads they hold.
  const change = await owner.removeWitness([a.url, b.url], { acceptRemoteLoss: true, reason: "restored the last backup" });
  assert.equal(change.acceptedLoss.reason, "restored the last backup");
  assert.deepEqual(change.acceptedLoss.heads.map((x) => x.head.position).sort(), [lost.position, lost.position]);
  const state = h.disk();
  const unbinding = state.events.find((e) => e.id === change.eventId);
  assert.equal(unbinding.type, "WITNESSES_UNBOUND");
  assert.deepEqual([...unbinding.data.verifierKeys].sort(), [a.verifierKey, b.verifierKey].sort());
  assert.equal(unbinding.data.acceptedLoss.reason, "restored the last backup");
  assert.deepEqual(unbinding.data.acceptedLoss.heads.map((x) => x.head.position), [lost.position, lost.position]);
  assert.ok(unbinding.data.controlAuthorization !== undefined, "owner-signed");
  assert.equal(boundWitnessesOf(state).length, 0);
  await owner.createAgent({ id: "agent:continues" });
  owner.close();
  resetWitnessViews();
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.deepEqual(a.latest(h.historyId()), lost, "the witness keeps what it received");
});

test("accepting a loss from one witness leaves the others in force; a witness that shows no loss cannot be dropped that way", async (t) => {
  const a = await startFakeWitness({ name: "one-a", seed: 15 });
  const b = await startFakeWitness({ name: "one-b", seed: 16 });
  t.after(() => Promise.all([a.close(), b.close()]));
  // Quorum 2 of 2: a round needs one answer, so A takes the statements while B is down.
  const h = await setup(policyOf([a, b], { mode: "sync", quorum: 2 }), 1);
  const old = snapshot(h.historyFile);
  b.down = true; // B misses the events that are lost
  await h.owner.createAgent({ id: "agent:lost" });
  h.owner.close();
  restore(h.historyFile, old);
  b.down = false;
  const owner = h.open();
  await assert.rejects(owner.createAgent({ id: "agent:x" }), (e) => e.code === "ROLLBACK_DETECTED" && e.detail.witness === a.url);
  await assert.rejects(owner.removeWitness(b.url, { acceptRemoteLoss: true, reason: "b is fine" }), (e) => e.code === "INVALID_INPUT" && e.detail.reason === "NO_LOSS");
  await owner.removeWitness(a.url, { acceptRemoteLoss: true, reason: "restored the last backup" });
  const written = await owner.createAgent({ id: "agent:continues" });
  assert.deepEqual(b.latest(h.historyId()), written.head, "the remaining witness witnesses the continued history");
  assert.deepEqual(boundWitnessesOf(h.disk()).map((w) => w.verifierKey), [b.verifierKey]);
});

// ---------------------------------------------------------------- plain http (item 6)

test("isLoopbackHost and normalizeWitnessConfig refuse plain http to other hosts", async (t) => {
  const w = await startFakeWitness({ name: "http-check", seed: 17 });
  t.after(() => w.close());
  for (const host of ["localhost", "127.0.0.1", "127.255.0.9", "[::1]"]) assert.equal(isLoopbackHost(host), true, host);
  for (const host of ["10.0.0.1", "128.0.0.1", "localhost.example", "[::2]", "127.0.0.256"]) assert.equal(isLoopbackHost(host), false, host);
  assert.throws(() => normalizeWitnessConfig({ url: "http://witness.example.org", verifierKey: w.verifierKey }), (e) => e.code === "INVALID_INPUT" && e.detail.reason === "INSECURE_HTTP");
  assert.equal(normalizeWitnessConfig({ url: "http://witness.example.org", verifierKey: w.verifierKey, allowInsecureHttp: true }).allowInsecureHttp, true);
  assert.equal(normalizeWitnessConfig({ url: "https://witness.example.org/", verifierKey: w.verifierKey }).url, "https://witness.example.org");
  assert.equal(normalizeWitnessConfig({ url: w.url, verifierKey: w.verifierKey }).url, w.url);
  const s = space();
  await assert.rejects(createLocalOwner({ historyFile: s.historyFile, domain: s.domain, owner: "o", controller: "o", now, witness: { witnesses: [{ url: "http://10.1.2.3:8411", verifierKey: w.verifierKey }] } }),
    (e) => e.code === "INVALID_INPUT");
  assert.equal(existsSync(s.historyFile), false);
});

// ---------------------------------------------------------------- the out-of-band minimum policy (item 11)

test("IRONTRELLIS_WITNESS_POLICY: a minimum every store open merges (adds witnesses, raises requirements); unusable → WITNESS_UNREADABLE; `witness: false` is the caller's own choice", async (t) => {
  const w = await startFakeWitness({ name: "minimum", seed: 18 });
  t.after(() => w.close());
  const h = await setup(undefined, 2); // no witness at all in the history or its side file
  const dir = mkdtempSync(join(tmpdir(), "whard-policy-"));
  const file = join(dir, "irontrellis-witness-policy.json");
  writeFileSync(file, JSON.stringify({ witnesses: [config(w)], requireOnOpen: true }), { mode: 0o600 });
  const old = snapshot(h.historyFile);
  await withEnv(WITNESS_POLICY_ENV, file, async () => {
    assert.equal(minimumWitnessPolicy().witnesses.length, 1);
    assert.equal(minimumWitnessPolicy().maxUnwitnessedEvents, undefined, "absent fields constrain nothing");
    resetWitnessViews();
    const owner = h.open();
    const status = owner.witnessStatus();
    assert.equal(status.minimumPolicyFile, file);
    assert.equal(status.policy.requireOnOpen, true);
    await owner.createAgent({ id: "agent:witnessed" });
    await owner.flush();
    assert.deepEqual(w.latest(h.historyId()), h.head());
    // The side file cannot remove it, and removeWitness refuses to.
    await assert.rejects(owner.removeWitness(w.url), (e) => e.code === "INVALID_INPUT" && /IRONTRELLIS_WITNESS_POLICY/.test(e.message));
    owner.close();
    // A copy from before the witness (no binding, no side file) is refused by every opener that takes the minimum.
    restore(h.historyFile, old);
    const report = await verifyHistoryWithWitnesses(h.historyFile);
    assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")), report.failures.join("\n"));
    await assert.rejects(h.open().createAgent({ id: "agent:fork" }), (e) => e.code === "ROLLBACK_DETECTED");
    // `witness: false` is an explicit choice of the caller (inspection).
    assert.equal(openHistoryStore(h.historyFile, { witness: false }).witnessStatus(), undefined);
    // Unusable: fail closed.
    if (process.platform !== "win32") { // Windows modes are synthetic: the ACL protects the file there (docs/PLATFORMS.md §3)
      chmodSync(file, 0o664);
      assert.throws(() => openHistoryStore(h.historyFile), (e) => e.code === "WITNESS_UNREADABLE" && e.detail.reason === "WITNESS_POLICY_UNREADABLE");
      chmodSync(file, 0o600);
    }
    writeFileSync(file, "{ not json", { mode: 0o600 });
    assert.throws(() => openHistoryStore(h.historyFile), (e) => e.code === "WITNESS_UNREADABLE");
    writeFileSync(file, JSON.stringify({ witnesses: [{ url: "http://10.9.9.9", verifierKey: w.verifierKey }] }), { mode: 0o600 });
    assert.throws(() => openHistoryStore(h.historyFile), (e) => e.code === "WITNESS_UNREADABLE" && /plain http/.test(e.message));
  });
  await withEnv(WITNESS_POLICY_ENV, "relative/policy.json", async () => {
    assert.throws(() => minimumWitnessPolicy(), (e) => e.code === "WITNESS_UNREADABLE" && /absolute/.test(e.message));
  });
  await withEnv(WITNESS_POLICY_ENV, "", async () => assert.equal(minimumWitnessPolicy(), undefined));
});

test("IRONTRELLIS_WITNESS_POLICY at creation: its witnesses are registered and bound with the first events; it only raises the history's own requirements", async (t) => {
  const own = await startFakeWitness({ name: "own", seed: 19 });
  const operator = await startFakeWitness({ name: "operator", seed: 20 });
  t.after(() => Promise.all([own.close(), operator.close()]));
  const dir = mkdtempSync(join(tmpdir(), "whard-policy-"));
  const file = join(dir, "policy.json");
  writeFileSync(file, JSON.stringify({ witnesses: [config(operator)], mode: "sync", maxUnwitnessedEvents: 5, cacheMs: 1000 }), { mode: 0o600 });
  await withEnv(WITNESS_POLICY_ENV, file, async () => {
    const h = await setup(policyOf([own], { mode: "async", maxUnwitnessedEvents: 50, requireOnOpen: true }), 0);
    assert.deepEqual(boundWitnessesOf(h.disk()).map((b) => b.verifierKey).sort(), [own.verifierKey, operator.verifierKey].sort());
    const policy = h.owner.witnessStatus().policy;
    assert.equal(policy.mode, "sync", "raised");
    assert.equal(policy.maxUnwitnessedEvents, 5, "lowered bound");
    assert.equal(policy.requireOnOpen, true, "kept (the minimum does not lower it)");
    assert.equal(policy.cacheMs, 1000);
    const doc = readWitnessState(witnessStatePathFor(h.historyFile));
    assert.deepEqual(doc.policy.witnesses.map((w) => w.verifierKey), [own.verifierKey], "the side file keeps the history's own policy");
  });
});

// ---------------------------------------------------------------- coherence F1 regression: anchors can never bind

test("regression (coherence F1): no anchor path (http, rekor, custom, a hand-built anchor) can bind, unbind or re-policy a remote witness, whatever the anchor receipt says", async (t) => {
  const core = await import("../src/index.ts");
  const anchorModule = await import("../src/anchor.ts");
  const { canonicalEncode } = await import("../src/canonical.ts");
  const { signControlEvent } = await import("../src/signer.ts");
  const s = space();
  const { verifierKey } = core.generateNoteKey("w.example");
  const attacker = core.generateNoteKey("evil.example");
  const down = async () => { throw new TypeError("fetch failed"); };
  await createLocalOwner({ historyFile: s.historyFile, domain: s.domain, owner: "owner", controller: "controller", now, witness: { witnesses: [{ url: "https://w.example", verifierKey }], fetch: down } });
  const signer = loadOwnerKeyFile(ownerKeyPathFor(s.historyFile));
  const reopen = () => openHistoryStore(s.historyFile, { signer, witness: { witnesses: [], fetch: down } });
  let store = reopen();
  const bound = () => boundWitnessesOf(reopen().state()).map((w) => w.verifierKey);
  const policy = () => canonicalEncode(core.boundPolicyOf(reopen().state()) ?? null);
  assert.deepEqual(bound(), [verifierKey]);
  const policyBefore = policy();
  const historyId = store.state().eventHistoryHashes[0];
  // Everything a hostile endpoint could answer: unbind the bound witness, bind the attacker's, raise the policy minimum.
  const hostile = [
    { version: "irontrellis-witness-binding/1", action: "UNBIND", historyId, witnesses: [{ url: "https://w.example", verifierKey }] },
    { version: "irontrellis-witness-binding/1", action: "BIND", historyId, witnesses: [{ url: "https://evil.example", verifierKey: attacker.verifierKey }], policy: { quorum: 2, requireOnOpen: true, maxUnwitnessedEvents: 1 } },
    { action: "UNBIND", verifierKeys: [verifierKey], policy: { quorum: 1, requireOnOpen: true, maxUnwitnessedEvents: 1 } },
  ];
  const answering = (body) => async () => new Response(JSON.stringify(body), { status: 200 });
  const custom = (body) => ({ kind: "custom", name: "custom", submit: async () => body });
  let n = 0;
  for (const body of hostile) {
    const paths = [["custom", custom(body)], ["rekor", anchorModule.rekorAnchor({ fetch: answering(body) })]];
    if (typeof anchorModule.httpWitness === "function") paths.push(["http", anchorModule.httpWitness("https://evil.example/anchor", { fetch: answering(body) })]);
    for (const [kind, witness] of paths) {
      store = reopen();
      try { await core.anchorHead(store, signer, witness, { id: `event:anchor:${(n += 1)}`, anchoredAt: now() }); } catch { /* a refused anchor is fine too */ }
      assert.deepEqual(bound(), [verifierKey], `a ${kind} anchor answering ${JSON.stringify(body).slice(0, 60)}… must not change the bound witnesses`);
      assert.equal(policy(), policyBefore, `a ${kind} anchor must not change the bound policy`);
    }
  }
  // An owner-signed ANCHOR_RECORDED built by hand with the old binding literal is not a binding either (refused, or ignored).
  for (const body of hostile) {
    store = reopen();
    const state = store.state();
    const unsigned = { id: `event:anchor:${(n += 1)}`, type: "ANCHOR_RECORDED", timestamp: now(), data: { anchoredHead: state.head, anchor: "http-witness", receipt: body, anchoredAt: now() } };
    const event = await signControlEvent(signer, unsigned, state.genesis.domain, state.head, state.hashAlgorithm);
    try { store.withExclusiveWriter((writer) => writer.appendAtExpectedHead(event, state.head)); } catch { /* refused */ }
    assert.deepEqual(bound(), [verifierKey]);
    assert.equal(policy(), policyBefore);
  }
});
