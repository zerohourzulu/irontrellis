// The remote witness client (docs/reference/witness-protocol.md §9.6, §9.7) against the in-test fake witness (helpers/fake-witness.mjs):
// verified checkpoints and receipts, consistency against remembered checkpoints (split view), the protocol answers
// (STALE_PREVIOUS, EQUIVOCATION, NOT_REGISTERED, KEY_EVENT_HEAD_UNKNOWN), transport failures, policy validation and
// the side file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startFakeWitness } from "./helpers/fake-witness.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const client = await import("../src/witness-client.ts");
const sessionModule = await import("../src/witness-session.ts");
const stateModule = await import("../src/witness-state.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { createLocalOwner: createLocalOwnerDefault, createLocalDomain: createLocalDomainDefault } = await import("../src/owner.ts");
// These tests cover the format-1 (and legacy) owner API; the API writes format 2 by default (SPEC §19), so format 1 is named for every handle and domain made here.
const createLocalOwner = (options) => createLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const createLocalDomain = (options = {}) => createLocalDomainDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { loadOwnerKeyFile, ownerKeyPathFor } = await import("../src/signer.ts");
const { generateNoteKey } = await import("../src/transparency/index.ts");

const { remoteWitness, normalizeWitnessPolicy, memoryCheckpointTracker, witnessesToConsult } = client;
const { signStatement } = sessionModule;

/** A fresh format-1 history (no witness) with `events` agents, its owner signer and a reader for its state. */
async function history(events = 3, directory = mkdtempSync(join(tmpdir(), "wclient-"))) {
  const historyFile = join(directory, "history.jsonl");
  let clock = 1_000;
  const owner = await createLocalOwner({ historyFile, domain: createLocalDomain(), owner: "owner", controller: "controller", now: () => (clock += 1), witness: false });
  for (let n = 0; n < events; n += 1) await owner.createAgent({ id: `agent:${n}` });
  const signer = loadOwnerKeyFile(ownerKeyPathFor(historyFile));
  const state = () => openHistoryStore(historyFile, { witness: false }).state();
  return { historyFile, owner, signer, state, directory };
}

const headOf = (state) => ({ hash: state.head.hash, position: state.head.position });

test("register, submit and read back: every receipt and checkpoint verifies with the configured key", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await history(3);
  const c = remoteWitness({ url: `${w.url}/`, verifierKey: w.verifierKey });
  assert.equal(c.url, w.url, "the base url is normalised");
  const info = await c.info();
  assert.equal(info.origin, w.origin);
  assert.equal(info.verifierKey, w.verifierKey);
  const state = h.state();
  const registered = await c.register(state.events[0]);
  assert.equal(registered.historyId, state.eventHistoryHashes[0]);
  assert.equal(registered.created, true);
  assert.equal((await c.register(state.events[0])).created, false, "registration is idempotent");
  const before = await c.history(state.eventHistoryHashes[0]);
  assert.equal(before.latest, null);
  assert.equal(before.equivocations, 0);
  const first = await c.submit(await signStatement(h.signer, state, null));
  assert.equal(first.kind, "ACCEPTED");
  assert.equal(first.status, "APPENDED");
  assert.deepEqual(first.latest.head, state.head);
  const again = await c.submit(await signStatement(h.signer, state, headOf(state)));
  assert.equal(again.kind, "ACCEPTED");
  assert.equal(again.status, "ALREADY_WITNESSED");
  const read = await c.head(state.eventHistoryHashes[0], state.head.position);
  assert.deepEqual(read.head, state.head);
  const summary = await c.history(state.eventHistoryHashes[0]);
  assert.deepEqual(summary.latest.head, state.head);
  assert.equal(c.origin, w.origin);
  const checkpoint = await c.checkpoint();
  assert.equal(checkpoint.size, w.size);
  const entries = await c.entries(0, 10);
  assert.deepEqual(entries.map((e) => e.kind), ["REGISTERED", "HEAD"]);
  assert.equal(await c.history(`0x${"ab".repeat(32)}`), undefined, "an unknown history reads as undefined");
});

test("STALE_PREVIOUS and EQUIVOCATION come back as answers; an equivocation is evidence, deduped, and the history stays open (§9.1)", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await history(2);
  const c = remoteWitness({ url: w.url, verifierKey: w.verifierKey });
  const s1 = h.state();
  await c.register(s1.events[0]);
  assert.equal((await c.submit(await signStatement(h.signer, s1, null))).kind, "ACCEPTED");
  // A diverged copy at the same position, signed by the same owner key.
  const copy = mkdtempSync(join(tmpdir(), "wclient-copy-"));
  for (const suffix of ["", ".head", ".owner-key.json"]) copyFileSync(`${h.historyFile}${suffix}`, join(copy, `history.jsonl${suffix}`));
  await h.owner.createAgent({ id: "agent:a" });
  const { openLocalOwner } = await import("../src/owner.ts");
  const other = openLocalOwner({ historyFile: join(copy, "history.jsonl"), domain: s1.genesis.domain, owner: "owner", controller: "controller", now: () => 5_000, witness: false, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  await other.createAgent({ id: "agent:b" });
  const a = h.state(), b = openHistoryStore(join(copy, "history.jsonl"), { witness: false }).state();
  assert.equal(a.head.position, b.head.position);
  assert.notEqual(a.head.hash, b.head.hash);
  // Stale: previous null although the witness holds a head.
  const stale = await c.submit(await signStatement(h.signer, a, null));
  assert.equal(stale.kind, "STALE_PREVIOUS");
  assert.deepEqual(stale.latest.head, s1.head);
  assert.equal((await c.submit(await signStatement(h.signer, a, headOf(s1)))).kind, "ACCEPTED");
  const forked = await signStatement(h.signer, b, headOf(s1));
  const fork = await c.submit(forked);
  assert.equal(fork.kind, "EQUIVOCATION");
  assert.equal(fork.receipt.entry.kind, "EQUIVOCATION");
  assert.deepEqual(fork.receipt.entry.second, forked, "the evidence records the submitted statement");
  assert.deepEqual(fork.latest.head, a.head, "the reply names the witness latest");
  const size = w.size;
  const again = await c.submit(forked);
  assert.equal(again.kind, "EQUIVOCATION");
  assert.equal(again.index, fork.index, "the same conflicting statement is recorded once");
  assert.equal(w.size, size);
  const summary = await c.history(s1.eventHistoryHashes[0]);
  assert.equal(summary.equivocations, 1);
  assert.equal(summary.lastEquivocation.index, fork.index);
  assert.equal(summary.lastEquivocation.receipt.entry.kind, "EQUIVOCATION");
  // Not frozen: the owner continues on the witnessed branch.
  await h.owner.createAgent({ id: "agent:a2" });
  const next = await c.submit(await signStatement(h.signer, h.state(), headOf(a)));
  assert.equal(next.kind, "ACCEPTED");
  assert.equal(next.status, "APPENDED");
  assert.equal((await c.history(s1.eventHistoryHashes[0])).equivocations, 1);
});

test("an EQUIVOCATION answer must carry verifiable evidence naming the submitted statement", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await history(2);
  const s1 = h.state();
  const c0 = remoteWitness({ url: w.url, verifierKey: w.verifierKey });
  await c0.register(s1.events[0]);
  assert.equal((await c0.submit(await signStatement(h.signer, s1, null))).kind, "ACCEPTED");
  await h.owner.createAgent({ id: "agent:a" });
  const a = h.state();
  assert.equal((await c0.submit(await signStatement(h.signer, a, headOf(s1)))).kind, "ACCEPTED");
  // A witness that answers EQUIVOCATION with a receipt for another entry (or none) is invalid, never an alarm.
  const lying = (rewrite) => async (url, init) => {
    const response = await globalThis.fetch(url, init);
    if (init.method !== "POST" || !new URL(url).pathname.endsWith("/heads")) return response;
    const body = JSON.parse(await response.text());
    const text = JSON.stringify(rewrite(body));
    return { ok: false, status: 409, text: async () => text };
  };
  const statement = await signStatement(h.signer, a, headOf(s1)); // already held: the real answer is ALREADY_WITNESSED
  const noReceipt = remoteWitness({ url: w.url, verifierKey: w.verifierKey, fetch: lying((body) => ({ error: { code: "EQUIVOCATION", message: "x" }, latest: body.latest })) });
  await assert.rejects(noReceipt.submit(statement), (e) => e.code === "WITNESS_INVALID_RESPONSE");
  const wrongEntry = remoteWitness({ url: w.url, verifierKey: w.verifierKey, fetch: lying((body) => ({ error: { code: "EQUIVOCATION", message: "x" }, receipt: body.receipt, latest: body.latest })) });
  await assert.rejects(wrongEntry.submit(statement), (e) => e.code === "WITNESS_INVALID_RESPONSE" && /EQUIVOCATION entry/.test(e.message));
});

test("a tampered receipt or a checkpoint signed by another key is WITNESS_INVALID_RESPONSE", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await history(1);
  const state = h.state();
  const c = remoteWitness({ url: w.url, verifierKey: w.verifierKey });
  await c.register(state.events[0]);
  w.tamper = "proof";
  await assert.rejects(c.submit(await signStatement(h.signer, state, null)), (e) => e.code === "WITNESS_INVALID_RESPONSE" && /INCLUSION_INVALID/.test(e.message));
  w.tamper = "entry";
  await assert.rejects(c.history(state.eventHistoryHashes[0]), (e) => e.code === "WITNESS_INVALID_RESPONSE");
  w.tamper = undefined;
  const stranger = remoteWitness({ url: w.url, verifierKey: generateNoteKey("fake-witness").verifierKey });
  await assert.rejects(stranger.checkpoint(), (e) => e.code === "WITNESS_INVALID_RESPONSE" && /does not verify/.test(e.message));
  await assert.rejects(stranger.info(), (e) => e.code === "WITNESS_INVALID_RESPONSE" && /serves verifier key/.test(e.message));
  w.wrongKey();
  await assert.rejects(c.checkpoint(), (e) => e.code === "WITNESS_INVALID_RESPONSE");
});

test("split view: a checkpoint the witness cannot prove consistent is WITNESS_SPLIT_VIEW, sticky, and remembered across clients", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await history(1);
  const state = h.state();
  const tracker = memoryCheckpointTracker();
  const c = remoteWitness({ url: w.url, verifierKey: w.verifierKey }, { tracker });
  await c.register(state.events[0]);
  await c.submit(await signStatement(h.signer, state, null));
  assert.equal(tracker.get(w.origin).size, 2);
  w.splitView();
  await assert.rejects(c.checkpoint(), (e) => e.code === "WITNESS_SPLIT_VIEW");
  await assert.rejects(c.info(), (e) => e.code === "WITNESS_SPLIT_VIEW", "sticky: every later call fails the same way");
  assert.equal(c.splitView.code, "WITNESS_SPLIT_VIEW");
  // A new client with the same (persisted) tracker detects it too; one without it cannot.
  const again = remoteWitness({ url: w.url, verifierKey: w.verifierKey }, { tracker });
  await assert.rejects(again.checkpoint(), (e) => e.code === "WITNESS_SPLIT_VIEW");
  const fresh = remoteWitness({ url: w.url, verifierKey: w.verifierKey });
  assert.equal((await fresh.checkpoint()).size, 2);
});

test("a smaller checkpoint than the remembered one must be proven a prefix of it", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await history(2);
  const state = h.state();
  const tracker = memoryCheckpointTracker();
  const c = remoteWitness({ url: w.url, verifierKey: w.verifierKey }, { tracker });
  await c.register(state.events[0]);
  const small = await c.checkpoint();
  await c.submit(await signStatement(h.signer, state, null));
  // Another process remembered a larger checkpoint; this process sees an older one: consistent, the larger is kept.
  const c2 = remoteWitness({ url: w.url, verifierKey: w.verifierKey }, { tracker });
  assert.equal(tracker.get(w.origin).size, 2);
  tracker.set(w.origin, { size: small.size, rootB64: small.rootB64, note: small.note });
  const seen = await c2.checkpoint();
  assert.equal(seen.size, 2);
  assert.equal(tracker.get(w.origin).size, 2);
  // A forged remembered checkpoint (not signed by the key) is ignored, never trusted.
  tracker.set(w.origin, { size: 99, rootB64: small.rootB64, note: small.note });
  assert.equal((await remoteWitness({ url: w.url, verifierKey: w.verifierKey }, { tracker }).checkpoint()).size, 2);
});

test("split view by a shorter log under the same key: a witness that refuses the consistency proof to a tree it signed is WITNESS_SPLIT_VIEW, not unavailable", async (t) => {
  const w = await startFakeWitness();
  const impostor = await startFakeWitness(); // the same name and seed: the same note key, another (shorter) log
  t.after(() => Promise.all([w.close(), impostor.close()]));
  assert.equal(impostor.verifierKey, w.verifierKey);
  const h = await history(2);
  const state = h.state();
  const tracker = memoryCheckpointTracker();
  const c = remoteWitness({ url: w.url, verifierKey: w.verifierKey }, { tracker });
  await c.register(state.events[0]);
  await c.submit(await signStatement(h.signer, state, null));
  assert.equal(tracker.get(w.origin).size, 2);
  // The shorter log signs a size-1 tree; asked to prove it a prefix of the remembered size-2 tree, it answers 400.
  const other = remoteWitness({ url: impostor.url, verifierKey: w.verifierKey }, { tracker });
  await assert.rejects(other.register(state.events[0]), (e) => e.code === "WITNESS_SPLIT_VIEW" && /refuses to prove/.test(e.message));
  assert.equal(other.splitView?.code, "WITNESS_SPLIT_VIEW", "sticky");
  // A transport failure on the proof request stays WITNESS_UNAVAILABLE (transient).
  const flaky = remoteWitness({ url: w.url, verifierKey: w.verifierKey }, {
    tracker: memoryCheckpointTracker(),
    fetch: async (url, init) => { if (url.includes("/v1/proofs/consistency")) throw new Error("connection reset"); return globalThis.fetch(url, init); },
  });
  await flaky.checkpoint();
  await c.submit(await signStatement(h.signer, h.state(), headOf(state))); // nothing new, but the tree is unchanged
  await h.owner.createAgent({ id: "agent:more" });
  await c.submit(await signStatement(h.signer, h.state(), headOf(state)));
  await assert.rejects(flaky.checkpoint(), (e) => e.code === "WITNESS_UNAVAILABLE");
  assert.equal(flaky.splitView, undefined);
});

test("key events: KEY_EVENT_HEAD_UNKNOWN until the old-key statement for the rotation head is held, then accepted with new epochs", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await history(1);
  const c = remoteWitness({ url: w.url, verifierKey: w.verifierKey });
  const before = h.state();
  await c.register(before.events[0]);
  await c.submit(await signStatement(h.signer, before, null));
  const rotated = await h.owner.rotateOwnerKey({ reason: "scheduled" });
  const state = h.state();
  const r = rotated.head.position;
  const body = {
    event: state.events[r], previousHead: { hash: state.eventHistoryHashes[r - 1], position: r - 1 }, eventHead: { hash: state.eventHistoryHashes[r], position: r },
  };
  const early = await c.keyEvent(state.eventHistoryHashes[0], body);
  assert.equal(early.kind, "REJECTED");
  assert.equal(early.code, "KEY_EVENT_HEAD_UNKNOWN");
  // The new key is unknown to the witness until the rotation is posted: ROTATION_REQUIRED.
  await h.owner.createAgent({ id: "agent:after" });
  const newSigner = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile));
  const later = h.state();
  const refused = await c.submit(await signStatement(newSigner, later, headOf(before)));
  assert.equal(refused.kind, "REJECTED");
  assert.equal(refused.hint, "ROTATION_REQUIRED");
  // Old key signs head r (as rotateOwnerKey would have, while it held it), then the rotation, then the new key.
  const { signHeadStatement, HEAD_STATEMENT_VERSION } = await import("../src/transparency/index.ts");
  const headR = { hash: state.eventHistoryHashes[r], position: r, canonicalTime: state.events[r].timestamp };
  const statementR = await signHeadStatement(h.signer, { version: HEAD_STATEMENT_VERSION, historyId: state.eventHistoryHashes[0], domain: state.genesis.domain, head: headR, previous: headOf(before) });
  assert.equal((await c.submit(statementR)).kind, "ACCEPTED");
  const accepted = await c.keyEvent(state.eventHistoryHashes[0], body);
  assert.equal(accepted.kind, "ACCEPTED");
  assert.deepEqual(accepted.epochs.map((e) => e.fromPosition), [0, r + 1]);
  assert.deepEqual(accepted.receipt.entry.previousHead, body.previousHead, "the ROTATED leaf carries the head the rotation's signature binds (§9.2)");
  // A ROTATED leaf that names another previousHead than the one sent is not believed (here the transport swaps the request's).
  const wrongPrevious = { hash: state.eventHistoryHashes[r - 2], position: r - 1 };
  const swapped = remoteWitness({ url: w.url, verifierKey: w.verifierKey, fetch: (url, init) =>
    globalThis.fetch(url, new URL(url).pathname.endsWith("/key-events") ? { ...init, body: JSON.stringify({ ...JSON.parse(init.body), previousHead: body.previousHead }) } : init) });
  await assert.rejects(swapped.keyEvent(state.eventHistoryHashes[0], { ...body, previousHead: wrongPrevious }), (e) => e.code === "WITNESS_INVALID_RESPONSE" && /ROTATED/.test(e.message));
  const direct = await c.keyEvent(state.eventHistoryHashes[0], { ...body, previousHead: wrongPrevious });
  assert.equal(direct.kind, "REJECTED", "the same rotation with another previousHead is not idempotent");
  assert.equal(direct.code, "KEY_EVENT_INVALID");
  assert.equal((await c.keyEvent(state.eventHistoryHashes[0], body)).kind, "ACCEPTED", "idempotent");
  assert.equal((await c.submit(await signStatement(newSigner, later, { hash: headR.hash, position: r }))).kind, "ACCEPTED");
});

test("transport failures are WITNESS_UNAVAILABLE; 4xx refusals WITNESS_REJECTED; the timeout aborts", async (t) => {
  const w = await startFakeWitness({ token: "s3cret" });
  t.after(() => w.close());
  const h = await history(1);
  const state = h.state();
  const c = remoteWitness({ url: w.url, verifierKey: w.verifierKey });
  await assert.rejects(c.register(state.events[0]), (e) => e.code === "WITNESS_REJECTED" && e.detail.code === "UNAUTHORIZED");
  const authorized = remoteWitness({ url: w.url, verifierKey: w.verifierKey, token: "s3cret" });
  assert.equal((await authorized.register(state.events[0])).created, true);
  w.down = true;
  await assert.rejects(c.checkpoint(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.status === 503);
  w.down = false;
  const closed = remoteWitness({ url: "http://127.0.0.1:9", verifierKey: w.verifierKey, timeoutMs: 2000 });
  await assert.rejects(closed.checkpoint(), (e) => e.code === "WITNESS_UNAVAILABLE");
  const hanging = remoteWitness({ url: w.url, verifierKey: w.verifierKey, timeoutMs: 50, fetch: (_url, init) => new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason))) });
  const started = Date.now();
  await assert.rejects(hanging.checkpoint(), (e) => e.code === "WITNESS_UNAVAILABLE");
  assert.ok(Date.now() - started < 2000);
  const garbage = remoteWitness({ url: w.url, verifierKey: w.verifierKey, fetch: async () => ({ ok: true, status: 200, text: async () => "<html>" }) });
  await assert.rejects(garbage.history(state.eventHistoryHashes[0]), (e) => e.code === "WITNESS_UNAVAILABLE");
});

test("policy validation and defaults", () => {
  const { verifierKey } = generateNoteKey("w1");
  const policy = normalizeWitnessPolicy({ witnesses: [{ url: "https://w.example/", verifierKey }] });
  assert.deepEqual({ ...policy, witnesses: undefined }, { witnesses: undefined, quorum: 1, mode: "async", maxUnwitnessedEvents: 1000, requireOnOpen: false, cacheMs: 60000 });
  assert.equal(policy.witnesses[0].url, "https://w.example");
  const bad = [
    { witnesses: [{ url: "ftp://w", verifierKey }] }, { witnesses: [{ url: "https://w", verifierKey: "nope" }] }, { witnesses: [{ url: "https://w", verifierKey }], quorum: 2 },
    { witnesses: [{ url: "https://w", verifierKey }], mode: "later" }, { witnesses: [{ url: "https://w", verifierKey }], extra: 1 }, { witnesses: [{ url: "https://u:p@w", verifierKey }] },
    { witnesses: [{ url: "https://w", verifierKey }], maxUnwitnessedEvents: 0 },
  ];
  for (const value of bad) assert.throws(() => normalizeWitnessPolicy(value), (e) => e.code === "INVALID_INPUT", JSON.stringify(value));
  const two = generateNoteKey("w2").verifierKey, three = generateNoteKey("w3").verifierKey;
  const trio = normalizeWitnessPolicy({ witnesses: [{ url: "https://a", verifierKey }, { url: "https://b", verifierKey: two }, { url: "https://c", verifierKey: three }, { url: "https://d", verifierKey }], quorum: 2 });
  assert.equal(trio.witnesses.length, 3, "deduplicated by verifier key");
  assert.equal(witnessesToConsult(trio), 2);
  assert.equal(witnessesToConsult({ ...trio, quorum: 1 }), 3);
  assert.equal(witnessesToConsult({ ...trio, quorum: 3 }), 1);
});

test("the side file: mode 0600, strict parsing, seals verify only with an owner key in force", async () => {
  const h = await history(1);
  const path = stateModule.witnessStatePathFor(h.historyFile);
  const state = h.state();
  const historyId = state.eventHistoryHashes[0];
  const { verifierKey } = generateNoteKey("w1");
  stateModule.updateWitnessState(path, historyId, (doc) => ({ ...doc, policy: stateModule.storedPolicyOf(normalizeWitnessPolicy({ witnesses: [{ url: "https://w", verifierKey }] })) }));
  if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  const doc = stateModule.readWitnessState(path);
  assert.equal(doc.historyId, historyId);
  assert.equal(doc.policy.witnesses[0].url, "https://w");
  const id = { historyId, origin: "origin/x", verifierKey, url: "https://w" };
  // A signer with signHashSync seals at once; an asynchronous one (ssh-agent, command, KMS, the async-signer test mode) through sealCachedLatestAsync. Same seal.
  const seal = h.signer.signHashSync !== undefined ? stateModule.sealCachedLatest(h.signer, id, state.head, 123) : await stateModule.sealCachedLatestAsync(h.signer, id, state.head, 123);
  assert.deepEqual(await stateModule.sealCachedLatestAsync(h.signer, id, state.head, 123), seal, "Ed25519 is deterministic: both ways give the same seal");
  const cached = { head: state.head, fetchedAt: 123, seal };
  assert.equal(stateModule.cachedLatestIsSealed(state, id, cached), true);
  assert.equal(stateModule.cachedLatestIsSealed(state, id, { ...cached, fetchedAt: 124 }), false, "the time is sealed");
  assert.equal(stateModule.cachedLatestIsSealed(state, { ...id, origin: "origin/y" }, cached), false, "the origin is sealed");
  assert.equal(stateModule.cachedLatestIsSealed(state, { ...id, verifierKey: generateNoteKey("w2").verifierKey }, cached), false, "the witness's verifier key is sealed");
  assert.equal(stateModule.cachedLatestIsSealed(state, { ...id, url: "https://other" }, cached), false, "the pinned URL is sealed");
  assert.equal(stateModule.cachedLatestIsSealed(state, id, { head: null, fetchedAt: 123, seal }), false, "the head is sealed");
  writeFileSync(path, "{ not json");
  assert.throws(() => stateModule.readWitnessState(path), (e) => e.code === "WITNESS_UNREADABLE");
  writeFileSync(path, JSON.stringify({ version: "irontrellis-witness-state/1", witnesses: { o: { url: 1 } }, pending: [] }));
  assert.throws(() => stateModule.readWitnessState(path), (e) => e.code === "WITNESS_UNREADABLE");
  // A side file for another history keeps its policy but loses its witness state on the next update.
  writeFileSync(path, JSON.stringify({ version: "irontrellis-witness-state/1", historyId: `0x${"cd".repeat(32)}`, witnesses: { o: { url: "u", verifierKey, registered: true } }, pending: [] }));
  const replaced = stateModule.updateWitnessState(path, historyId, (d) => d);
  assert.deepEqual(replaced.witnesses, {});
  assert.equal(replaced.historyId, historyId);
});
