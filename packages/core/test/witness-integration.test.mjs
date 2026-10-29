// Remote witnesses wired into the store and the owner API (WITNESS-DESIGN §1, §4.2, §8.1), against the in-test fake
// witness: sync and async submission, flush, STALE_PREVIOUS (prefix: re-sign; not a prefix: sticky rollback, no statement
// for the rolled-back branch), the rc.1 residual attack (an older copy of history + pin + anchors + side file restored),
// truncation, forks and equivocation, rotation ordering and crash recovery, an unreachable witness and
// maxUnwitnessedEvents, split view, quorum 2 of 3, invalid answers, and a deleted or rolled-back side file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startFakeWitness } from "./helpers/fake-witness.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { createLocalOwner: createLocalOwnerDefault, openLocalOwner: openLocalOwnerDefault, createLocalDomain: createLocalDomainDefault, verifyHistoryWithWitnesses, verifyHistory } = await import("../src/owner.ts");
// These tests cover the format-1 (and legacy) owner API; the API writes format 2 by default (SPEC §19), so format 1 is named for every handle and domain made here.
const createLocalOwner = (options) => createLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const openLocalOwner = (options) => openLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const createLocalDomain = (options = {}) => createLocalDomainDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { anchorHead, localAnchorLog, anchorsPathFor } = await import("../src/anchor.ts");
const { loadOwnerKeyFile, ownerKeyPathFor, retiredOwnerKeyPathFor } = await import("../src/signer.ts");
const { readWitnessState, witnessStatePathFor } = await import("../src/witness-state.ts");
const { signStatement, boundWitnessesOf, resetWitnessViews } = await import("../src/witness-session.ts");
const { remoteWitness } = await import("../src/witness-client.ts");
const { generateNoteKey } = await import("../src/transparency/index.ts");

let clock = 1_000_000;
const now = () => (clock += 1);
const policyOf = (witnesses, extra = {}) => ({ witnesses: witnesses.map((w) => ({ url: w.url, verifierKey: w.verifierKey })), ...extra });
const SUFFIXES = ["", ".head", ".anchors", ".witness.json"];

async function setup(witnesses, extra = {}, events = 3) {
  const directory = mkdtempSync(join(tmpdir(), "wint-"));
  const historyFile = join(directory, "history.jsonl");
  const domain = createLocalDomain();
  const owner = await createLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now, witness: policyOf(witnesses, extra) });
  for (let n = 0; n < events; n += 1) await owner.createAgent({ id: `agent:${n}` });
  const open = (options = {}) => openLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now, ...options });
  const head = () => openHistoryStore(historyFile, { inspect: true, witness: false }).state().head;
  const historyId = () => openHistoryStore(historyFile, { inspect: true, witness: false }).state().eventHistoryHashes[0];
  return { directory, historyFile, domain, owner, open, head, historyId };
}
const snapshot = (historyFile) => Object.fromEntries(SUFFIXES.map((suffix) => [suffix, existsSync(historyFile + suffix) ? readFileSync(historyFile + suffix) : undefined]));
/** Puts files back as an attacker would; the next handle is a fresh process (it has not talked to the witnesses yet). */
const restore = (historyFile, snap) => {
  resetWitnessViews();
  for (const [suffix, bytes] of Object.entries(snap)) {
    if (bytes === undefined) rmSync(historyFile + suffix, { force: true });
    else writeFileSync(historyFile + suffix, bytes, { mode: 0o600 });
  }
};
const rollbackWith = (reason) => (error) => error.code === "ROLLBACK_DETECTED" && error.detail?.reason === reason;
const headsOf = (w, historyId) => w.heads(historyId).map((s) => s.statement.head.position);
/** A fetch that runs `hook(url, init)` before the request goes out. */
const intercepting = (hook) => async (url, init) => { await hook(url, init); return globalThis.fetch(url, init); };

test("sync mode: every owner write is witnessed before it returns; creation registers and binds the witness", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 0);
  const id = h.historyId();
  const state = openHistoryStore(h.historyFile, { witness: false }).state();
  assert.equal(state.events[2].type, "WITNESSES_BOUND", "the witness is bound in the history");
  assert.deepEqual(boundWitnessesOf(state).map((b) => b.verifierKey), [w.verifierKey]);
  assert.deepEqual(w.latest(id), h.head());
  for (let n = 0; n < 4; n += 1) {
    const result = await h.owner.createAgent({ id: `agent:${n}` });
    assert.deepEqual(w.latest(id), result.head, "the witness holds the head when the write returns");
  }
  // Creation writes genesis (with the next-key commitment), principal and binding (2); the witness first holds head 2.
  assert.deepEqual(headsOf(w, id), [2, 3, 4, 5, 6]);
  const status = h.owner.witnessStatus();
  assert.equal(status.unwitnessedEvents, 0);
  assert.equal(status.witnesses[0].bound, true);
  assert.equal(status.witnesses[0].source, "network");
  const doc = readWitnessState(witnessStatePathFor(h.historyFile));
  assert.equal(doc.policy.mode, "sync");
  assert.ok(doc.witnesses[w.origin].latest.seal !== undefined, "the owner seals what it learned");
  assert.equal(doc.witnesses[w.origin].checkpoint.size, w.size);
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.equal(report.remoteWitnessStatus, "OK");
  assert.ok(!report.notes.some((n) => n.startsWith("ANCHOR_LOG_NONE")));
  const sync = verifyHistory(h.historyFile);
  assert.equal(sync.ok, true);
  assert.equal(sync.remoteWitnessStatus, "NOT_CONSULTED");
  assert.ok(sync.notes.some((n) => n.startsWith("REMOTE_WITNESS_NOT_CONSULTED")));
});

test("async mode: writes return at once, the worker coalesces to the newest head, flush waits", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  // A witness slower than the writer (each submission takes 40 ms), so the worker has newer heads to coalesce to however long
  // a write takes (an asynchronous signer, as in the async-signer test mode, yields between writes).
  const slow = intercepting(async (url, init) => { if (init.method === "POST" && new URL(url).pathname.endsWith("/heads")) await new Promise((resolve) => setTimeout(resolve, 40)); });
  const h = await setup([w], { fetch: slow }, 0);
  const id = h.historyId();
  await h.owner.flush();
  const before = w.state.statements.length;
  for (let n = 0; n < 8; n += 1) await h.owner.createAgent({ id: `agent:${n}` });
  await h.owner.flush();
  assert.deepEqual(w.latest(id), h.head());
  const submitted = w.state.statements.length - before;
  assert.ok(submitted >= 1 && submitted < 8, `coalesced: ${submitted} statements for 8 writes`);
  assert.equal(h.owner.witnessStatus().unwitnessedEvents, 0);
  assert.equal(h.owner.witnessStatus().pending.length, 0);
});

test("async mode with an asynchronous-only signer: an owner write waits while this handle's worker signs a statement under the writer lock", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const { keyPairFromPrivateKey, signHashWith } = await import("../src/crypto/suites.ts");
  const pair = keyPairFromPrivateKey("ed25519", "owner:1", `0x${"42".repeat(32)}`);
  const sign = signHashWith(pair);
  // A KMS-like signer (no signHashSync). Head statements wait for `release` once armed, so the worker provably holds the
  // store's writer lock (statements are signed under it, docs/WITNESS.md §2) when the next owner write arrives.
  let armed = false, release, entered;
  const gate = new Promise((resolve) => { release = resolve; });
  const inside = new Promise((resolve) => { entered = resolve; });
  const signer = Object.freeze({
    keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential,
    signHash: async (hash, context) => {
      await new Promise((resolve) => setImmediate(resolve));
      if (armed && context?.purpose === "head-statement") { entered(); await gate; }
      return sign(hash);
    },
  });
  const directory = mkdtempSync(join(tmpdir(), "wint-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const historyFile = join(directory, "history.jsonl");
  const owner = await createLocalOwner({ historyFile, domain: createLocalDomain(), owner: "owner", controller: "controller", now, signer, nextKey: false, witness: policyOf([w], { mode: "async" }) });
  await owner.flush();
  armed = true;
  await owner.createAgent({ id: "agent:first" });
  await inside; // the worker is inside its locked section, waiting on the signer
  const second = owner.createAgent({ id: "agent:second" });
  const settled = await Promise.race([second.then(() => "written", (error) => error), new Promise((resolve) => setTimeout(() => resolve("waiting"), 100))]);
  assert.equal(settled, "waiting", "the write waits for the worker's section instead of failing on this handle's own writer lock");
  release();
  await second;
  await owner.flush();
  const head = openHistoryStore(historyFile, { inspect: true, witness: false }).state().head;
  assert.deepEqual(w.latest(openHistoryStore(historyFile, { inspect: true, witness: false }).state().eventHistoryHashes[0]), head);
  assert.equal(owner.witnessStatus().unwitnessedEvents, 0);
});

test("STALE_PREVIOUS with a prefix: the statement is signed again with previous = the witness latest", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const id = h.historyId();
  const signer = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile));
  // Another writer without a witness policy appends y; the witness still holds the old head.
  const plain = h.open({ witness: false });
  await plain.createAgent({ id: "agent:y" });
  const other = remoteWitness({ url: w.url, verifierKey: w.verifierKey });
  let raced = false;
  const b = h.open({
    witness: policyOf([w], {
      mode: "sync",
      fetch: intercepting(async (url, init) => {
        if (raced || init.method !== "POST" || !new URL(url).pathname.endsWith("/heads")) return;
        raced = true;
        // Just before B's statement arrives, y (a prefix of B's file) is witnessed by someone else.
        const state = openHistoryStore(h.historyFile, { witness: false }).state();
        const { buildPrefixState } = await prefixHelper();
        const prefix = buildPrefixState(state, state.head.position - 1);
        await other.submit(await signStatement(signer, prefix, w.latest(id)));
      }),
    }),
  });
  const statementsBefore = w.state.statements.length;
  const result = await b.createAgent({ id: "agent:x" });
  assert.equal(raced, true);
  assert.deepEqual(w.latest(id), result.head);
  const mine = w.state.statements.slice(statementsBefore).filter((s) => s.statement.head.hash === result.head.hash);
  assert.equal(mine.length, 2, "submitted, refused as stale, re-signed and accepted");
  assert.notDeepEqual(mine[0].statement.previous, mine[1].statement.previous);
  assert.equal(mine[1].statement.previous.position, result.head.position - 1);
  await b.createAgent({ id: "agent:z" });
});

/** A replay state of the first `position + 1` events (for a raw statement about a prefix head). */
async function prefixHelper() {
  const { replay } = await import("../src/replay.ts");
  return { buildPrefixState: (state, position) => replay(state.events.slice(0, position + 1)).state };
}

test("STALE_PREVIOUS that is not a prefix: sticky WITNESS_AHEAD, no statement for the rolled-back branch", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const id = h.historyId();
  const old = snapshot(h.historyFile);
  // The true branch goes on (positions 5..7, after the three creation events and two agents) and is witnessed at its newest head only.
  // Its head statements stay queued in the side file (the witness does not get them yet), however long its writes take
  // (an asynchronous signer, as in the async-signer test mode, gives the background worker time to run between writes).
  const truth = h.open({
    witness: policyOf([w], { mode: "async", fetch: intercepting(async (url, init) => { if (init.method === "POST" && new URL(url).pathname.endsWith("/heads")) throw new TypeError("fetch failed"); }) }),
  });
  for (let n = 0; n < 3; n += 1) await truth.createAgent({ id: `agent:true:${n}` });
  // That owner process ends before the attacker acts (a live handle would see its file change under it: FILE_CHANGED_UNDER_WRITER).
  truth.close();
  const trueBranch = snapshot(h.historyFile);
  // The file is rolled back; B (fresh process) checks the witness before the true branch is submitted…
  restore(h.historyFile, old);
  let raced = false;
  const b = h.open({
    witness: policyOf([w], {
      mode: "sync",
      fetch: intercepting(async (url, init) => {
        if (raced || init.method !== "POST" || !new URL(url).pathname.endsWith("/heads")) return;
        raced = true;
        // …and the true branch reaches the witness while B's statement is in flight.
        const current = snapshot(h.historyFile);
        restore(h.historyFile, trueBranch);
        const later = h.open({ witness: policyOf([w], { mode: "async" }) });
        await later.flush();
        later.close();
        restore(h.historyFile, current);
      }),
    }),
  });
  const before = w.state.statements.length;
  await assert.rejects(b.createAgent({ id: "agent:rolled-back" }), rollbackWith("WITNESS_AHEAD"));
  assert.equal(raced, true);
  const fromB = w.state.statements.slice(before).filter((s) => s.statement.head.position === 5 && s.statement.head.hash !== w.latest(id).hash);
  assert.equal(fromB.length, 1, "the one statement B signed while the witness still agreed with its file");
  const count = w.state.statements.length;
  // Sticky: reads and writes of this handle refuse; nothing more reaches the witness.
  assert.throws(() => b.capacity(), rollbackWith("WITNESS_AHEAD"));
  await assert.rejects(b.createAgent({ id: "agent:again" }), rollbackWith("WITNESS_AHEAD"));
  await assert.rejects(b.flush(), rollbackWith("WITNESS_AHEAD"));
  assert.equal(w.state.statements.length, count);
  assert.equal(headsOf(w, id).at(-1), 7);
});

test("the rc.1 residual attack: an older copy of history + pin + anchors + side file is refused by open, verify and the next write", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const id = h.historyId();
  // The old copy the attacker keeps: owner-attested pin, a local anchor, the side file of that time.
  const store = openHistoryStore(h.historyFile, { signer: loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)) });
  await anchorHead(store, loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)), localAnchorLog(anchorsPathFor(h.historyFile)), { id: "event:anchor:1", anchoredAt: now() });
  store.close();
  await h.owner.createAgent({ id: "agent:after-anchor" });
  const old = snapshot(h.historyFile);
  const oldHead = h.head();
  for (let n = 0; n < 5; n += 1) await h.owner.createAgent({ id: `agent:later:${n}` });
  const latest = w.latest(id);
  assert.ok(latest.position > oldHead.position);
  restore(h.historyFile, old);
  // Locally the copy is flawless: pin attested, anchors a prefix, sync verify passes (it did not ask the witness).
  assert.equal(verifyHistory(h.historyFile).ok, true);
  const statements = w.state.statements.length;
  // verify asks the witness.
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, false);
  assert.equal(report.rollback, true);
  assert.equal(report.remoteWitnessStatus, "ROLLBACK");
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")), report.failures.join("\n"));
  // Open with requireOnOpen: reads wait for the check, the check fails, and every read after it fails.
  const reader = h.open({ witness: policyOf([w], { requireOnOpen: true, cacheMs: 0 }) });
  assert.throws(() => reader.capacity(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
  await assert.rejects(reader.checkWitnesses(), rollbackWith("WITNESS_AHEAD"));
  assert.throws(() => reader.capacity(), rollbackWith("WITNESS_AHEAD"));
  // The next owner write (policy from the restored side file and the history's binding) refuses before appending.
  const writer = h.open();
  await assert.rejects(writer.createAgent({ id: "agent:on-the-old-branch" }), rollbackWith("WITNESS_AHEAD"));
  assert.deepEqual(h.head(), oldHead, "nothing was appended");
  assert.equal(w.state.statements.length, statements, "no statement was signed for the rolled-back branch");
  assert.deepEqual(w.latest(id), latest);
  // repin cannot re-attest the old head while the witness holds a later one.
  const repinner = openHistoryStore(h.historyFile, { signer: loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)) });
  await assert.rejects(repinner.checkWitnesses(), rollbackWith("WITNESS_AHEAD"));
  assert.throws(() => repinner.repin(), rollbackWith("WITNESS_AHEAD"));
});

test("a live owner handle whose file is cut back underneath it refuses its next write without asking", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const old = snapshot(h.historyFile);
  for (let n = 0; n < 3; n += 1) await h.owner.createAgent({ id: `agent:later:${n}` });
  restore(h.historyFile, old);
  w.down = true; // no network needed: the handle knows what the witness holds
  const statements = w.state.statements.length;
  await assert.rejects(h.owner.createAgent({ id: "agent:x" }), rollbackWith("WITNESS_AHEAD"));
  assert.throws(() => h.owner.capacity(), rollbackWith("WITNESS_AHEAD"));
  assert.equal(w.state.statements.length, statements);
});

test("another handle in the same process starts from what the process verified: a cut-back file is refused at open", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const old = snapshot(h.historyFile);
  await h.owner.createAgent({ id: "agent:later" });
  for (const suffix of ["", ".head"]) writeFileSync(h.historyFile + suffix, old[suffix]); // no resetWitnessViews(): same process
  w.down = true;
  assert.throws(() => h.open({ witness: policyOf([w]) }), rollbackWith("WITNESS_AHEAD"));
});

test("truncation with the side file kept: refused on the side file's word even while the witness is down, and by the witness", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const cut = snapshot(h.historyFile);
  for (let n = 0; n < 3; n += 1) await h.owner.createAgent({ id: `agent:later:${n}` });
  restore(h.historyFile, { "": cut[""], ".head": cut[".head"] });
  w.down = true;
  // Like a local anchor log holding a later head: the remembered witness head refuses readers and writers alike.
  assert.throws(() => h.open(), rollbackWith("WITNESS_AHEAD"));
  const store = openHistoryStore(h.historyFile);
  assert.throws(() => store.state(), rollbackWith("WITNESS_AHEAD"));
  assert.equal(verifyHistory(h.historyFile).ok, false, "even the synchronous verify reports it");
  assert.ok(verifyHistory(h.historyFile).failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")));
  w.down = false;
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")));
});

test("a replaced history (same length, another branch) is WITNESS_FORK", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const base = snapshot(h.historyFile);
  await h.owner.createAgent({ id: "agent:witnessed" });
  const witnessed = h.head();
  restore(h.historyFile, base);
  // A writer without witnesses (as an attacker holding a copy would) writes another event at the same position.
  await h.open({ witness: false }).createAgent({ id: "agent:other" });
  assert.equal(h.head().position, witnessed.position);
  rmSync(witnessStatePathFor(h.historyFile), { force: true });
  await assert.rejects(h.open().createAgent({ id: "agent:x" }), rollbackWith("WITNESS_FORK"));
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && /not a prefix/.test(f)));
});

test("equivocation (§9.1): two diverged copies written with the same owner key; the witness records the evidence, the losing copy's writer refuses, the history stays open", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const id = h.historyId();
  const copyDir = mkdtempSync(join(tmpdir(), "wint-copy-"));
  const copyFile = join(copyDir, "history.jsonl");
  for (const suffix of [...SUFFIXES, ".owner-key.json"]) if (existsSync(h.historyFile + suffix)) writeFileSync(copyFile + suffix, readFileSync(h.historyFile + suffix), { mode: 0o600 });
  const a = h.owner;
  let raced = false;
  const b = openLocalOwner({
    historyFile: copyFile, domain: h.domain, owner: "owner", controller: "controller", now,
    witness: policyOf([w], {
      mode: "sync",
      fetch: intercepting(async (url, init) => {
        if (raced || init.method !== "POST" || !new URL(url).pathname.endsWith("/heads")) return;
        raced = true;
        await a.createAgent({ id: "agent:branch-a" }); // A's head at the same position lands first
      }),
    }),
  });
  await assert.rejects(b.createAgent({ id: "agent:branch-b" }), (e) => rollbackWith("WITNESS_FORK")(e) && Number.isSafeInteger(e.detail.equivocationIndex));
  assert.equal(w.histories.get(id).equivocations, 1);
  assert.equal(w.entries.at(-1).kind, "EQUIVOCATION");
  const statements = w.state.statements.length;
  await assert.rejects(b.createAgent({ id: "agent:b2" }), rollbackWith("WITNESS_FORK"));
  assert.equal(w.state.statements.length, statements, "the handle never signs again");
  // The witnessed branch goes on: a fresh process writes, the witness accepts.
  resetWitnessViews();
  const aFresh = h.open();
  const written = await aFresh.createAgent({ id: "agent:a2" });
  assert.deepEqual(w.latest(id), written.head);
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.equal(report.remoteWitnessStatus, "OK");
  assert.equal(report.rollback, false);
  assert.ok(report.notes.some((n) => n.startsWith("REMOTE_WITNESS_EQUIVOCATION_RECORDED 1:") && n.includes("treat the owner key as compromised")), report.notes.join("\n"));
  assert.equal(report.remoteWitnesses[0].equivocations, 1);
  assert.equal(report.remoteWitnesses[0].lastEquivocation.position, written.head.position - 1);
  assert.ok(!report.failures.some((f) => f.startsWith("REMOTE_WITNESS_EQUIVOCATION")));
  // The losing copy is simply not on the witness chain.
  const copyReport = await verifyHistoryWithWitnesses(copyFile);
  assert.equal(copyReport.remoteWitnessStatus, "ROLLBACK");
  assert.ok(copyReport.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")));
});

test("the C5 race (§9.1): the file is rolled back between the witness check and the submission; the history is not bricked and the restored copy writes on", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const id = h.historyId();
  const old = snapshot(h.historyFile);
  // The true branch appends one event; its head is not submitted yet (async).
  const truth = h.open({ witness: policyOf([w], { mode: "async" }) });
  await truth.createAgent({ id: "agent:true" });
  truth.close(); // that process ends; another one submits the head later
  const good = snapshot(h.historyFile);
  // The attacker restores the older copy; a fresh owner process writes on it: its check sees the witness latest as a prefix…
  restore(h.historyFile, old);
  let raced = false;
  const b = h.open({
    witness: policyOf([w], {
      mode: "sync",
      fetch: intercepting(async (url, init) => {
        if (raced || init.method !== "POST" || !new URL(url).pathname.endsWith("/heads")) return;
        raced = true;
        // …and before its statement arrives, the true head at the same position reaches the witness.
        const current = snapshot(h.historyFile);
        restore(h.historyFile, good);
        const later = h.open({ witness: policyOf([w], { mode: "async" }) });
        await later.flush();
        later.close();
        restore(h.historyFile, current);
      }),
    }),
  });
  await assert.rejects(b.createAgent({ id: "agent:rolled-back" }), rollbackWith("WITNESS_FORK"));
  assert.equal(raced, true);
  assert.equal(w.histories.get(id).equivocations, 1, "the conflicting statement is recorded as evidence");
  assert.equal(w.entries.at(-1).kind, "EQUIVOCATION");
  const witnessed = w.latest(id);
  // Before §9.1 the witness froze the history here. Now: restore the good copy and write on.
  restore(h.historyFile, good);
  const owner = h.open();
  const next = await owner.createAgent({ id: "agent:after-restore" });
  assert.equal(next.head.position, witnessed.position + 1);
  assert.deepEqual(w.latest(id), next.head, "the witness accepts the statement extending its latest head");
  await owner.createAgent({ id: "agent:and-on" });
  assert.deepEqual(w.latest(id), h.head());
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.ok(report.notes.some((n) => n.startsWith("REMOTE_WITNESS_EQUIVOCATION_RECORDED 1:")));
  const status = owner.witnessStatus();
  assert.equal(status.alarm, undefined);
  assert.equal(status.witnesses[0].equivocations, 1);
});

test("a stolen CURRENT owner key signs a divergent head with a stale previous: evidence recorded, the witness chain and the owner are unaffected", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 3);
  const id = h.historyId();
  const witnessed = h.head();
  // The thief holds the owner key and an older copy; it builds another event at a position the witness holds.
  const { replay } = await import("../src/replay.ts");
  const { signControlEvent } = await import("../src/signer.ts");
  const events = openHistoryStore(h.historyFile, { witness: false }).state().events;
  const cut = replay(events.slice(0, witnessed.position - 1)).state; // two events behind the witnessed head
  const key = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile));
  const forged = await signControlEvent(key, { id: "agent:thief", type: "AGENT_CREATED", timestamp: cut.head.canonicalTime + 1, data: { agentId: "agent:thief", principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } },
    cut.genesis.domain, cut.head, "sha256");
  const divergent = replay([...events.slice(0, cut.head.position + 1), forged]).state;
  assert.equal(divergent.head.position, witnessed.position - 1);
  assert.notEqual(divergent.head.hash, h.head().hash);
  // Stale previous: the head before the divergent one (the witness holds a later latest and another head at that position).
  const previous = { hash: cut.head.hash, position: cut.head.position };
  const client = remoteWitness({ url: w.url, verifierKey: w.verifierKey });
  const answer = await client.submit(await signStatement(key, divergent, previous));
  assert.equal(answer.kind, "EQUIVOCATION");
  assert.deepEqual(answer.latest.head, witnessed, "the witness latest is unchanged");
  assert.deepEqual(w.latest(id), witnessed);
  assert.equal(w.histories.get(id).equivocations, 1);
  // The owner is unaffected: its next write is accepted, verify passes with the note, and a rotation retires the stolen key.
  resetWitnessViews();
  const owner = h.open();
  await owner.createAgent({ id: "agent:owner-goes-on" });
  assert.deepEqual(w.latest(id), h.head());
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.ok(report.notes.some((n) => n.startsWith("REMOTE_WITNESS_EQUIVOCATION_RECORDED 1:")));
  await owner.rotateOwnerKey({ reason: "the key signed a conflicting head" });
  await owner.createAgent({ id: "agent:after-rotation" });
  await owner.flush();
  assert.deepEqual(w.latest(id), h.head());
  const late = await client.submit(await signStatement(key, divergent, previous));
  assert.equal(late.kind, "EQUIVOCATION", "the same stolen statement is still only evidence");
  assert.equal(late.index, answer.index, "and is recorded once");
});

test("rotation: statement for head r by the old key, then the rotation, then new-key statements (sync)", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const id = h.historyId();
  const oldKey = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)).keyId;
  const rotated = await h.owner.rotateOwnerKey({ reason: "scheduled" });
  await h.owner.createAgent({ id: "agent:after" });
  const r = rotated.head.position;
  const log = w.entries.filter((e) => e.historyId === id && e.kind !== "REGISTERED").map((e) => e.kind === "HEAD"
    ? `HEAD ${e.signedStatement.statement.head.position} ${e.signedStatement.keyId}` : `${e.kind} ${e.rotationHead?.position ?? ""}`.trim());
  const at = log.indexOf(`HEAD ${r} ${oldKey}`);
  assert.ok(at >= 0, log.join("\n"));
  assert.deepEqual(log.slice(at), [`HEAD ${r} ${oldKey}`, `ROTATED ${r}`, `HEAD ${r + 1} ${rotated.keyId}`]);
  assert.deepEqual(w.histories.get(id).epochs.map((e) => e.fromPosition), [0, r + 1]);
  assert.equal(h.owner.witnessStatus().pending.length, 0);
  assert.equal((await verifyHistoryWithWitnesses(h.historyFile)).ok, true);
});

test("rotation while the witness is down: the old-key statement queued in the side file is submitted by the next process", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const id = h.historyId();
  const oldKey = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)).keyId;
  w.down = true;
  // WITNESS-DESIGN §11.2: by default a history with bound witnesses rotates in two phases, so a down witness aborts it cleanly.
  const before = h.head();
  await assert.rejects(h.owner.rotateOwnerKey({ reason: "while down" }), (e) => e.code === "WITNESS_UNAVAILABLE" && /rotation needs every bound witness; retry, or rotate with --emergency/.test(e.message));
  assert.deepEqual(h.head(), before, "nothing appended");
  for (const suffix of [".rotation.pending.json", ".owner-key.pending.json", ".owner-next-key.pending.json"]) assert.equal(existsSync(h.historyFile + suffix), false, suffix);
  // The emergency rotation is the previous behaviour: locally first, delivered afterwards.
  const rotated = await h.owner.rotateOwnerKey({ reason: "while down", emergency: true });
  assert.equal(rotated.emergency, true);
  assert.ok(existsSync(rotated.bundle), "a key-event bundle for an offline hand-off");
  const pending = readWitnessState(witnessStatePathFor(h.historyFile)).pending;
  assert.deepEqual(pending.map((item) => item.kind), ["statement", "rotation"]);
  assert.equal(pending[0].statements[w.origin].keyId, oldKey, "signed by the old key before the swap");
  h.owner.close(); // the process ends here
  // Only the queued statement can supply the old key's signature now.
  const retired = retiredOwnerKeyPathFor(h.historyFile, oldKey);
  renameSync(retired, `${retired}.away`);
  w.down = false;
  const next = h.open();
  await next.createAgent({ id: "agent:after" });
  await next.flush();
  const r = rotated.head.position;
  const kinds = w.entries.filter((e) => e.historyId === id).slice(-3).map((e) => (e.kind === "HEAD" ? `HEAD ${e.signedStatement.statement.head.position} ${e.signedStatement.keyId}` : e.kind));
  assert.deepEqual(kinds, [`HEAD ${r} ${oldKey}`, "ROTATED", `HEAD ${r + 1} ${rotated.keyId}`]);
  assert.equal(next.witnessStatus().pending.length, 0);
});

test("a crash between the rotation append and the queue: recovered from the archived key file", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "async" }, 2);
  const id = h.historyId();
  await h.owner.flush();
  const oldKey = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)).keyId;
  w.down = true;
  const rotated = await h.owner.rotateOwnerKey({ emergency: true });
  h.owner.close();
  // As if the process died before the queue reached the side file.
  const path = witnessStatePathFor(h.historyFile);
  const doc = JSON.parse(readFileSync(path, "utf8"));
  writeFileSync(path, JSON.stringify({ ...doc, pending: [] }), { mode: 0o600 });
  w.down = false;
  const next = h.open();
  await next.flush();
  const r = rotated.head.position;
  const tail = w.entries.filter((e) => e.historyId === id).slice(-2).map((e) => (e.kind === "HEAD" ? `HEAD ${e.signedStatement.statement.head.position} ${e.signedStatement.keyId}` : e.kind));
  assert.deepEqual(tail, [`HEAD ${r} ${oldKey}`, "ROTATED"]);
  await next.createAgent({ id: "agent:new-key" });
  await next.flush();
  assert.equal(w.heads(id).at(-1).keyId, rotated.keyId);
});

test("witness down: statements queue, maxUnwitnessedEvents refuses writes (reads continue), recovery when it is back", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  // After the flush the witness holds the head; four queued writes then reach the limit of 4.
  const h = await setup([w], { mode: "async", maxUnwitnessedEvents: 4 }, 1);
  await h.owner.flush();
  w.down = true;
  for (let n = 0; n < 4; n += 1) await h.owner.createAgent({ id: `agent:queued:${n}` });
  await assert.rejects(h.owner.createAgent({ id: "agent:refused" }), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "MAX_UNWITNESSED");
  assert.equal(h.owner.capacity().eventCount, h.head().position + 1, "reads continue");
  await assert.rejects(h.owner.flush(), (e) => e.code === "WITNESS_UNAVAILABLE");
  // Another process sees the same backlog (the side file's sealed answer).
  await assert.rejects(h.open().createAgent({ id: "agent:elsewhere" }), (e) => e.code === "WITNESS_UNAVAILABLE");
  w.down = false;
  await h.owner.flush();
  assert.equal(h.owner.witnessStatus().unwitnessedEvents, 0);
  await h.owner.createAgent({ id: "agent:resumed" });
  await h.owner.flush();
  assert.deepEqual(w.latest(h.historyId()), h.head());
});

test("A-24.1 / A-176.2: at maxUnwitnessedEvents a power-reducing event and a STATE_CHECKPOINT are still written; other writes stay refused", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  // Format 2 (a STATE_CHECKPOINT is a format-2 event): this test makes its own handle with the default format.
  const directory = mkdtempSync(join(tmpdir(), "wint-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const historyFile = join(directory, "history.jsonl");
  const owner = await createLocalOwnerDefault({ historyFile, domain: createLocalDomainDefault(), owner: "owner", controller: "controller", now, witness: policyOf([w], { mode: "async", maxUnwitnessedEvents: 4 }) });
  const state = () => openHistoryStoreStrict(historyFile, { inspect: true, witness: false }).state();
  const h = { owner, head: () => state().head, historyId: () => state().eventHistoryHashes[0] };
  await h.owner.flush();
  w.down = true;
  for (let n = 0; n < 4; n += 1) await h.owner.createAgent({ id: `agent:queued:${n}` });
  const refused = (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "MAX_UNWITNESSED";
  await assert.rejects(h.owner.createAgent({ id: "agent:refused" }), refused);
  const before = state().events.length;
  await h.owner.advanceEpoch({ agent: "agent:queued:0", from: 1, to: 2 }); // CONTROL_EPOCH_ADVANCED is power-reducing
  await h.owner.checkpoint();
  // Step 5d P2-11: the two writes are the history's last two events (the earlier check compared a head with itself). The
  // ruling's lapsed-signed checkpoint (A-176.2 under ATTESTED) is not built here; recorded in DEVIATIONS r2.2.
  const written = state().events;
  assert.equal(written.length, before + 2);
  assert.deepEqual(written.slice(-2).map((e) => e.type), ["CONTROL_EPOCH_ADVANCED", "STATE_CHECKPOINT"]);
  assert.equal(h.owner.witnessStatus().unwitnessedEvents, 6, "both are queued for the witness like any write");
  await assert.rejects(h.owner.createAgent({ id: "agent:still-refused" }), refused);
  w.down = false;
  await h.owner.flush();
  assert.equal(h.owner.witnessStatus().unwitnessedEvents, 0);
  assert.deepEqual(w.latest(h.historyId()), h.head());
});


test("A-176.2 (DEVIATIONS r2.2 83): at maxUnwitnessedEvents a STATE_CHECKPOINT signed by a key LAPSED under ATTESTED is still written", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
  const { signerFromKeyPair } = await import("../src/signer.ts");
  const { humanAttestationHash, signerClass } = await import("../src/index.ts");
  const pair = (keyId, n) => keyPairFromPrivateKey("ed25519", keyId, `0x${n.toString(16).padStart(64, "0")}`);
  const pub = (p) => ({ keyId: p.keyId, scheme: "ed25519", credential: p.credential });
  const O1 = pair("owner:1", 0x8001), O2 = pair("owner:2", 0x8002), AT1 = pair("attester:1", 0x8301), AT2 = pair("attester:2", 0x8302);
  const statement = (domain, subject, attester, notBefore, expiresAt) => {
    const body = { version: "irontrellis-human-attestation/1", audience: domain, subject: pub(subject), profile: "phl:ceremony/1", attesterKeyId: attester.keyId, evidenceDigest: `0x${"cd".repeat(32)}`, notBefore, expiresAt };
    return { ...body, signature: signerFromKeyPair(attester).signHashSync(humanAttestationHash({ ...body, signature: "" })) };
  };
  const directory = mkdtempSync(join(tmpdir(), "wint-lapsed-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const historyFile = join(directory, "history.jsonl");
  const domain = createLocalDomainDefault();
  let tick = 1000;
  // owner:1 (the handle's key) is HUMAN until 1500, then LAPSED; owner:2 is HUMAN until 5000, the attestation horizon.
  const ownerPolicy = { threshold: 1, byType: { STATE_CHECKPOINT: 1 }, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations: [statement(domain, O1, AT1, 0, 1500), statement(domain, O2, AT2, 0, 5000)] };
  const owner = await createLocalOwnerDefault({ historyFile, domain, owner: "owner", controller: "controller", now: () => tick, signer: signerFromKeyPair(O1), coOwnerKeys: [pub(O2)], ownerPolicy,
    witness: policyOf([w], { mode: "async", maxUnwitnessedEvents: 2 }) });
  const state = () => openHistoryStoreStrict(historyFile, { inspect: true, witness: false }).state();
  await owner.flush();
  w.down = true;
  for (let n = 0; n < 2; n += 1) await owner.createAgent({ id: `agent:queued:${n}` });
  const refused = (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "MAX_UNWITNESSED";
  await assert.rejects(owner.createAgent({ id: "agent:refused" }), refused, "a non-exempt write at the limit, while owner:1 is still HUMAN");
  tick = 2000;
  const epoch = state().ownerKeyEpochs.at(-1);
  assert.equal(signerClass(epoch.policy, epoch.keys, pub(O1), tick), "LAPSED");
  const before = state().events.length;
  await owner.checkpoint();
  const written = state().events;
  assert.equal(written.length, before + 1);
  assert.equal(written.at(-1).type, "STATE_CHECKPOINT");
  assert.equal(written.at(-1).timestamp, 2000);
  assert.equal(written.at(-1).data.controlAuthorization.keyId, "owner:1", "signed by the LAPSED key");
  assert.equal(owner.witnessStatus().unwitnessedEvents, 3, "queued for the witness like any write");
});
test("split view: a witness that cannot prove its log consistent is fatal, recorded, and fails verify", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  w.splitView();
  await assert.rejects(h.owner.createAgent({ id: "agent:x" }), (e) => e.code === "WITNESS_SPLIT_VIEW");
  assert.throws(() => h.owner.capacity(), (e) => e.code === "WITNESS_SPLIT_VIEW");
  assert.match(Object.values(readWitnessState(witnessStatePathFor(h.historyFile)).witnesses)[0].splitView.message, /split view/);
  assert.throws(() => h.open(), (e) => e.code === "WITNESS_SPLIT_VIEW", "recorded: later processes refuse too");
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_SPLIT_VIEW")), report.failures.join("\n"));
});

test("quorum 2 of 3: one witness down is tolerated; two are not; rollback evidence from any single witness is fatal", async (t) => {
  const ws = await Promise.all([1, 2, 3].map((seed) => startFakeWitness({ name: `w${seed}`, seed })));
  t.after(() => Promise.all(ws.map((w) => w.close())));
  const [w1, w2, w3] = ws;
  const h = await setup(ws, { mode: "sync", quorum: 2 }, 1);
  const id = h.historyId();
  w3.down = true;
  await h.owner.createAgent({ id: "agent:two-of-three" });
  await h.owner.flush();
  assert.deepEqual(w1.latest(id), h.head());
  assert.deepEqual(w2.latest(id), h.head());
  let report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.ok(report.notes.some((n) => n.startsWith("REMOTE_WITNESS_UNREACHABLE")));
  w2.down = true;
  await h.owner.createAgent({ id: "agent:one-of-three" });
  await assert.rejects(h.owner.flush(), (e) => e.code === "WITNESS_UNAVAILABLE");
  report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_UNREACHABLE")));
  const allowed = await verifyHistoryWithWitnesses(h.historyFile, { allowUnreachableWitness: true });
  assert.equal(allowed.ok, true, allowed.failures.join("\n"));
  // Only w3 holds the newest head; roll the file back and bring w3 back up: its word alone fails the copy.
  w2.down = false;
  await h.owner.flush();
  const old = snapshot(h.historyFile);
  w3.down = false;
  // Statements to w1 and w2 are lost on the way; only w3 accepts the newest head.
  const lossy = h.open({ witness: policyOf(ws, { mode: "sync", quorum: 2, fetch: async (url, init) => {
    if (init.method === "POST" && !url.startsWith(w3.url)) throw new Error("dropped");
    return globalThis.fetch(url, init);
  } }) });
  const newest = await lossy.createAgent({ id: "agent:only-w3" });
  assert.deepEqual(w3.latest(id), newest.head);
  assert.notDeepEqual(w1.latest(id), newest.head);
  restore(h.historyFile, old);
  report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && f.includes(w3.url)), report.failures.join("\n"));
});

test("a tampered receipt or the wrong verifier key never counts as witnessed", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 1);
  w.tamper = "proof";
  await h.owner.createAgent({ id: "agent:x" });
  assert.equal(h.owner.witnessStatus().unwitnessedEvents, 1);
  assert.equal(h.owner.witnessStatus().witnesses[0].lastError.code, "WITNESS_INVALID_RESPONSE");
  await assert.rejects(h.owner.flush(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.cause === "WITNESS_INVALID_RESPONSE");
  let report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_INVALID")));
  w.tamper = undefined;
  const impostor = generateNoteKey("fake-witness").verifierKey;
  report = await verifyHistoryWithWitnesses(h.historyFile, { witness: { witnesses: [{ url: w.url, verifierKey: impostor }] } });
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_INVALID")), report.failures.join("\n"));
});

test("a deleted side file: the history's binding keeps the witness, and the restored copy is still refused", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  const old = snapshot(h.historyFile);
  for (let n = 0; n < 3; n += 1) await h.owner.createAgent({ id: `agent:later:${n}` });
  restore(h.historyFile, { ...old, ".witness.json": undefined });
  assert.equal(existsSync(witnessStatePathFor(h.historyFile)), false);
  const writer = h.open();
  assert.equal(writer.witnessStatus().witnesses[0].bound, true);
  await assert.rejects(writer.createAgent({ id: "agent:x" }), rollbackWith("WITNESS_AHEAD"));
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")));
});

test("a rolled-back side file cannot vouch for a rolled-back history: writers and verify ask, and an unsealed cache is not trusted", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync", requireOnOpen: true, cacheMs: 3_600_000 }, 2);
  const old = snapshot(h.historyFile);
  for (let n = 0; n < 3; n += 1) await h.owner.createAgent({ id: `agent:later:${n}` });
  restore(h.historyFile, old);
  // Writers never take the file's word, however fresh.
  await assert.rejects(h.open().createAgent({ id: "agent:x" }), rollbackWith("WITNESS_AHEAD"));
  assert.ok((await verifyHistoryWithWitnesses(h.historyFile)).failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")));
  // A reader with requireOnOpen may use a sealed answer younger than cacheMs (bounded staleness, documented); an unsealed
  // or forged one is never enough, whatever its time.
  restore(h.historyFile, old);
  const path = witnessStatePathFor(h.historyFile);
  const doc = JSON.parse(readFileSync(path, "utf8"));
  const [origin] = Object.keys(doc.witnesses);
  delete doc.witnesses[origin].latest.seal;
  doc.witnesses[origin].latest.fetchedAt = Date.now();
  writeFileSync(path, JSON.stringify(doc), { mode: 0o600 });
  const reader = h.open();
  assert.throws(() => reader.capacity(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
  await assert.rejects(reader.checkWitnesses(), rollbackWith("WITNESS_AHEAD"));
});

test("requireOnOpen: a fresh owner-sealed answer skips the network within cacheMs; later readers ask again", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync", requireOnOpen: true, cacheMs: 60_000 }, 2);
  const requests = w.state.requests.length;
  const reader = h.open();
  assert.equal(reader.capacity().eventCount, h.head().position + 1);
  assert.equal(w.state.requests.length, requests, "no request: the sealed answer is fresh");
  resetWitnessViews(); // another process: it has not heard from the witness, and cacheMs 0 refuses the sealed answer
  const strict = h.open({ witness: policyOf([w], { requireOnOpen: true, cacheMs: 0 }) });
  assert.throws(() => strict.capacity(), (e) => e.detail?.reason === "NOT_CHECKED");
  const view = await strict.checkWitnesses();
  assert.equal(view.consulted, 1);
  assert.equal(strict.capacity().eventCount, h.head().position + 1);
  // A reader without the owner key cannot seal answers, but it can rely on the owner's seal.
  const keyless = openHistoryStore(h.historyFile, { witness: policyOf([w], { requireOnOpen: true, cacheMs: 60_000 }) });
  assert.equal(keyless.state().head.position, h.head().position);
});

test("addWitness and removeWitness bind and unbind in the history; a witness showing a rollback cannot be unbound", async (t) => {
  const w1 = await startFakeWitness({ name: "one", seed: 1 });
  const w2 = await startFakeWitness({ name: "two", seed: 2 });
  t.after(() => Promise.all([w1.close(), w2.close()]));
  const directory = mkdtempSync(join(tmpdir(), "wint-add-"));
  const historyFile = join(directory, "history.jsonl");
  const domain = createLocalDomain();
  const owner = await createLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now });
  await owner.createAgent({ id: "agent:1" });
  assert.equal(owner.witnessStatus(), undefined);
  const added = await owner.addWitness({ url: w1.url, verifierKey: w1.verifierKey }, { mode: "sync" });
  assert.equal(added.submitted, true, JSON.stringify(added.error));
  assert.ok(added.eventId);
  const id = openHistoryStore(historyFile, { witness: false }).state().eventHistoryHashes[0];
  assert.deepEqual(w1.latest(id), openHistoryStore(historyFile, { witness: false }).state().head);
  await owner.addWitness({ url: w2.url, verifierKey: w2.verifierKey }, { quorum: 2 });
  assert.equal(owner.witnessStatus().policy.quorum, 2);
  assert.deepEqual(boundWitnessesOf(openHistoryStore(historyFile, { witness: false }).state()).map((b) => b.url), [w1.url, w2.url]);
  const removed = await owner.removeWitness(w2.url);
  assert.ok(removed.eventId);
  assert.deepEqual(owner.witnessStatus().witnesses.map((x) => x.url), [w1.url]);
  assert.equal(owner.witnessStatus().policy.quorum, 1);
  await assert.rejects(owner.addWitness({ url: "http://127.0.0.1:9", verifierKey: w1.verifierKey }), (e) => e.code === "WITNESS_UNAVAILABLE");
  // Roll back: the unbinding of w1 is itself an owner write, refused.
  const old = snapshot(historyFile);
  await owner.createAgent({ id: "agent:2" });
  await owner.flush();
  restore(historyFile, old);
  const other = openLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now });
  await assert.rejects(other.removeWitness(w1.url), rollbackWith("WITNESS_AHEAD"));
});

test("requireOnOpen: a fresh owner process's first write whose data reads the state (grant, global prohibit, addWitness) asks the witnesses first", async (t) => {
  const w = await startFakeWitness();
  const w2 = await startFakeWitness({ name: "second", seed: 2 });
  t.after(() => Promise.all([w.close(), w2.close()]));
  const h = await setup([w], { mode: "sync", requireOnOpen: true, cacheMs: 0 }, 1);
  const id = h.historyId();
  const expiresAt = clock + 86_400_000;
  for (const write of [
    (owner) => owner.grant({ id: "grant:a", to: "agent:0", actions: ["read"], resources: ["doc:*"], expiresAt }),
    (owner) => owner.prohibit({ id: "prohibit:g", actions: ["delete"], resources: ["doc:*"], global: true }),
    async (owner) => { await owner.addWitness({ url: w2.url, verifierKey: w2.verifierKey }); return { head: h.head() }; },
  ]) {
    resetWitnessViews(); // a new process: nothing verified yet, reads are gated until the witnesses answer
    const owner = h.open();
    assert.throws(() => owner.capacity(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
    const result = await write(owner);
    assert.deepEqual(w.latest(id), result.head, "checked, written and witnessed");
  }
  // A rolled-back copy: the grant is refused by the witness check (not by the gate), and nothing is signed for it.
  const old = snapshot(h.historyFile);
  await h.owner.createAgent({ id: "agent:later" });
  restore(h.historyFile, old);
  const statements = w.state.statements.length;
  await assert.rejects(h.open().grant({ id: "grant:c", to: "agent:0", actions: ["read"], resources: ["doc:*"], expiresAt }), rollbackWith("WITNESS_AHEAD"));
  assert.equal(w.state.statements.length, statements);
});

test("addWitness with a quorum that needs the new witness, on a history longer than maxUnwitnessedEvents: the new witness is brought up before the binding write", async (t) => {
  const w1 = await startFakeWitness({ name: "q-one", seed: 11 });
  const w2 = await startFakeWitness({ name: "q-two", seed: 12 });
  t.after(() => Promise.all([w1.close(), w2.close()]));
  const h = await setup([w1], { mode: "sync", maxUnwitnessedEvents: 2 }, 4);
  const id = h.historyId();
  assert.ok(h.head().position > 2);
  const owner = h.open(); // the policy comes from the side file (an explicit policy would override the added witness's quorum)
  const added = await owner.addWitness({ url: w2.url, verifierKey: w2.verifierKey }, { quorum: 2 });
  assert.ok(added.eventId, "the binding was written");
  assert.equal(added.submitted, true, JSON.stringify(added.error));
  assert.equal(owner.witnessStatus().policy.quorum, 2);
  assert.deepEqual(w1.latest(id), h.head());
  assert.deepEqual(w2.latest(id), h.head());
  await owner.createAgent({ id: "agent:after" });
  assert.equal(owner.witnessStatus().unwitnessedEvents, 0);
});

test("a split view recorded in the side file fails verify even when the witness now answers consistently (the record only adds findings)", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2);
  assert.equal((await verifyHistoryWithWitnesses(h.historyFile)).ok, true);
  const path = witnessStatePathFor(h.historyFile);
  const doc = JSON.parse(readFileSync(path, "utf8"));
  doc.witnesses[w.origin].splitView = { detectedAt: 1_700_000_000_000, message: "split view: two checkpoints of size 4 with different roots" };
  writeFileSync(path, JSON.stringify(doc), { mode: 0o600 });
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, false);
  assert.equal(report.remoteWitnessStatus, "SPLIT_VIEW");
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_SPLIT_VIEW") && f.includes("recorded at 2023-11-14")), report.failures.join("\n"));
  const allowed = await verifyHistoryWithWitnesses(h.historyFile, { allowUnreachableWitness: true });
  assert.equal(allowed.ok, false, "a split view is never accepted as unreachable");
});

// an owner write at maxUnwitnessedEvents flushes first, as witness sync does.
// (The hook's session start at the limit after runtime events: packages/hooks/test/witness.test.mjs; an exempt write at
// the limit with the witness down: the A-24.1 / A-176.2 test above.)
test("an owner write at maxUnwitnessedEvents with the witness reachable again flushes first, then succeeds", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "async", maxUnwitnessedEvents: 4 }, 1);
  await h.owner.flush();
  w.down = true;
  for (let n = 0; n < 4; n += 1) await h.owner.createAgent({ id: `agent:queued:${n}` });
  w.down = false;
  // Before this fix this was refused (MAX_UNWITNESSED): the process had already checked once, so nothing was submitted.
  await h.owner.createAgent({ id: "agent:after-flush" });
  await h.owner.flush();
  assert.deepEqual(w.latest(h.historyId()), h.head());
  assert.equal(h.owner.witnessStatus().unwitnessedEvents, 0);
});

test("rollback evidence met by the flush at the limit throws ROLLBACK_DETECTED, never swallowed", async (t) => {
  const w = await startFakeWitness();
  t.after(() => w.close());
  const h = await setup([w], { mode: "async", maxUnwitnessedEvents: 4 }, 1);
  await h.owner.flush();
  w.down = true;
  for (let n = 0; n < 4; n += 1) await h.owner.createAgent({ id: `agent:queued:${n}` });
  const old = snapshot(h.historyFile); // at the limit, as the side file saw it
  w.down = false;
  await h.owner.flush();
  await h.owner.createAgent({ id: "agent:later" });
  await h.owner.flush(); // the witness now holds a head this copy will lack
  restore(h.historyFile, old);
  await assert.rejects(h.open().createAgent({ id: "agent:on-the-old-copy" }), (e) => e.code === "ROLLBACK_DETECTED");
});
