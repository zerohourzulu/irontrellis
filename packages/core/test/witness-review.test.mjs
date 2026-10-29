// Regression tests for the independent review of block 2 (docs/reference/witness-protocol.md §9.8, §5.3, §2.3), against the in-test fake
// witness. Each test turns one of the review's proofs of concept into a permanent check that failed on the reviewed code:
//  - B1: a relay replays an older GENUINE answer as the witness's latest (fresh latest notes over the client's nonce), and
//    the attacker-writable side file points a BOUND witness at that relay (bound witnesses are pinned to the binding);
//  - H1: the side file raises the quorum and adds an attacker witness so the bound witness's answer is "not needed"
//    (every check needs its answers from the bound set with the bound quorum);
//  - M1: the history file is swapped for an owner-signed fork in the unlocked window between an owner write and its
//    submission (statements are signed under the writer lock from the state this handle appended);
//  - the owner-signed policy minimum a binding carries: no side file or caller option lowers it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
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
const { witnessStatePathFor } = await import("../src/witness-state.ts");
const { boundPolicyOf, boundWitnessesOf, resetWitnessViews } = await import("../src/witness-session.ts");

let clock = 9_000_000;
const now = () => (clock += 1);
const config = (w, extra = {}) => ({ url: w.url, verifierKey: w.verifierKey, ...extra });
const SUFFIXES = ["", ".head", ".anchors", ".witness.json"];

async function setup(policy, events = 2) {
  const directory = mkdtempSync(join(tmpdir(), "wreview-"));
  const historyFile = join(directory, "history.jsonl");
  const domain = createLocalDomain();
  const owner = await createLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now, witness: policy });
  for (let n = 0; n < events; n += 1) await owner.createAgent({ id: `agent:${n}` });
  const open = (options = {}) => openLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now, ...options });
  const disk = () => openHistoryStore(historyFile, { inspect: true, witness: false }).state();
  return { directory, historyFile, domain, owner, open, disk, head: () => disk().head, historyId: () => disk().eventHistoryHashes[0] };
}
const snapshot = (historyFile) => Object.fromEntries(SUFFIXES.map((suffix) => [suffix, existsSync(historyFile + suffix) ? readFileSync(historyFile + suffix) : undefined]));
/** Puts files back as an attacker on the host would; the next handle is a fresh process. */
const restore = (historyFile, snap) => {
  resetWitnessViews();
  for (const [suffix, bytes] of Object.entries(snap)) {
    if (bytes === undefined) rmSync(historyFile + suffix, { force: true });
    else writeFileSync(historyFile + suffix, bytes, { mode: 0o600 });
  }
};
const editSideFile = (historyFile, change) => {
  const path = witnessStatePathFor(historyFile);
  writeFileSync(path, JSON.stringify(change(JSON.parse(readFileSync(path, "utf8")))), { mode: 0o600 });
};
const rollbackWith = (reason) => (error) => error?.code === "ROLLBACK_DETECTED" && error.detail?.reason === reason;
const headsOf = (w, historyId) => w.heads(historyId).map((s) => s.statement.head.position);

/**
 * The attacker's relay in front of a witness (loopback http, allowed without allowInsecureHttp): `mode` "forward"
 * (and, while `recording`, remember every GET answer by path), "replay" (answer `GET /v1/histories/:id` from what it remembered, i.e. a
 * genuine but OLD signed answer, forward the other reads, 503 every POST), or a `transform(pathname, body)` applied to
 * forwarded JSON answers; `answer(method, pathname)` may return `{ status, body }` to answer without forwarding.
 */
async function startRelay(target) {
  const relay = { mode: "forward", recording: true, recorded: new Map(), log: [], transform: undefined, answer: undefined };
  const server = createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => { raw += chunk; });
    req.on("end", async () => {
      const { pathname } = new URL(req.url, "http://relay.invalid");
      relay.log.push(`${req.method} ${pathname}`);
      const send = (status, text, type = "application/json") => { res.writeHead(status, { "content-type": type }); res.end(text); };
      const early = relay.answer?.(req.method, pathname);
      if (early !== undefined) return send(early.status, JSON.stringify(early.body));
      if (relay.mode === "replay") {
        if (req.method === "POST") return send(503, JSON.stringify({ error: { code: "INTERNAL", message: "down" } }));
        const old = /^\/v1\/histories\/0x[0-9a-f]{64}$/.test(pathname) ? relay.recorded.get(pathname) : undefined;
        if (old !== undefined) return send(old.status, old.text, old.type);
      }
      const headers = { ...(req.headers["content-type"] === undefined ? {} : { "content-type": req.headers["content-type"] }), ...(req.headers.authorization === undefined ? {} : { authorization: req.headers.authorization }) };
      const response = await fetch(`${target.url}${req.url}`, { method: req.method, headers, ...(raw === "" ? {} : { body: raw }) });
      let text = await response.text();
      const type = response.headers.get("content-type") ?? "application/json";
      if (req.method === "GET" && relay.mode === "forward" && relay.recording) relay.recorded.set(pathname, { status: response.status, text, type });
      if (relay.transform !== undefined && type.startsWith("application/json")) {
        const changed = await relay.transform(pathname, JSON.parse(text));
        if (changed !== undefined) text = JSON.stringify(changed);
      }
      send(response.status, text, type);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  relay.url = `http://127.0.0.1:${server.address().port}`;
  relay.close = () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); });
  return relay;
}

// ---------------------------------------------------------------- B1

test("B1 (review): a relay on the path to the bound witness replays an older genuine latest answer: verify fails REMOTE_WITNESS_INVALID, the requireOnOpen gate stays closed, the owner write is refused and nothing is appended", async (t) => {
  const w = await startFakeWitness({ name: "b1-bound-path", seed: 31 });
  const relay = await startRelay(w);
  t.after(async () => { await relay.close(); await w.close(); });
  // The witness is bound at the relay's URL: the relay is the network path (no TLS, or a loopback URL the host controls).
  const h = await setup({ witnesses: [config(relay, { verifierKey: w.verifierKey })], mode: "sync", requireOnOpen: true, cacheMs: 0 }, 2);
  const id = h.historyId();
  // The attacker records the witness's genuine answers about the old state, and keeps the old files.
  resetWitnessViews();
  assert.equal((await verifyHistoryWithWitnesses(h.historyFile)).ok, true);
  assert.ok(relay.recorded.has(`/v1/histories/${id}`));
  relay.recording = false;
  const old = snapshot(h.historyFile), oldHead = h.head();
  for (let n = 0; n < 2; n += 1) await h.owner.createAgent({ id: `agent:later:${n}` });
  h.owner.close();
  const witnessed = w.latest(id);
  assert.ok(witnessed.position > oldHead.position);
  restore(h.historyFile, old);
  const size = w.size;

  for (const [attack, arm] of [
    // The recorded answer (a genuine signed answer, just old): its latest note answers another nonce.
    ["replayed recorded answer", () => { relay.mode = "replay"; relay.transform = undefined; }],
    // The review's PoC: a fresh answer whose `latest` is swapped for the genuine receipt of the older head.
    ["older genuine receipt as latest", () => {
      relay.mode = "forward";
      relay.transform = async (pathname, body) => {
        if (pathname !== `/v1/histories/${id}`) return undefined;
        const older = await (await fetch(`${w.url}/v1/histories/${id}/heads/${oldHead.position}`)).json();
        return { ...body, latest: { head: older.head, receipt: older.receipt } };
      };
    }],
  ]) {
    arm();
    resetWitnessViews();
    const report = await verifyHistoryWithWitnesses(h.historyFile);
    assert.equal(report.ok, false, `${attack}: verify must fail`);
    assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_INVALID") && /latest note/.test(f)), `${attack}: ${report.failures.join("\n")}`);
    assert.equal(report.remoteWitnessStatus, "INVALID");
    assert.equal((await verifyHistoryWithWitnesses(h.historyFile, { allowUnreachableWitness: true })).ok, false, `${attack}: an invalid answer is not unreachability`);
    // requireOnOpen: the gate stays closed.
    resetWitnessViews();
    const reader = openHistoryStore(h.historyFile);
    await assert.rejects(reader.checkWitnesses(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.cause === "WITNESS_INVALID_RESPONSE", attack);
    assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED", attack);
    reader.close();
    // The owner write is refused and nothing is appended to the rolled-back copy.
    resetWitnessViews();
    const owner = h.open();
    await assert.rejects(owner.createAgent({ id: `agent:on-old-copy:${attack}` }), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "INVALID_ANSWER", attack);
    await assert.rejects(owner.createAgent({ id: `agent:again:${attack}` }), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "INVALID_ANSWER", `${attack}: every write asks again`);
    owner.close();
    assert.deepEqual(h.head(), oldHead, `${attack}: nothing appended`);
  }
  assert.equal(w.size, size, "the witness received nothing for the old copy");
  assert.deepEqual(w.latest(id), witnessed);
  // The honest network again: the rollback is plain to see.
  relay.mode = "forward";
  relay.transform = undefined;
  resetWitnessViews();
  const honest = await verifyHistoryWithWitnesses(h.historyFile);
  assert.ok(honest.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")), honest.failures.join("\n"));
});

test("B1 (review): the side file (or a caller's policy) cannot relocate a BOUND witness: its URL comes from the owner-signed binding, the attacker's relay is never asked, the rollback is found", async (t) => {
  const w = await startFakeWitness({ name: "b1-pinned", seed: 32 });
  const relay = await startRelay(w);
  t.after(async () => { await relay.close(); await w.close(); });
  const h = await setup({ witnesses: [config(w)], mode: "sync", requireOnOpen: true, cacheMs: 0 }, 2);
  const id = h.historyId();
  const old = snapshot(h.historyFile), oldHead = h.head();
  await fetch(`${relay.url}/v1/checkpoint`);
  await fetch(`${relay.url}/v1/histories/${id}`); // the relay remembers the witness's answer about the old state
  for (let n = 0; n < 2; n += 1) await h.owner.createAgent({ id: `agent:later:${n}` });
  h.owner.close();
  restore(h.historyFile, old);
  relay.mode = "replay";
  relay.log.length = 0;
  // The review's PoC: the bound verifier key at the relay's URL, everything remembered dropped.
  editSideFile(h.historyFile, (doc) => ({ ...doc, policy: { ...doc.policy, witnesses: doc.policy.witnesses.map((x) => ({ ...x, url: relay.url })) }, witnesses: {}, pending: [] }));
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && f.includes(w.url)), report.failures.join("\n"));
  assert.deepEqual(report.remoteWitnesses.map((r) => [r.url, r.bound]), [[w.url, true]]);
  resetWitnessViews();
  const owner = h.open();
  assert.deepEqual(owner.witnessStatus().witnesses.map((x) => x.url), [w.url], "pinned to the binding");
  await assert.rejects(owner.createAgent({ id: "agent:on-old-copy" }), rollbackWith("WITNESS_AHEAD"));
  owner.close();
  // A caller's explicit policy cannot move it either (it may bring a transport or a token, not a URL).
  resetWitnessViews();
  const explicit = openHistoryStore(h.historyFile, { witness: { witnesses: [{ url: relay.url, verifierKey: w.verifierKey }], requireOnOpen: false } });
  assert.deepEqual(explicit.witnessStatus().witnesses.map((x) => x.url), [w.url]);
  await assert.rejects(explicit.checkWitnesses(), rollbackWith("WITNESS_AHEAD"));
  explicit.close();
  assert.deepEqual(h.head(), oldHead);
  assert.deepEqual(relay.log, [], "the relay was never asked");
});

test("a bound witness moves to a new URL only by an owner-signed re-binding (addWitness with the new URL for the same verifier key)", async (t) => {
  const w = await startFakeWitness({ name: "rebind", seed: 33 });
  const relay = await startRelay(w); // the witness's new address (here: a plain forwarder)
  t.after(async () => { await relay.close(); await w.close(); });
  const h = await setup({ witnesses: [config(w)], mode: "sync" }, 1);
  assert.deepEqual(boundWitnessesOf(h.disk()).map((b) => b.url), [w.url]);
  const change = await h.owner.addWitness(config(relay, { verifierKey: w.verifierKey }));
  assert.ok(change.eventId !== undefined, "a new BIND event");
  assert.deepEqual(boundWitnessesOf(h.disk()).map((b) => b.url), [relay.url]);
  await h.owner.createAgent({ id: "agent:after-move" });
  assert.ok(relay.log.some((line) => line.startsWith("POST /v1/histories/")), "the new URL is used");
  assert.deepEqual(w.latest(h.historyId()), h.head());
  h.owner.close();
});

// ---------------------------------------------------------------- H1

test("H1 (review): a side file that raises the quorum and adds an attacker witness cannot make the bound witness optional: it is still asked and its rollback evidence is fatal", async (t) => {
  const honest = await startFakeWitness({ name: "h1-honest", seed: 41 });
  const attacker = await startFakeWitness({ name: "h1-attacker", seed: 42 }); // registration open, knows nothing
  t.after(async () => { await honest.close(); await attacker.close(); });
  const h = await setup({ witnesses: [config(honest)], mode: "sync", requireOnOpen: true, cacheMs: 0 }, 2);
  const id = h.historyId();
  const old = snapshot(h.historyFile), oldHead = h.head();
  for (let n = 0; n < 2; n += 1) await h.owner.createAgent({ id: `agent:later:${n}` });
  h.owner.close();
  const witnessed = honest.latest(id);
  restore(h.historyFile, old);
  // The review's PoC: [bound key at a dead URL with a 1 ms timeout, attacker witness], quorum 2 (n - q + 1 = 1 answer).
  editSideFile(h.historyFile, (doc) => ({
    ...doc, witnesses: {}, pending: [],
    policy: { witnesses: [{ url: "http://127.0.0.1:1", verifierKey: honest.verifierKey, timeoutMs: 1 }, config(attacker)], quorum: 2, mode: "async", maxUnwitnessedEvents: Number.MAX_SAFE_INTEGER, requireOnOpen: false, cacheMs: 60_000 },
  }));
  for (const allowUnreachableWitness of [false, true]) {
    resetWitnessViews();
    const report = await verifyHistoryWithWitnesses(h.historyFile, { allowUnreachableWitness });
    assert.equal(report.ok, false, `allowUnreachableWitness ${allowUnreachableWitness}`);
    assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && f.includes(honest.url)), report.failures.join("\n"));
  }
  resetWitnessViews();
  const reader = openHistoryStore(h.historyFile);
  assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED", "the binding's requireOnOpen holds whatever the side file says");
  await assert.rejects(reader.checkWitnesses(), rollbackWith("WITNESS_AHEAD"));
  reader.close();
  resetWitnessViews();
  const owner = h.open();
  await assert.rejects(owner.createAgent({ id: "agent:on-old-copy" }), rollbackWith("WITNESS_AHEAD"));
  owner.close();
  assert.deepEqual(h.head(), oldHead);
  assert.deepEqual(honest.latest(id), witnessed);
  assert.deepEqual(attacker.heads(id), [], "no statement for the old copy went anywhere");
});

test("H1 (review): with two bound witnesses (bound quorum 1: both must answer), a side-file witness never stands in for an unreachable bound one", async (t) => {
  const w1 = await startFakeWitness({ name: "h1-bound-1", seed: 43 });
  const w2 = await startFakeWitness({ name: "h1-bound-2", seed: 44 });
  const extra = await startFakeWitness({ name: "h1-extra", seed: 45 });
  t.after(async () => { await w1.close(); await w2.close(); await extra.close(); });
  const h = await setup({ witnesses: [config(w1), config(w2)], quorum: 1, mode: "sync" }, 1);
  assert.deepEqual(boundPolicyOf(h.disk()), { quorum: 1, requireOnOpen: false, maxUnwitnessedEvents: 1000 });
  h.owner.close();
  // The side file adds a third witness and asks for quorum 2: the policy-wide rule would accept any 2 of 3 answers.
  editSideFile(h.historyFile, (doc) => ({ ...doc, policy: { ...doc.policy, witnesses: [...doc.policy.witnesses, config(extra)], quorum: 2 } }));
  w2.down = true;
  resetWitnessViews();
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, false, "one bound witness is down and the bound quorum 1 needs both");
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_UNREACHABLE") && /witnesses the history binds/.test(f)), report.failures.join("\n"));
  w2.down = false;
  resetWitnessViews();
  const back = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(back.ok, true, back.failures.join("\n"));
});

// ---------------------------------------------------------------- the owner-signed policy minimum

test("the binding's owner-signed policy minimum (quorum, requireOnOpen, maxUnwitnessedEvents) holds whatever the side file or a caller says; effective policy = strictest", async (t) => {
  const w = await startFakeWitness({ name: "minimum", seed: 51 });
  t.after(() => w.close());
  // 4, not 2: the creation write (genesis, principal, binding) and one agent leave events to witness in async mode.
  const h = await setup({ witnesses: [config(w)], mode: "async", requireOnOpen: true, maxUnwitnessedEvents: 4, cacheMs: 0 }, 1);
  const state = h.disk();
  assert.deepEqual(boundPolicyOf(state), { quorum: 1, requireOnOpen: true, maxUnwitnessedEvents: 4 });
  const binding = state.events.find((event) => event.type === "WITNESSES_BOUND");
  assert.deepEqual(binding.data.policy, { quorum: 1, requireOnOpen: true, maxUnwitnessedEvents: 4 }, "signed with the binding event");
  await h.owner.flush(); // no submission of this process still in flight (it would count as this process's fresh check)
  h.owner.close();
  editSideFile(h.historyFile, (doc) => ({ ...doc, policy: { ...doc.policy, requireOnOpen: false, maxUnwitnessedEvents: 1_000_000 } }));
  // (cacheMs 0: an owner-sealed cached answer within cacheMs would legitimately open the gate without the network.)
  for (const explicit of [undefined, { witnesses: [config(w)], requireOnOpen: false, maxUnwitnessedEvents: 1_000_000, cacheMs: 0 }]) {
    resetWitnessViews();
    const store = openHistoryStore(h.historyFile, explicit === undefined ? {} : { witness: explicit });
    assert.equal(store.witnessStatus().policy.requireOnOpen, true);
    assert.equal(store.witnessStatus().policy.maxUnwitnessedEvents, 4);
    assert.throws(() => store.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
    store.close();
  }
  // A stricter side file still counts (strictest wins).
  editSideFile(h.historyFile, (doc) => ({ ...doc, policy: { ...doc.policy, maxUnwitnessedEvents: 2 } }));
  resetWitnessViews();
  const owner = h.open();
  assert.equal(owner.witnessStatus().policy.maxUnwitnessedEvents, 2);
  // maxUnwitnessedEvents refuses writes while the witness is down (after this process's check opened the gate).
  await owner.checkWitnesses();
  w.down = true;
  await owner.createAgent({ id: "agent:queued:1" });
  await owner.createAgent({ id: "agent:queued:2" });
  await assert.rejects(owner.createAgent({ id: "agent:queued:3" }), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "MAX_UNWITNESSED" && e.detail.maxUnwitnessedEvents === 2);
  w.down = false;
  await owner.flush();
  // Lowering the minimum takes the owner key: a new binding with the changed policy.
  await owner.addWitness(config(w), { requireOnOpen: false, maxUnwitnessedEvents: 50 });
  assert.deepEqual(boundPolicyOf(h.disk()), { quorum: 1, requireOnOpen: false, maxUnwitnessedEvents: 50 });
  owner.close();
});

// ---------------------------------------------------------------- M1

test("M1 (review): the file is swapped for an owner-signed fork between an owner write and its submission: FILE_CHANGED_UNDER_WRITER, nothing is signed for the fork, the witness log is unchanged", async (t) => {
  const w = await startFakeWitness({ name: "m1", seed: 61 });
  t.after(() => w.close());
  const h = await setup({ witnesses: [config(w)], mode: "sync" }, 2);
  const id = h.historyId();
  h.owner.close();
  // The honest owner process: the file is swapped for F while its sync submission asks the witness (the unlocked window).
  let armed = false, swapped = false, F;
  const owner = h.open({
    witness: {
      witnesses: [config(w)], mode: "sync",
      fetch: async (url, init) => {
        if (armed && !swapped && init.method === "GET" && new URL(url).pathname === `/v1/histories/${id}`) {
          swapped = true;
          for (const suffix of ["", ".head", ".anchors"]) {
            if (F[suffix] === undefined) continue;
            writeFileSync(`${h.historyFile}${suffix}.swap`, F[suffix], { mode: 0o600 });
            renameSync(`${h.historyFile}${suffix}.swap`, h.historyFile + suffix);
          }
        }
        return globalThis.fetch(url, init);
      },
    },
  });
  await owner.createAgent({ id: "agent:warm" }); // this process has checked and submitted once
  const x = w.latest(id); // the witness latest: a prefix of both branches
  assert.deepEqual(x, h.head());
  // A genuine second branch F: a copy of the history at x continued with the owner key (witness off), e.g. a restored
  // backup that was written on, or a second owner process.
  const forkFile = join(h.directory, "fork.jsonl");
  for (const suffix of ["", ".head", ".anchors"]) if (existsSync(h.historyFile + suffix)) copyFileSync(h.historyFile + suffix, forkFile + suffix);
  copyFileSync(`${h.historyFile}.owner-key.json`, `${forkFile}.owner-key.json`);
  const fork = openLocalOwner({ historyFile: forkFile, domain: h.domain, owner: "owner", controller: "controller", now, witness: false });
  for (let n = 0; n < 3; n += 1) await fork.createAgent({ id: `agent:fork:${n}` });
  fork.close();
  F = snapshot(forkFile);
  const forkState = openHistoryStore(forkFile, { inspect: true, witness: false }).state();
  assert.equal(forkState.eventHistoryHashes[x.position], x.hash, "x is a prefix of F (so a witness check alone cannot tell)");
  const before = w.state.statements.length, size = w.size, latest = w.latest(id);
  armed = true;
  await assert.rejects(owner.createAgent({ id: "agent:honest" }), rollbackWith("FILE_CHANGED_UNDER_WRITER"));
  assert.equal(swapped, true);
  assert.equal(w.state.statements.length, before, "nothing was signed or sent after the swap");
  assert.equal(w.size, size, "the witness log is unchanged");
  assert.deepEqual(w.latest(id), latest);
  assert.ok(!headsOf(w, id).some((position) => forkState.eventHistoryHashes[position] !== undefined && w.heads(id).some((s) => s.statement.head.hash === forkState.eventHistoryHashes[position] && position > x.position)),
    "no head of the fork reached the witness");
  // Sticky for this handle: reads, writes and flush refuse; still nothing reaches the witness.
  assert.throws(() => owner.capacity(), rollbackWith("FILE_CHANGED_UNDER_WRITER"));
  await assert.rejects(owner.createAgent({ id: "agent:again" }), rollbackWith("FILE_CHANGED_UNDER_WRITER"));
  await assert.rejects(owner.flush(), rollbackWith("FILE_CHANGED_UNDER_WRITER"));
  assert.equal(w.state.statements.length, before);
  assert.equal(owner.witnessStatus().alarm.reason, "FILE_CHANGED_UNDER_WRITER");
  owner.close();
  // The fork does not verify against the witness chain... unless it is on it: here x is a prefix of F and nothing past
  // it was witnessed, so F verifies with an unwitnessed tail; what matters is that the witness never attested F.
  resetWitnessViews();
  const forkReport = await verifyHistoryWithWitnesses(forkFile, { witness: { witnesses: [config(w)] } });
  assert.ok(forkReport.notes.some((n) => n.startsWith("UNWITNESSED_TAIL")), forkReport.notes.join("\n"));
});

// ---------------------------------------------------------------- M2

test("M2 (review): an owner key rotation is pushed to the witnesses before rotateOwnerKey returns, in async mode too; a witness that missed it shows it pending and gets it before any later head", async (t) => {
  const w = await startFakeWitness({ name: "m2", seed: 71 });
  const late = await startFakeWitness({ name: "m2-late", seed: 72 });
  t.after(async () => { await w.close(); await late.close(); });
  // quorum 2 of 2: a check (and a submission round) needs n - q + 1 = 1 answer, so one witness down is tolerated.
  const h = await setup({ witnesses: [config(w), config(late)], quorum: 2, mode: "async" }, 1);
  await h.owner.flush();
  const id = h.historyId();
  late.down = true;
  // Settle any background round still in flight from before the witness went down (an asynchronous signer gives the async
  // worker time to start one): its answer, received later, would count as a fresh confirmation of `late`.
  await h.owner.flush().catch(() => undefined);
  // WITNESS-DESIGN §11.2: the default two-phase rotation needs every bound witness at the head; with one down it aborts, nothing written.
  const head = h.head();
  await assert.rejects(h.owner.rotateOwnerKey({ reason: "leaked" }), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "ROTATION_NEEDS_WITNESSES");
  assert.deepEqual(h.head(), head);
  const rotated = await h.owner.rotateOwnerKey({ reason: "leaked", emergency: true });
  // Recorded by the reachable witness when the call returns (no worker tick needed).
  assert.deepEqual(w.histories.get(id).epochs.map((epoch) => epoch.fromPosition), [0, rotated.fromPosition]);
  const status = h.owner.witnessStatus();
  assert.equal(status.witnesses.find((x) => x.url === w.url).pendingRotations, 0);
  assert.ok(status.pending.some((item) => item.kind === "rotation"), "kept in the queue for the witness that missed it");
  // The witness that missed it: the rotation (and the old-key statement for its head) come before any new-key head.
  late.down = false;
  await h.owner.createAgent({ id: "agent:after-rotation" });
  await h.owner.flush();
  const kinds = late.entries.filter((entry) => entry.historyId === id).map((entry) => (entry.kind === "HEAD" ? `HEAD ${entry.signedStatement.statement.head.position} ${entry.signedStatement.keyId}` : entry.kind));
  const rotatedAt = kinds.indexOf("ROTATED");
  assert.ok(rotatedAt > 0, kinds.join(" | "));
  assert.equal(kinds[rotatedAt - 1], `HEAD ${rotated.head.position} ${rotated.retired[0]}`, "the old-key statement for the rotation head, then the rotation");
  assert.ok(kinds.slice(rotatedAt + 1).every((line) => line.endsWith(rotated.keyId)), "every later head by the new key");
  assert.equal(h.owner.witnessStatus().witnesses.every((x) => x.pendingRotations === 0), true);
  h.owner.close();
});

// ---------------------------------------------------------------- N1 (re-review)

test("N1 (re-review): an owner seal is bound to its witness (verifier key, pinned URL, origin from the binding's receipt): a seal relabelled, copied or moved onto another witness's entry, a bound one included, is not accepted and the requireOnOpen gate asks the network; a witness only the side file adds is never sealed", async (t) => {
  const a = await startFakeWitness({ name: "n1-a", seed: 81 });
  const b = await startFakeWitness({ name: "n1-b", seed: 82 });
  const c = await startFakeWitness({ name: "n1-side-file-only", seed: 83 });
  t.after(async () => { await a.close(); await b.close(); await c.close(); });
  // Two bound witnesses with the bound quorum 1: a requireOnOpen check needs an answer (or a valid sealed one) from each.
  const h = await setup({ witnesses: [config(a), config(b)], quorum: 1, mode: "sync", requireOnOpen: true, cacheMs: 600_000 }, 1);
  h.owner.close();
  // A witness only the side file adds (no binding, no out-of-band minimum), with a quorum that needs just one answer of three.
  // (quorum 3 of 3 for the whole policy: the policy-wide rule needs one answer, the bound set still both of its own.)
  editSideFile(h.historyFile, (doc) => ({ ...doc, policy: { ...doc.policy, witnesses: [...doc.policy.witnesses, config(c)], quorum: 3 } }));
  resetWitnessViews();
  const owner = h.open();
  await owner.createAgent({ id: "agent:sealed" });
  owner.close();
  const sideNow = readFileSync(witnessStatePathFor(h.historyFile));
  const side = JSON.parse(sideNow);
  const originOf = (w) => Object.keys(side.witnesses).find((origin) => side.witnesses[origin].verifierKey === w.verifierKey);
  const [originA, originB, originC] = [originOf(a), originOf(b), originOf(c)];
  assert.ok(side.witnesses[originA].latest.seal !== undefined && side.witnesses[originB].latest.seal !== undefined, "bound witnesses are sealed");
  assert.equal(side.witnesses[originC].latest.seal, undefined, "a witness only the side file adds is never sealed");
  const requests = () => a.state.requests.length + b.state.requests.length + c.state.requests.length;
  const open = () => { resetWitnessViews(); return openHistoryStore(h.historyFile); };
  // Baseline: each bound witness's own sealed answer opens the gate without a network call.
  {
    const before = requests();
    const reader = open();
    assert.equal(reader.state().head.position, h.head().position);
    assert.equal(reader.witnessStatus().witnesses.find((w) => w.verifierKey === b.verifierKey).source, "sealed-cache");
    reader.close();
    assert.equal(requests(), before, "no network call");
  }
  const attacks = {
    // the review's scenario: a's sealed entry relabelled as b's (b's origin looked up in the side file), b's own entry gone
    "a's entry relabelled as b's": (w) => { w[originA] = { ...w[originA], verifierKey: b.verifierKey, url: b.url }; delete w[originB]; },
    "a's sealed answer copied into b's entry": (w) => { w[originB] = { ...w[originB], latest: w[originA].latest }; },
    "a's entry moved to b's origin with b's key and URL": (w) => { w[originB] = { ...w[originA], verifierKey: b.verifierKey, url: b.url }; },
    "b's sealed answer under another origin": (w) => { w["irontrellis-witness/elsewhere"] = w[originB]; delete w[originB]; },
    "a's sealed answer relabelled onto the side-file witness": (w) => { w[originC] = { ...w[originA], verifierKey: c.verifierKey, url: c.url }; delete w[originB]; },
  };
  for (const [name, change] of Object.entries(attacks)) {
    writeFileSync(witnessStatePathFor(h.historyFile), sideNow, { mode: 0o600 });
    editSideFile(h.historyFile, (doc) => { const witnesses = { ...doc.witnesses }; change(witnesses); return { ...doc, witnesses }; });
    const asked = b.state.requests.length;
    const reader = open();
    assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED", `${name}: not accepted, the gate stays closed`);
    assert.notEqual(reader.witnessStatus().witnesses.find((w) => w.verifierKey === b.verifierKey).source, "sealed-cache", name);
    await reader.checkWitnesses();
    assert.ok(b.state.requests.length > asked, `${name}: b itself was asked over the network`);
    assert.equal(reader.state().head.position, h.head().position);
    reader.close();
  }
});

test("N1 (re-review): a witness only the side file names never gets a seal, so relabelling its entry as a bound witness's cannot open the gate", async (t) => {
  const bound = await startFakeWitness({ name: "n1-only-bound", seed: 84 });
  const extra = await startFakeWitness({ name: "n1-extra", seed: 85 });
  t.after(async () => { await bound.close(); await extra.close(); });
  const h = await setup({ witnesses: [config(bound)], mode: "sync", requireOnOpen: true, cacheMs: 600_000 }, 1);
  h.owner.close();
  editSideFile(h.historyFile, (doc) => ({ ...doc, policy: { ...doc.policy, witnesses: [...doc.policy.witnesses, config(extra)], quorum: 2 } }));
  resetWitnessViews();
  const owner = h.open();
  await owner.createAgent({ id: "agent:x" });
  owner.close();
  const side = JSON.parse(readFileSync(witnessStatePathFor(h.historyFile), "utf8"));
  const originBound = Object.keys(side.witnesses).find((o) => side.witnesses[o].verifierKey === bound.verifierKey);
  const originExtra = Object.keys(side.witnesses).find((o) => side.witnesses[o].verifierKey === extra.verifierKey);
  assert.equal(side.witnesses[originExtra].latest.seal, undefined);
  // The review's scenario on the reviewed code: the extra witness's (sealed) entry relabelled as the bound one's.
  editSideFile(h.historyFile, (doc) => {
    const witnesses = { ...doc.witnesses };
    witnesses[originExtra] = { ...witnesses[originExtra], verifierKey: bound.verifierKey, url: bound.url };
    delete witnesses[originBound];
    return { ...doc, witnesses };
  });
  resetWitnessViews();
  const asked = bound.state.requests.length;
  const reader = openHistoryStore(h.historyFile);
  assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
  await reader.checkWitnesses();
  assert.ok(bound.state.requests.length > asked, "the bound witness was asked");
  reader.close();
});

// ---------------------------------------------------------------- N2 (re-review)

test("N2 (re-review): a bound witness without a registration receipt (bound offline): its unsigned 404 never counts for readers or verify (unreachable, the availability policy applies), and the binding is flagged until witness add records the receipt", async (t) => {
  const w = await startFakeWitness({ name: "n2", seed: 91 });
  const relay = await startRelay(w);
  t.after(async () => { await relay.close(); await w.close(); });
  const directory = mkdtempSync(join(tmpdir(), "wreview-n2-"));
  const historyFile = join(directory, "history.jsonl");
  const domain = createLocalDomain();
  const created = await createLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now });
  await created.createAgent({ id: "agent:0" });
  // Bound while unreachable: no receipt in the binding.
  relay.answer = () => ({ status: 503, body: { error: { code: "INTERNAL", message: "down" } } });
  await created.addWitness(config(relay, { verifierKey: w.verifierKey }), { mode: "sync", requireOnOpen: true, cacheMs: 0 }, { allowOffline: true });
  relay.answer = undefined;
  const disk = () => openHistoryStore(historyFile, { inspect: true, witness: false }).state();
  assert.equal(boundWitnessesOf(disk()).length, 1);
  assert.equal((await import("../src/witness-session.ts")).boundRegistrationOf(disk(), w.verifierKey), undefined, "receipt-less binding");
  // The owner writes on (an owner-keyed process registers; the registration's signed note is its answer) and the witness follows.
  await created.createAgent({ id: "agent:1" });
  const old = snapshot(historyFile), oldHead = disk().head;
  await created.createAgent({ id: "agent:2" });
  await created.createAgent({ id: "agent:3" });
  const status = created.witnessStatus();
  assert.equal(status.witnesses[0].bindingWithoutReceipt, true);
  created.close();
  const id = disk().eventHistoryHashes[0];
  assert.deepEqual(w.latest(id), disk().head);
  // Rollback, and the relay forges an unsigned "not registered".
  restore(historyFile, old);
  relay.answer = (method, pathname) => (method === "GET" && pathname === `/v1/histories/${id}` ? { status: 404, body: { error: { code: "NOT_REGISTERED", message: "unknown history" } } } : undefined);
  const report = await verifyHistoryWithWitnesses(historyFile);
  assert.equal(report.ok, false, report.notes.join("\n"));
  assert.ok(report.failures.some((f) => f.startsWith("REMOTE_WITNESS_UNREACHABLE") && /unsigned/.test(f)), report.failures.join("\n"));
  assert.ok(report.notes.some((n) => n.startsWith("REMOTE_WITNESS_BINDING_WITHOUT_RECEIPT") && /witness add/.test(n)), report.notes.join("\n"));
  assert.ok(!report.notes.some((n) => n.startsWith("REMOTE_WITNESS_UNREGISTERED")), "not counted as an answer");
  assert.equal(report.remoteWitnesses[0].status, "UNREACHABLE");
  // allowUnreachableWitness is the operator's explicit acceptance (the availability policy), with the flag still shown.
  const allowed = await verifyHistoryWithWitnesses(historyFile, { allowUnreachableWitness: true });
  assert.ok(allowed.notes.some((n) => n.startsWith("REMOTE_WITNESS_BINDING_WITHOUT_RECEIPT")));
  resetWitnessViews();
  const reader = openHistoryStore(historyFile);
  assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
  await assert.rejects(reader.checkWitnesses(), (e) => e.code === "WITNESS_UNAVAILABLE" && /unsigned answer/.test(e.message));
  assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE", "the requireOnOpen gate stays closed");
  assert.equal(reader.witnessStatus().witnesses[0].bindingWithoutReceipt, true);
  reader.close();
  assert.deepEqual(disk().head, oldHead);
  // Honest network: the rollback is found; with the current copy back, witness add records the receipt and the flag goes.
  relay.answer = undefined;
  resetWitnessViews();
  assert.ok((await verifyHistoryWithWitnesses(historyFile)).failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")));
});
