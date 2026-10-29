// Block 3.2 performance changes that must not change a single verdict:
//  - speculative replay (crypto/parallel-verify.ts): a large format-1 file is replayed with its Ed25519
//    verifications on worker threads; the result is kept only when every one verified, otherwise the file is
//    replayed sequentially. Every test compares the pool against the sequential engine on the same bytes: the
//    same head and state, or the same first error (message, position and code), whatever mix of bad signatures
//    and bad transitions the file holds, and whatever the pool does (answers, stalls).
//  - verify() on an open handle skips the re-parse only for bytes whose SHA-256 equals what the cached replay
//    read; any other file is re-parsed or replayed exactly as before.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { openHistoryStore: openHistoryStoreStrict, createHistoryStore: createHistoryStoreStrict, SPECULATIVE_REPLAY_MIN_RECORDS } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const createHistoryStore = (path, events, options = {}) => createHistoryStoreStrict(path, events, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { signerFromKeyPair, signControlEvent } = await import("../src/signer.ts");
const { HistoryHasher, hashCanonical } = await import("../src/hash.ts");
const { isControlEvent, TRELLIS_VERSIONS, ADAPTER_POLICY_HASHES } = await import("../src/events.ts");
const suites = await import("../src/crypto/suites.ts");
const pv = await import("../src/crypto/parallel-verify.ts");

const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: "deployment:parallel-verify" });
const owner = suites.keyPairFromPrivateKey("ed25519", "owner:pv", `0x${"42".repeat(32)}`);
const signer = signerFromKeyPair(owner);
const LINE_VERSION = "irontrellis-portable-file-store/1";
const COUNT = SPECULATIVE_REPLAY_MIN_RECORDS + 300;

const workspace = (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-pv-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const genesis = () => ({
  id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
  data: {
    domain: DOMAIN, versions: { ...TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: [{ keyId: owner.keyId, scheme: "ed25519", credential: owner.credential }],
    adapterPolicyHash: ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:pv", policyVersion: "policy:pv/1",
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:pv", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
  },
});
const agent = (n, agentId = `agent:${n}`) => ({ id: `agent:${n}`, type: "AGENT_CREATED", timestamp: n + 2, data: { agentId, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
const unsigned = (event) => { const { controlAuthorization: _dropped, ...data } = event.data; return { ...event, data }; };

/** Events 0..count-1 (genesis, principal, agents), every control event signed over the head before it. */
async function build(count, edit = () => undefined) {
  const events = [genesis(), { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }];
  for (let n = 0; events.length < count; n += 1) events.push(agent(n));
  for (let i = 0; i < events.length; i += 1) events[i] = edit(i, events[i]) ?? events[i];
  return resign(events, 0);
}
/** Re-signs every control event at or after `from` over the head before it; `keep` positions keep their (possibly corrupt) signature. */
async function resign(events, from, keep = new Set()) {
  const hasher = new HistoryHasher("irontrellis-event/1");
  const out = [];
  let head = null;
  for (let i = 0; i < events.length; i += 1) {
    let event = events[i];
    if (i >= from && i > 0 && isControlEvent(event.type) && !keep.has(i)) event = await signControlEvent(signer, unsigned(event), DOMAIN, head, "sha256");
    out.push(event);
    head = { hash: hasher.push(event), position: i, canonicalTime: event.timestamp };
  }
  return out;
}
/** A store file with a valid record chain for whatever `events` are (the replay decides). */
function write(path, events) {
  let previousHash = null;
  const lines = events.map((event) => {
    const recordHash = hashCanonical({ version: LINE_VERSION, previousHash, event }, "sha256");
    const line = JSON.stringify({ version: LINE_VERSION, previousHash, event, recordHash });
    previousHash = recordHash;
    return line;
  });
  writeFileSync(path, `${lines.join("\n")}\n`);
}
const flip = (hex) => `${hex.slice(0, -2)}${hex.endsWith("00") ? "01" : "00"}`;
const corruptSignature = (event) => ({ ...event, data: { ...event.data, controlAuthorization: { ...event.data.controlAuthorization, signature: flip(event.data.controlAuthorization.signature) } } });

/** Opens `path` (inspect: no pin needed) with `threads` workers; the outcome as comparable data. */
async function openWith(path, threads, options = {}) {
  await pv.setVerifyThreadsForTests(threads, options);
  try {
    const store = openHistoryStore(path, { inspect: true });
    const state = store.state();
    const outcome = { ok: true, head: store.head(), events: state.events.length, hashes: state.eventHistoryHashes.slice(), agents: state.agents.size };
    store.close();
    return { outcome, stats: pv.speculationStats() };
  } catch (error) {
    return { outcome: { ok: false, code: error.code, message: error.message, detail: error.detail }, stats: pv.speculationStats() };
  }
}
test.after(() => pv.setVerifyThreadsForTests(undefined));

test("speculative replay: a large valid history opens to the same state with the pool as sequentially", async (t) => {
  const path = join(workspace(t), "valid.jsonl");
  write(path, await build(COUNT));
  const sequential = await openWith(path, 0);
  const pooled = await openWith(path, 2);
  assert.equal(sequential.outcome.ok, true);
  assert.deepEqual(pooled.outcome, sequential.outcome);
  assert.equal(sequential.stats.runs, 0, "no pool: no speculation");
  assert.equal(pooled.stats.runs, 1);
  assert.equal(pooled.stats.discarded, 0);
  assert.equal(pooled.stats.queued, COUNT - 1, "one queued verification per control event");
  // Below the threshold the replay is sequential.
  const small = join(workspace(t), "small.jsonl");
  write(small, await build(SPECULATIVE_REPLAY_MIN_RECORDS - 1));
  assert.equal((await openWith(small, 2)).stats.runs, 0);
});

test("speculative replay: a bad signature gives the sequential error and the speculation is discarded", async (t) => {
  const dir = workspace(t);
  const k = SPECULATIVE_REPLAY_MIN_RECORDS + 100;
  const events = await build(COUNT);
  events[k] = corruptSignature(events[k]);
  // Later events re-signed over the new heads, so the corrupt signature is the only defect.
  const path = join(dir, "bad-signature.jsonl");
  write(path, await resign(events, k + 1));
  const sequential = await openWith(path, 0);
  const pooled = await openWith(path, 2);
  assert.equal(sequential.outcome.ok, false);
  assert.equal(sequential.outcome.detail.position, k);
  assert.equal(sequential.outcome.detail.code, "CONTROL_AUTHORIZATION_INVALID");
  assert.deepEqual(pooled.outcome, sequential.outcome);
  assert.equal(pooled.stats.discarded, 1, "the speculative result was thrown away");
});

test("speculative replay: bad transitions before and after a bad signature give the sequential first error", async (t) => {
  const dir = workspace(t);
  const early = SPECULATIVE_REPLAY_MIN_RECORDS + 50, late = SPECULATIVE_REPLAY_MIN_RECORDS + 150;
  // A duplicate agent (correctly signed): TRANSITION_INVALID at its position.
  const duplicate = (i, event) => (event.type === "AGENT_CREATED" ? agent(i - 2, "agent:0") : event);
  // 1. The transition failure comes first, a bad signature later: the transition failure is reported; the speculation
  //    ended there with every queued signature valid, so its error stands.
  {
    let events = await build(COUNT, (i, event) => (i === early ? duplicate(i, event) : undefined));
    events[late] = corruptSignature(events[late]);
    events = await resign(events, late + 1);
    const path = join(dir, "transition-then-signature.jsonl");
    write(path, events);
    const sequential = await openWith(path, 0);
    const pooled = await openWith(path, 2);
    assert.deepEqual([sequential.outcome.detail.position, sequential.outcome.detail.code], [early, "TRANSITION_INVALID"]);
    assert.deepEqual(pooled.outcome, sequential.outcome);
    assert.equal(pooled.stats.discarded, 0);
  }
  // 2. The bad signature comes first: the speculation runs past it (optimistically) into the transition failure,
  //    finds the signature failed, discards everything and replays sequentially: the signature is reported.
  {
    let events = await build(COUNT, (i, event) => (i === late ? duplicate(i, event) : undefined));
    events[early] = corruptSignature(events[early]);
    events = await resign(events, early + 1);
    const path = join(dir, "signature-then-transition.jsonl");
    write(path, events);
    const sequential = await openWith(path, 0);
    const pooled = await openWith(path, 2);
    assert.deepEqual([sequential.outcome.detail.position, sequential.outcome.detail.code], [early, "CONTROL_AUTHORIZATION_INVALID"]);
    assert.deepEqual(pooled.outcome, sequential.outcome);
    assert.equal(pooled.stats.discarded, 1);
  }
});

test("speculative replay: a pool that stops answering is recovered by the calling thread, then retired", async (t) => {
  const path = join(workspace(t), "stalled.jsonl");
  write(path, await build(COUNT));
  const sequential = await openWith(path, 0);
  const stalled = await openWith(path, 2, { stalled: true, stallMs: 200 });
  assert.deepEqual(stalled.outcome, sequential.outcome);
  assert.equal(stalled.stats.runs, 1);
  assert.equal(stalled.stats.threads, 0, "the stalled pool is not used again");
  // A bad signature is still found with a stalled pool.
  const events = await build(COUNT);
  events[COUNT - 5] = corruptSignature(events[COUNT - 5]);
  const bad = join(workspace(t), "stalled-bad.jsonl");
  write(bad, await resign(events, COUNT - 4));
  const expected = await openWith(bad, 0);
  assert.deepEqual((await openWith(bad, 2, { stalled: true, stallMs: 200 })).outcome, expected.outcome);
});

test("IRONTRELLIS_VERIFY_THREADS sets the pool size (0 turns speculation off), capped at the CPU count; a process default below it", async () => {
  const saved = process.env.IRONTRELLIS_VERIFY_THREADS;
  try {
    await pv.setVerifyThreadsForTests(undefined);
    // Capped at the number of CPUs (review block 3, L3: more workers than CPUs only cost start-up time and memory).
    const cpus = availableParallelism();
    for (const [value, expected] of [["0", 0], ["1", 1], ["3", Math.min(3, cpus)], ["-1", 0], ["many", 0], ["99", Math.min(16, cpus)], [String(cpus + 1), Math.min(16, cpus)]]) {
      process.env.IRONTRELLIS_VERIFY_THREADS = value;
      assert.equal(pv.verifyThreads(), expected, value);
    }
    delete process.env.IRONTRELLIS_VERIFY_THREADS;
    assert.equal(pv.verifyThreads(), Math.max(0, Math.min(4, cpus - 1)));
    // A process's own default (the hook's): used only when the variable is not set, and capped at cores - 1.
    pv.setDefaultVerifyThreads(1);
    try {
      assert.equal(pv.verifyThreads(), Math.min(1, cpus - 1));
      pv.setDefaultVerifyThreads(64);
      assert.equal(pv.verifyThreads(), Math.max(0, cpus - 1));
      process.env.IRONTRELLIS_VERIFY_THREADS = "0";
      assert.equal(pv.verifyThreads(), 0, "the variable wins");
      assert.equal(pv.verifyThreadsConfigured(), true);
      delete process.env.IRONTRELLIS_VERIFY_THREADS;
      assert.equal(pv.verifyThreadsConfigured(), false);
      assert.throws(() => pv.setDefaultVerifyThreads(-1), RangeError);
      assert.throws(() => pv.setDefaultVerifyThreads(1.5), RangeError);
    } finally {
      pv.setDefaultVerifyThreads(undefined);
    }
    assert.equal(pv.verifyThreads(), Math.max(0, Math.min(4, cpus - 1)));
  } finally {
    if (saved === undefined) delete process.env.IRONTRELLIS_VERIFY_THREADS;
    else process.env.IRONTRELLIS_VERIFY_THREADS = saved;
  }
});

test("verify() on an open handle: unchanged bytes skip the re-parse; any change is re-parsed or replayed as before", async (t) => {
  const dir = workspace(t);
  const path = join(dir, "history.jsonl");
  const store = createHistoryStore(path, [genesis()], { signer, fsync: false });
  for (const event of (await build(40)).slice(1)) store.append(event);
  const reopened = openHistoryStore(path);
  assert.equal(reopened.verify().ok, true);
  // Same length, same last line, one byte changed in the middle: the digest differs, the re-parse finds the defect.
  const bytes = readFileSync(path);
  const at = bytes.indexOf(Buffer.from('"agentId":"agent:5"'));
  assert.ok(at > 0);
  const tampered = Buffer.from(bytes);
  tampered[at + 17] = "6".charCodeAt(0);
  writeFileSync(path, tampered);
  assert.throws(() => reopened.verify(), (error) => error.code === "INVALID_HISTORY" && /record integrity check failed/.test(error.message));
  writeFileSync(path, bytes);
  assert.equal(reopened.verify().ok, true, "the original bytes verify again");
  // After this handle writes (its own lines are encoded, not parsed), verify() re-parses as before.
  reopened.setSigner(signer);
  reopened.append(await signControlEvent(signer, agent(900), DOMAIN, reopened.head(), "sha256"));
  const report = reopened.verify();
  assert.equal(report.ok, true);
  assert.equal(report.eventCount, 41);
  // Another writer's append: the handle's cached size no longer matches; verify() replays the file.
  store.append(await signControlEvent(signer, agent(901), DOMAIN, store.head(), "sha256"));
  assert.equal(reopened.verify().eventCount, 42);
  store.close();
  reopened.close();
});

test("speculative replay: caller-supplied replay hooks never see a speculative run", async (t) => {
  const { defaultReplayHooks } = await import("../src/replay.ts");
  const path = join(workspace(t), "hooks.jsonl");
  write(path, await build(COUNT));
  await pv.setVerifyThreadsForTests(2);
  let calls = 0;
  const hooks = {
    validateIntentAdmissionTransition: (...args) => { calls += 1; return defaultReplayHooks.validateIntentAdmissionTransition(...args); },
    validateAdministrativeTransition: (...args) => { calls += 1; return defaultReplayHooks.validateAdministrativeTransition(...args); },
  };
  const store = openHistoryStore(path, { inspect: true, hooks });
  assert.equal(store.head().position, COUNT - 1);
  store.close();
  assert.equal(pv.speculationStats().runs, 0, "custom hooks: the replay is sequential");
  // The engine's own hooks (the default) do speculate.
  openHistoryStore(path, { inspect: true }).close();
  assert.equal(pv.speculationStats().runs, 1);
});

// ---------------------------------------------------------------- the verify() digest shortcut, adversarially
//
// verify() on an open handle may skip re-parsing only when the file's bytes are exactly the ones this process parsed
// (same length AND same SHA-256 of every byte). Nothing on disk feeds that decision: there is no cache file to tamper
// with (docs/history/PERFORMANCE-2026-09-26.md §5 explains why no persistent verification cache exists), and neither size nor mtime nor
// inode is trusted. Each case below must give the verdict a fresh open gives on the same bytes.

const { utimesSync, statSync: statOf, renameSync, truncateSync, appendFileSync } = await import("node:fs");

async function openedHistory(t, count = 40) {
  const dir = workspace(t);
  const path = join(dir, "history.jsonl");
  const writer = createHistoryStore(path, [genesis()], { signer, fsync: false });
  for (const event of (await build(count)).slice(1)) writer.append(event);
  writer.close();
  utimesSync(path, FIXED_TIME, FIXED_TIME); // a whole-second mtime a swap can restore exactly
  const reader = openHistoryStore(path);
  assert.equal(reader.verify().ok, true);
  return { dir, path, reader, bytes: readFileSync(path) };
}
const FIXED_TIME = new Date(1_700_000_000_000);
/** Replaces the file's content keeping its size, mode and timestamps (a same-size, same-mtime swap). */
function swapKeepingStat(path, content, { viaRename = false } = {}) {
  const before = statOf(path);
  assert.equal(content.length, before.size, "the swapped content has the same size");
  if (viaRename) {
    writeFileSync(`${path}.swap`, content);
    renameSync(`${path}.swap`, path);
  } else writeFileSync(path, content);
  utimesSync(path, FIXED_TIME, FIXED_TIME);
  const after = statOf(path);
  assert.equal(after.size, before.size);
  assert.equal(after.mtimeMs, before.mtimeMs, "same mtime");
}
const fresh = (path) => { try { const s = openHistoryStore(path, { inspect: true }); const r = s.verify(); s.close(); return r.ok; } catch (error) { return error.code; } };

test("verify() digest shortcut: a same-size, same-mtime byte edit is found (in place and by rename)", async (t) => {
  for (const viaRename of [false, true]) {
    const { path, reader, bytes } = await openedHistory(t);
    const at = bytes.indexOf(Buffer.from('"agentId":"agent:7"'));
    assert.ok(at > 0);
    const tampered = Buffer.from(bytes);
    tampered[at + 17] = "8".charCodeAt(0); // agent:7 → agent:8: a duplicate agent, the record hash no longer matches
    swapKeepingStat(path, tampered, { viaRename });
    assert.equal(fresh(path), "INVALID_HISTORY");
    assert.throws(() => reader.verify(), (error) => error.code === "INVALID_HISTORY", `viaRename=${viaRename}`);
    swapKeepingStat(path, bytes, { viaRename });
    assert.equal(reader.verify().ok, true, "the original bytes verify again");
    reader.close();
  }
});

test("verify() digest shortcut: a same-size swap to another, fully valid history is verified as that history", async (t) => {
  // Two histories with identical sizes: same events, different owner-signed content of equal length (agent:10 vs agent:11).
  const { path, reader, bytes } = await openedHistory(t);
  const events = await build(40);
  const other = events.map((event) => (event.type === "AGENT_CREATED" && event.data.agentId === "agent:10" ? agent(10, "agent:99") : event));
  const otherPath = join(workspace(t), "other.jsonl");
  const writer = createHistoryStore(otherPath, [genesis()], { signer, fsync: false });
  for (const event of (await resign(other, 1)).slice(1)) writer.append(event);
  writer.close();
  const otherBytes = readFileSync(otherPath);
  assert.equal(otherBytes.length, bytes.length);
  assert.notDeepEqual(otherBytes, bytes);
  // The swap keeps this file's pin: the pinned head is not in the swapped file, so it is a rollback/replacement.
  swapKeepingStat(path, otherBytes, { viaRename: true });
  // The handle sees a file whose pinned head it does not contain: a rollback, never the cached verdict.
  const report = reader.verify();
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((failure) => failure.startsWith("PIN_ROLLBACK")), report.failures.join("; "));
  const swapped = openHistoryStore(otherPath, { inspect: true });
  assert.equal(report.head.hash, swapped.head().hash, "verify() reports the swapped file's own head, not the cached one");
  swapped.close();
  assert.equal(fresh(path), false, "a fresh (inspecting) open and verify refuses it too");
  reader.close();
});

test("verify() digest shortcut: a truncated or extended file is re-read, never vouched for", async (t) => {
  {
    // Truncated to a line boundary: the pin names a head the file lacks.
    const { path, reader, bytes } = await openedHistory(t);
    const cut = bytes.lastIndexOf(10, bytes.length - 2) + 1;
    truncateSync(path, cut);
    const report = reader.verify();
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((failure) => failure.startsWith("PIN_ROLLBACK")), report.failures.join("; "));
    // Truncated mid-line: an incomplete record.
    truncateSync(path, cut - 5);
    assert.throws(() => reader.verify(), (error) => error.code === "INVALID_HISTORY");
    reader.close();
  }
  {
    // Extended by a garbage line, then by a valid-looking line that does not chain.
    const { path, reader, bytes } = await openedHistory(t);
    appendFileSync(path, "{}\n");
    assert.throws(() => reader.verify(), (error) => error.code === "INVALID_HISTORY");
    writeFileSync(path, Buffer.concat([bytes, bytes.subarray(bytes.lastIndexOf(10, bytes.length - 2) + 1)]));
    assert.throws(() => reader.verify(), (error) => error.code === "INVALID_HISTORY" && /chain/.test(error.message));
    writeFileSync(path, bytes);
    assert.equal(reader.verify().ok, true);
    reader.close();
  }
});

test("verify() digest shortcut: verify() after this handle refreshed another writer's tail still checks every byte", async (t) => {
  const { path, reader } = await openedHistory(t);
  const writer = openHistoryStore(path, { signer, fsync: false });
  writer.append(await signControlEvent(signer, agent(700), DOMAIN, writer.head(), "sha256"));
  writer.close();
  utimesSync(path, FIXED_TIME, FIXED_TIME);
  // The reader picks the tail up (its digest now covers the tail bytes it parsed) ...
  assert.equal(reader.head().position, 40);
  assert.equal(reader.verify().ok, true);
  // ... and an edit inside the earlier, already-verified part is still caught.
  const bytes = readFileSync(path);
  const at = bytes.indexOf(Buffer.from('"agentId":"agent:3"'));
  const tampered = Buffer.from(bytes);
  tampered[at + 17] = "4".charCodeAt(0);
  swapKeepingStat(path, tampered);
  assert.throws(() => reader.verify(), (error) => error.code === "INVALID_HISTORY");
  reader.close();
});
