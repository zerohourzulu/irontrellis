// History store tests: legacy byte-compatibility with the reference
// PortableFileEventStore (both directions), format-1 create/open/append/CAS,
// locking with stale-lock recovery, incremental tail reads after external
// appends, rollback detection against the pinned head, tamper detection,
// verify() reports, and append latency.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, truncateSync, utimesSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

import { referenceCore as core, referenceCore02, fixturePath, DEMO_CASE } from "./reference.mjs";
import { bestOf, loadFactor } from "./helpers/timing.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling
const { PortableFileEventStore, PortableStoreConflictError } = await referenceCore02("indexer/portable-file-event-store.ts");
const { openHistoryStore: openHistoryStoreStrict, createHistoryStore: createHistoryStoreStrict, PINNED_HEAD_VERSION } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const createHistoryStore = (path, events, options = {}) => createHistoryStoreStrict(path, events, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { signerFromKeyPair, signControlEvent, verifyHeadAttestation } = await import("../src/signer.ts");
const { StoreConflictError } = await import("../src/coordinators.ts");
const { replay } = await import("../src/replay.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const suites = await import("../src/crypto/suites.ts");

const revive = (_key, value) =>
  value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value;
const fixture = (name) => JSON.parse(readFileSync(fixturePath(name), "utf8"), revive);
const JSONL = [fixturePath("handover-history.jsonl"), fixturePath("original-core/cases/core02-packet-r1/history.jsonl"),
  `${DEMO_CASE}history.jsonl`];
const HISTORIES = ["handover-history.json", "handover-denied-history.json", "mandate-history.json",
  "original-core/cases/core02-packet-r1/export/history.json", "original-core/cases/core02-simulated-r1/export/history.json"];
/** Prototype- and key-order-insensitive view for deep equality (the reference hands out null-prototype records). */
const plain = (value) => {
  if (Array.isArray(value)) return value.map(plain);
  if (typeof value === "bigint") return `${value}n`;
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, plain(value[key])]));
  return value;
};
const workspace = (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-store-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const refHead = (history) => core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events: history }).head;
const lines = (path) => readFileSync(path, "utf8").split("\n").filter((line) => line !== "");
const code = (fn, expected) => {
  try { fn(); } catch (error) { assert.equal(error.code, expected, `${error.message}`); return error; }
  assert.fail(`expected ${expected}`);
};

// ---------------------------------------------------------------- legacy compatibility

test("legacy: every fixture JSONL reads identically to the reference store, with the reference head", () => {
  for (const path of JSONL) {
    const store = openHistoryStore(path);
    const reference = new PortableFileEventStore(path).readAll();
    assert.equal(store.format, "continuity-event/0.2");
    assert.deepEqual(plain(store.readAll()), plain(reference));
    assert.deepEqual(store.head(), refHead(reference));
    assert.equal(store.state().events.length, reference.length);
    const report = store.verify();
    assert.equal(report.pinnedHeadStatus, "UNPINNED");
    assert.equal(report.controlSignatures, "NOT_APPLICABLE");
    assert.equal(report.eventCount, reference.length);
  }
});

test("legacy: lines written by this store are byte-identical to the reference store's", (t) => {
  const dir = workspace(t);
  for (const name of HISTORIES) {
    const history = fixture(name);
    const mine = join(dir, `${name.replaceAll("/", "_")}.mine.jsonl`);
    const theirs = join(dir, `${name.replaceAll("/", "_")}.ref.jsonl`);
    const store = createHistoryStore(mine, [history[0]]);
    for (const event of history.slice(1)) store.append(event);
    const reference = new PortableFileEventStore(theirs);
    reference.appendAll(history);
    assert.equal(readFileSync(mine, "utf8"), readFileSync(theirs, "utf8"), name);
    assert.deepEqual(plain(new PortableFileEventStore(mine).readAll()), plain(history));
    assert.deepEqual(store.head(), refHead(history));
    if (process.platform !== "win32") assert.equal((statSync(mine).mode & 0o777), 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
    // Reference-written file: append through this store, the reference reads every line back.
    const opened = openHistoryStore(theirs);
    assert.deepEqual(opened.head(), refHead(history));
  }
  // Batch append through this store equals the same batch through the reference.
  const history = fixture("mandate-history.json");
  const batchMine = join(dir, "batch.mine.jsonl"), batchRef = join(dir, "batch.ref.jsonl");
  createHistoryStore(batchMine, history.slice(0, 2)).appendAll(history.slice(2));
  new PortableFileEventStore(batchRef).appendAll(history);
  assert.equal(readFileSync(batchMine, "utf8"), readFileSync(batchRef, "utf8"));
});

test("legacy: interleaved writers — this store and the reference store append to one file in turns", (t) => {
  const dir = workspace(t);
  const history = fixture("handover-history.json");
  const path = join(dir, "shared.jsonl");
  const reference = new PortableFileEventStore(path);
  reference.appendAll(history.slice(0, 3));
  const store = openHistoryStore(path);
  assert.equal(store.head().position, 2);
  const sameState = store.state();
  for (let index = 3; index < history.length; index += 1) {
    if (index % 2 === 0) reference.append(history[index]);
    else store.append(history[index]);
    assert.equal(store.head().position, index);
    assert.equal(store.state(), sameState, "external appends are absorbed incrementally, not by reloading");
  }
  assert.deepEqual(plain(reference.readAll()), plain(history));
  assert.deepEqual(plain(store.readAll()), plain(history));
  const expected = join(dir, "expected.jsonl");
  new PortableFileEventStore(expected).appendAll(history);
  assert.equal(readFileSync(path, "utf8"), readFileSync(expected, "utf8"));
  // The pinned head written by this store is at the last append it made, and the file is ahead of it.
  const report = store.verify();
  assert.equal(report.pinnedHeadStatus, (history.length - 1) % 2 === 1 ? "MATCHES" : "AHEAD");
  assert.equal(report.chain, "OK");
});

test("legacy: rejected appends throw the replay code and leave the file and state untouched", (t) => {
  const dir = workspace(t);
  const history = fixture("handover-history.json");
  const path = join(dir, "reject.jsonl");
  const store = createHistoryStore(path, history.slice(0, 4));
  const before = readFileSync(path, "utf8");
  code(() => store.append(history[1]), "EVENT_ID_DUPLICATE");
  code(() => store.appendAll([history[4], history[4]]), "EVENT_ID_DUPLICATE");
  assert.equal(readFileSync(path, "utf8"), before);
  assert.equal(store.head().position, 3);
  code(() => createHistoryStore(path, history.slice(0, 1)), "HISTORY_EXISTS");
  code(() => createHistoryStore(join(dir, "nogenesis.jsonl"), [history[1]]), "GENESIS_REQUIRED");
  assert.equal(statSync(join(dir, "nogenesis.jsonl"), { throwIfNoEntry: false }), undefined, "a failed create leaves no empty file");
});

// ---------------------------------------------------------------- format 1 scaffolding

const TRELLIS = "irontrellis-event/1";
const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: "deployment:store-test" });
const owner = suites.generateKeyPair("ed25519", "owner:store");
const signer = signerFromKeyPair(owner);
const genesisEvent = (keys = [owner]) => ({
  id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
  data: {
    domain: DOMAIN, versions: { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" },
    ownerKeys: keys.map((key) => ({ keyId: key.keyId, scheme: "ed25519", credential: key.credential })),
    adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:store", policyVersion: "policy:store/1",
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:store", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
    capacity: { maxEvents: null },
  },
});
/** Signs a control event over the store's current head. */
const signedFor = (store, raw, key = signer) => signControlEvent(key, raw, DOMAIN, store.head(), "sha256");
const agentEvent = (n, timestamp = n + 2) => ({ id: `agent:${n}`, type: "AGENT_CREATED", timestamp, data: { agentId: `agent:${n}`, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
const principalEvent = { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } };
/** A fresh format-1 history with `agents` agents; returns the store (opened with the signer). */
const trellisStore = async (path, agents, options = {}) => {
  const store = createHistoryStore(path, [genesisEvent()], { signer, ...options });
  store.append(await signedFor(store, principalEvent));
  for (let n = 0; n < agents; n += 1) store.append(await signedFor(store, agentEvent(n)));
  return store;
};

// ---------------------------------------------------------------- format 1 behaviour

test("format 1: create, open, append, CAS conflict, pinned attested head, verify", async (t) => {
  const dir = workspace(t);
  const path = join(dir, "history.jsonl");
  const store = await trellisStore(path, 3);
  assert.equal(store.format, TRELLIS);
  assert.equal(store.head().position, 4);
  const written = lines(path);
  assert.equal(written.length, 5);
  for (const line of written) {
    const record = JSON.parse(line);
    assert.deepEqual(Object.keys(record), ["version", "previousHash", "event", "recordHash"]);
    assert.equal(record.version, "irontrellis-portable-file-store/1");
  }
  assert.equal(JSON.parse(written[0]).previousHash, null);
  assert.equal(JSON.parse(written[1]).previousHash, JSON.parse(written[0]).recordHash);
  // A fresh open replays to the same head and state; the plain replay agrees.
  const reopened = openHistoryStore(path);
  assert.deepEqual(reopened.head(), store.head());
  assert.deepEqual(plain(reopened.readAll()), plain(store.readAll()));
  const fresh = replay(reopened.readAll());
  assert.equal(fresh.status, "ACCEPTED");
  assert.deepEqual(fresh.head, store.head());
  // CAS: stale expected head conflicts and reports the observed head; the right head appends.
  const stale = reopened.head();
  const next = await signedFor(store, agentEvent(3));
  const head = store.appendAtExpectedHead(next, stale);
  assert.equal(head.position, 5);
  const conflict = code(() => reopened.appendAtExpectedHead(next, stale), "STORE_CONFLICT");
  assert.ok(conflict instanceof StoreConflictError);
  assert.deepEqual(conflict.observedHead, head);
  assert.equal(reopened.head().position, 5, "the second instance absorbed the first instance's append");
  // The pinned head carries a verified attestation (local signer signs synchronously).
  const pin = store.pinnedHead();
  assert.deepEqual({ hash: pin.hash, position: pin.position, canonicalTime: pin.canonicalTime }, head);
  assert.equal(pin.recordHash, JSON.parse(lines(path).at(-1)).recordHash);
  assert.equal(JSON.parse(readFileSync(`${path}.head`, "utf8")).version, PINNED_HEAD_VERSION);
  assert.equal(verifyHeadAttestation(pin.attestation, DOMAIN, store.state().genesis.ownerKeys, "sha256"), true);
  assert.equal(verifyHeadAttestation(pin.attestation, { ...DOMAIN, deploymentId: "other" }, store.state().genesis.ownerKeys, "sha256"), false);
  const report = store.verify();
  assert.equal(report.chain, "OK");
  assert.equal(report.pinnedHeadStatus, "MATCHES");
  assert.equal(report.pinnedAttestation, "VERIFIED");
  assert.equal(report.controlSignatures, "VERIFIED");
  assert.deepEqual(report.head, head);
  assert.equal(report.eventCount, 6);
  assert.deepEqual(report.anchors, []);
  // Empty CAS store: always a conflict without an observed head.
  const empty = openHistoryStore(join(dir, "empty.jsonl"));
  assert.equal(empty.format, undefined);
  assert.equal(empty.head(), undefined);
  assert.deepEqual(empty.readAll(), []);
  code(() => empty.state(), "HISTORY_EMPTY");
  assert.equal(code(() => empty.appendAtExpectedHead(genesisEvent(), stale), "STORE_CONFLICT").observedHead, undefined);
  assert.equal(empty.verify().pinnedHeadStatus, "UNPINNED");
});

test("format 1: bigint markers round-trip through the line format", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "amounts.jsonl"), 1);
  const grant = await signedFor(store, { id: "grant", type: "AUTHORITY_GRANTED", timestamp: 10, data: { grant: {
    kind: "PERMISSION", authorityId: "root:1", grantorId: "owner", granteeId: "agent:0", rootAuthorityId: "root:1", independent: true,
    constraints: { actions: ["pay"], resources: ["ledger"], quantitative: true, maxAmount: 2n ** 200n, maxCumulativeAmount: 2n ** 255n, maxDelegationDepth: 0, requiredIntersectionIds: [] } } } });
  store.append(grant);
  assert.match(lines(store.path).at(-1), /"maxAmount":\{"\$continuity\.bigint":"1606938044258990275541962092341162602522202993782792835301376"\}/);
  const reopened = openHistoryStore(store.path);
  assert.equal(reopened.state().authorities.get("root:1").grant.constraints.maxAmount, 2n ** 200n);
  assert.deepEqual(reopened.head(), store.head());
});

test("format 1: lines carry the event's keys in canonical order whatever the caller's order; any order still reads", async (t) => {
  const dir = workspace(t);
  const reverse = (value) => {
    if (Array.isArray(value)) return value.map(reverse);
    if (value !== null && typeof value === "object") return Object.fromEntries(Object.keys(value).reverse().map((key) => [key, reverse(value[key])]));
    return value;
  };
  const sortedStore = await trellisStore(join(dir, "sorted.jsonl"), 1);
  const reversedStore = await trellisStore(join(dir, "reversed.jsonl"), 1);
  const event = agentEvent(1);
  const flipped = { data: reverse(event.data), timestamp: event.timestamp, type: event.type, id: event.id };
  assert.deepEqual(Object.keys(flipped.data), ["initialControlEpoch", "controllerId", "principalId", "agentId"]);
  sortedStore.append(await signedFor(sortedStore, event));
  reversedStore.append(await signedFor(reversedStore, flipped));
  const line = lines(sortedStore.path).at(-1);
  assert.equal(lines(reversedStore.path).at(-1), line);
  // Every nested record of every line is in sorted order.
  const isSorted = (value) => {
    if (Array.isArray(value)) return value.every(isSorted);
    if (value === null || typeof value !== "object") return true;
    const keys = Object.keys(value);
    return keys.join("\0") === keys.slice().sort().join("\0") && keys.every((key) => isSorted(value[key]));
  };
  for (const text of lines(sortedStore.path)) assert.ok(isSorted(JSON.parse(text).event), text);
  assert.deepEqual(Object.keys(JSON.parse(line).event.data), ["agentId", "controlAuthorization", "controllerId", "initialControlEpoch", "principalId"]);
  // A line whose event keys are in another order (another writer, an older file) reads to the same head.
  const record = JSON.parse(line);
  const unsorted = `{"version":${JSON.stringify(record.version)},"previousHash":${JSON.stringify(record.previousHash)},"event":${JSON.stringify(reverse(record.event))},"recordHash":${JSON.stringify(record.recordHash)}}`;
  assert.notEqual(unsorted, line);
  writeFileSync(reversedStore.path, `${[...lines(reversedStore.path).slice(0, -1), unsorted].join("\n")}\n`);
  assert.deepEqual(openHistoryStore(reversedStore.path).head(), sortedStore.head());
  assert.equal(openHistoryStore(reversedStore.path).verify().chain, "OK");
});

test("verify(): a cached store reuses its replay and reports exactly what a full replay reports", async (t) => {
  const dir = workspace(t);
  // Format 1: `a` keeps its cache fresh by writing; `b` is left behind by `a`'s appends, so its verify replays the file.
  const a = await trellisStore(join(dir, "verify.jsonl"), 2);
  const b = openHistoryStore(a.path);
  for (let n = 2; n < 5; n += 1) a.append(await signedFor(a, agentEvent(n)));
  const cached = a.verify();
  const replayed = b.verify();
  assert.equal(cached.eventCount, 7);
  assert.equal(cached.pinnedHeadStatus, "MATCHES");
  assert.equal(cached.pinnedAttestation, "VERIFIED");
  assert.deepEqual(cached, replayed);
  assert.deepEqual(openHistoryStore(a.path).verify(), replayed);
  assert.deepEqual(a.verify(), cached, "repeatable");
  // Legacy: the same comparison.
  const history = fixture("handover-history.json");
  const legacy = createHistoryStore(join(dir, "legacy.jsonl"), history.slice(0, 3));
  const behind = openHistoryStore(legacy.path);
  legacy.appendAll(history.slice(3));
  assert.deepEqual(legacy.verify(), behind.verify());
  assert.equal(legacy.verify().eventCount, history.length);
  // A same-size edit keeps size and last line but not the record hashes: the cached store still reports the tamper.
  const original = readFileSync(a.path, "utf8");
  const edited = original.replace('"agentId":"agent:1"', '"agentId":"agent:7"');
  assert.equal(edited.length, original.length);
  writeFileSync(a.path, edited);
  code(() => a.verify(), "INVALID_HISTORY");
  writeFileSync(a.path, original);
  assert.deepEqual(a.verify(), cached);
});

test("format 1: an asynchronous-only signer attests the pin after the append; flush() waits for it", async (t) => {
  const dir = workspace(t);
  const kms = Object.freeze({ keyId: owner.keyId, scheme: owner.scheme, credential: owner.credential, signHash: suites.signHashWith(owner) });
  const store = createHistoryStore(join(dir, "kms.jsonl"), [genesisEvent()], { signer: kms });
  assert.equal(store.pinnedHead().attestation, undefined);
  await store.flush();
  const pin = store.pinnedHead();
  assert.equal(verifyHeadAttestation(pin.attestation, DOMAIN, store.state().genesis.ownerKeys, "sha256"), true);
  assert.equal(pin.attestation.head.position, 0);
  store.append(await signedFor(store, principalEvent));
  store.append(await signedFor(store, agentEvent(0)));
  await store.flush();
  assert.equal(store.pinnedHead().attestation.head.position, 2);
  assert.equal(store.verify().pinnedAttestation, "VERIFIED");
});

test("locking: busy, non-reentrant, released on error, async callbacks hold the lock", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "lock.jsonl"), 1);
  const lock = `${store.path}.writer-lock`;
  // Nested writers on the same store or another instance are busy.
  store.withExclusiveWriter((writer) => {
    const info = JSON.parse(readFileSync(lock, "utf8"));
    assert.equal(info.pid, process.pid);
    assert.equal(info.hostname, hostname());
    code(() => store.append(principalEvent), "STORE_BUSY");
    code(() => openHistoryStore(store.path).withExclusiveWriter(() => {}), "STORE_BUSY");
    assert.equal(writer.readAll().length, 3);
  });
  assert.equal(statSync(lock, { throwIfNoEntry: false }), undefined, "lock removed after the callback");
  // The writer capability expires with its callback; errors release the lock.
  let escaped;
  assert.throws(() => store.withExclusiveWriter((writer) => { escaped = writer; throw new Error("boom"); }), /boom/);
  assert.equal(statSync(lock, { throwIfNoEntry: false }), undefined);
  code(() => escaped.readAll(), "WRITER_EXPIRED");
  // A promise-returning callback keeps the lock until it settles.
  const done = store.withExclusiveWriter(async (writer) => {
    const head = store.head();
    const event = await signedFor(store, agentEvent(1));
    return writer.appendAtExpectedHead(event, head);
  });
  assert.ok(statSync(lock, { throwIfNoEntry: false }), "lock held while the async callback runs");
  code(() => store.append(principalEvent), "STORE_BUSY");
  assert.equal((await done).position, 3);
  assert.equal(statSync(lock, { throwIfNoEntry: false }), undefined);
});

test("locking: stale locks (dead pid on this host, older than 60 s) are reclaimed; live or foreign locks are not", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "stale.jsonl"), 0);
  const lock = `${store.path}.writer-lock`;
  const deadPid = spawnSync(process.execPath, ["-e", ""]).pid;
  const old = (Date.now() - 120_000) / 1000;
  const plant = (content, ageSeconds = old) => { writeFileSync(lock, content); utimesSync(lock, ageSeconds, ageSeconds); };
  // Dead pid, same host, old: reclaimed.
  plant(JSON.stringify({ pid: deadPid, hostname: hostname(), createdAt: Date.now() - 120_000 }));
  store.append(await signedFor(store, agentEvent(0)));
  assert.equal(store.head().position, 2);
  assert.equal(statSync(lock, { throwIfNoEntry: false }), undefined);
  // Dead pid but fresh: busy (the owner may still be starting up).
  plant(JSON.stringify({ pid: deadPid, hostname: hostname(), createdAt: Date.now() }), Date.now() / 1000);
  code(() => store.append(agentEvent(0)), "STORE_BUSY");
  // Live pid, old: busy. The error names the lock file and its holder.
  plant(JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: Date.now() - 120_000 }));
  const busy = code(() => store.append(agentEvent(0)), "STORE_BUSY");
  assert.equal(busy.detail.lockPath, lock);
  assert.equal(busy.detail.holder.pid, process.pid);
  assert.ok(busy.message.includes(lock), busy.message);
  // Another host: never reclaimed.
  plant(JSON.stringify({ pid: deadPid, hostname: `${hostname()}-elsewhere`, createdAt: Date.now() - 120_000 }));
  code(() => store.append(agentEvent(0)), "STORE_BUSY");
  // The reference SDK's empty lock file: busy while fresh, reclaimed once old. Garbage is named as such.
  plant("", Date.now() / 1000);
  code(() => store.append(agentEvent(0)), "STORE_BUSY");
  plant("garbage", Date.now() / 1000);
  const garbage = code(() => store.append(agentEvent(0)), "STORE_BUSY");
  assert.match(garbage.message, /unreadable lock content/);
  assert.equal(garbage.detail.lockPath, lock);
  plant("");
  store.append(await signedFor(store, agentEvent(1)));
  assert.equal(store.head().position, 3);
  assert.deepEqual(readdirSync(dir).filter((name) => name.includes(".stale-")), [], "a reclaim leaves no renamed lock behind");
});

test("locking: two processes reclaiming the same stale lock never both hold it", async (t) => {
  // Deterministic under load: rounds are driven by a file barrier (see lock-race-worker.mjs), and the winner holds the
  // lock until the other worker's attempt is over. What is asserted does not depend on scheduling:
  //   safety: never two holders (0 violations), even for a retry while the winner is inside; the winner's lock is still
  //   its own when it leaves; every live lock displaced by a reclaimer is put back; the planted stale lock is reclaimed
  //   exactly once per round;
  //   liveness: every round completes, with exactly one winner and one STORE_BUSY.
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "contended.jsonl"), 1);
  const rounds = 120, deadPid = spawnSync(process.execPath, ["-e", ""]).pid;
  const barrier = join(dir, "barrier");
  mkdirSync(barrier);
  const old = Date.now() - 120_000;
  writeFileSync(`${store.path}.writer-lock`, JSON.stringify({ pid: deadPid, hostname: hostname(), createdAt: old }));
  utimesSync(`${store.path}.writer-lock`, old / 1000, old / 1000);
  const run = (id) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL("./lock-race-worker.mjs", import.meta.url)), store.path, String(rounds), barrier, String(id), String(deadPid)], { stdio: ["ignore", "pipe", "inherit"] });
    let out = "";
    child.stdout.on("data", (chunk) => { out += chunk; });
    child.on("error", reject);
    child.on("exit", (status) => (status === 0 ? resolve(JSON.parse(out)) : reject(new Error(`worker ${id} exited ${status}`))));
  });
  const [a, b] = await Promise.all([run(0), run(1)]);
  const wins = [a, b].map((r) => [...r.outcomes].filter((o) => o === "W").length);
  t.diagnostic(`lock race: wins ${wins.join("/")}, live locks displaced ${a.displaced + b.displaced}, put back ${a.relinked + b.relinked}`);
  assert.equal(a.violations + b.violations, 0, "both workers were inside the writer lock at once");
  assert.equal(a.retryEntered + b.retryEntered, 0, "the loser's retry got in while the winner was inside");
  assert.equal(a.lockLost + b.lockLost, 0, "a winner's lock was moved, deleted or replaced while it was inside");
  assert.equal(a.relinked + b.relinked, a.displaced + b.displaced, "every displaced live lock was put back");
  assert.equal(a.outcomes.length, rounds);
  assert.equal(b.outcomes.length, rounds);
  for (let round = 0; round < rounds; round += 1) {
    assert.deepEqual([a.outcomes[round], b.outcomes[round]].sort(), ["B", "W"], `round ${round}: exactly one winner and one STORE_BUSY`);
    assert.equal(a.reclaims[round] + b.reclaims[round], 1, `round ${round}: the stale lock is reclaimed exactly once`);
  }
  assert.deepEqual(readdirSync(dir).filter((name) => name.includes(".stale-") || name.endsWith(".inside")), []);
  assert.equal(store.verify().ok, true);
});

test("locking: lockTimeoutMs waits for another writer's lock instead of failing at once", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "wait.jsonl"), 0);
  const lock = `${store.path}.writer-lock`;
  writeFileSync(lock, JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: Date.now() }));
  const releaser = spawn(process.execPath, ["-e", `setTimeout(() => require("node:fs").unlinkSync(${JSON.stringify(lock)}), 300)`], { stdio: "ignore" });
  const released = new Promise((resolve) => releaser.on("exit", resolve));
  const event = await signedFor(store, agentEvent(0));
  code(() => store.append(event), "STORE_BUSY");
  const patient = openHistoryStore(store.path, { signer, lockTimeoutMs: 10_000 });
  const started = performance.now();
  assert.equal(patient.append(event).position, 2);
  t.diagnostic(`waited ${(performance.now() - started).toFixed(0)} ms for the lock`);
  await released;
  // A lock that is never released still ends in STORE_BUSY, after the wait, naming the lock.
  writeFileSync(lock, JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: Date.now() }));
  const late = code(() => openHistoryStore(store.path, { lockTimeoutMs: 50 }).append(agentEvent(1)), "STORE_BUSY");
  assert.match(late.message, /after 50 ms/);
  assert.equal(late.detail.lockPath, lock);
  rmSync(lock);
});

test("external appends by another instance are detected and read incrementally; the pin reflects the last writer", async (t) => {
  const dir = workspace(t);
  const a = await trellisStore(join(dir, "shared.jsonl"), 2);
  const b = openHistoryStore(a.path, { signer });
  const stateA = a.state();
  for (let n = 2; n < 6; n += 1) b.append(await signedFor(b, agentEvent(n)));
  assert.equal(a.head().position, 7);
  assert.equal(a.state(), stateA, "instance A extended its live state from the tail");
  assert.equal(a.state().agents.size, 6);
  a.append(await signedFor(a, agentEvent(6)));
  assert.equal(b.head().position, 8);
  assert.deepEqual(a.pinnedHead().attestation.head, a.head());
  assert.equal(a.verify().pinnedHeadStatus, "MATCHES");
  assert.equal(b.verify().pinnedHeadStatus, "MATCHES");
});

test("race: an opener between another writer's append and its pin write never sees a spurious rollback", async (t) => {
  const dir = workspace(t);
  const a = await trellisStore(join(dir, "race.jsonl"), 1);
  const path = a.path;
  const pinBefore = readFileSync(`${path}.head`);
  const b = openHistoryStore(path, { signer });
  b.append(await signedFor(b, agentEvent(1)));
  const fileAfter = readFileSync(path);
  const pinAfter = readFileSync(`${path}.head`);
  // Writer has appended its line but not yet written its pin: the file is ahead of the pin (normal).
  writeFileSync(`${path}.head`, pinBefore);
  assert.equal(openHistoryStore(path).head().position, 3);
  assert.equal(openHistoryStore(path).verify().pinnedHeadStatus, "AHEAD");
  assert.equal(a.head().position, 3, "a cached instance absorbs the tail regardless of the pin");
  writeFileSync(`${path}.head`, pinAfter);
  assert.equal(openHistoryStore(path).verify().pinnedHeadStatus, "MATCHES");
  // The reordering the old code was exposed to: the reader observes the new pin but a file that has not
  // caught up yet. Another process appends the missing line while the opener is retrying.
  const full = fileAfter.toString("utf8").split("\n").filter(Boolean);
  writeFileSync(path, `${full.slice(0, -1).join("\n")}\n`);
  writeFileSync(join(dir, "tail.txt"), `${full.at(-1)}\n`);
  const child = spawn(process.execPath, ["-e", `setTimeout(() => require("node:fs").appendFileSync(${JSON.stringify(path)}, require("node:fs").readFileSync(${JSON.stringify(join(dir, "tail.txt"))})), 120)`], { stdio: "ignore" });
  const exited = new Promise((resolve) => child.on("exit", resolve));
  const started = performance.now();
  const opened = openHistoryStore(path, { retry: { attempts: 40, delayMs: 50 } });
  t.diagnostic(`race opener settled after ${(performance.now() - started).toFixed(0)} ms`);
  assert.equal(opened.head().position, 3);
  assert.equal(opened.verify().pinnedHeadStatus, "MATCHES");
  await exited;
  // Without a writer catching up, the same picture is a genuine rollback (after the bounded retry).
  writeFileSync(path, `${full.slice(0, -1).join("\n")}\n`);
  const error = code(() => openHistoryStore(path, { retry: { attempts: 3, delayMs: 5 } }), "ROLLBACK_DETECTED");
  assert.equal(error.detail.pinnedHead.position, 3);
  assert.equal(error.detail.observedHead.position, 2);
});

test("rollback: truncation is detected on open and at runtime; acceptRollback re-pins with provenance", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "rollback.jsonl"), 4);
  const path = store.path;
  const full = readFileSync(path, "utf8");
  const pinFile = readFileSync(`${path}.head`);
  const pinBefore = store.pinnedHead();
  // Drop the last two records (a valid prefix remains).
  const kept = lines(path).slice(0, -2);
  writeFileSync(path, `${kept.join("\n")}\n`);
  code(() => store.head(), "ROLLBACK_DETECTED");
  const error = code(() => openHistoryStore(path), "ROLLBACK_DETECTED");
  assert.equal(error.detail.pinnedHead.position, 5);
  assert.equal(error.detail.observedHead.position, 3);
  // Accepted without a signer: the re-pin cannot be attested (the old attestation covered a removed head), so the report says so.
  const report = openHistoryStore(path, { acceptRollback: true }).verify();
  assert.equal(report.pinnedHeadStatus, "MATCHES");
  assert.equal(report.pinnedAttestation, "MISSING");
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.startsWith("PIN_ATTESTATION_MISSING")));
  assert.equal(typeof report.rollbackAcceptedAt, "number");
  assert.equal(report.previousPin.position, pinBefore.position);
  assert.ok(report.notes.some((n) => n.startsWith("ROLLBACK_ACCEPTED") && n.includes(`position ${pinBefore.position}`)));
  // The unattested re-pin is what the operator accepted, but readers still refuse it until the owner attests it.
  assert.equal(code(() => openHistoryStore(path), "ROLLBACK_DETECTED").detail.reason, "PIN_UNATTESTED");
  const pin = openHistoryStore(path, { allowUnpinned: true }).pinnedHead();
  assert.equal(pin.position, 3);
  assert.equal(typeof pin.rollbackAcceptedAt, "number");
  assert.equal(pin.previousPin.position, pinBefore.position);
  assert.equal(pin.previousPin.recordHash, pinBefore.recordHash);
  assert.equal(pin.previousPin.previousPin, undefined);
  // Review block 3, N4: a previous pin of another shape is "no readable previous pin", never "position undefined".
  const accepted = readFileSync(`${path}.head`, "utf8");
  for (const previousPin of [[], {}, { position: "x" }, null]) {
    writeFileSync(`${path}.head`, JSON.stringify({ ...JSON.parse(accepted), previousPin }));
    const notes = openHistoryStore(path, { inspect: true }).verify().notes;
    const note = notes.find((n) => n.startsWith("ROLLBACK_ACCEPTED"));
    assert.ok(note?.includes("there was no readable previous pin") && !note.includes("undefined"), JSON.stringify(notes));
  }
  writeFileSync(`${path}.head`, accepted);
  // A fork: same length as the pin but a different record at the pinned position.
  writeFileSync(path, full);
  writeFileSync(`${path}.head`, pinFile);
  const forked = openHistoryStore(path);
  assert.equal(forked.head().position, 5);
  forked.append(await signedFor(forked, agentEvent(9)));
  const forkLines = lines(path);
  writeFileSync(path, `${forkLines.slice(0, -1).join("\n")}\n`);
  const alt = openHistoryStore(path, { acceptRollback: true });
  alt.append(await signedFor(alt, agentEvent(10)));
  assert.equal(alt.pinnedHead().rollbackAcceptedAt, undefined, "a later plain pin drops the acceptance note");
  // Empty file behind a pin: rollback; a stale pin alone blocks createHistoryStore until accepted.
  truncateSync(path, 0);
  code(() => openHistoryStore(path), "ROLLBACK_DETECTED");
  rmSync(path);
  code(() => createHistoryStore(path, [genesisEvent()]), "ROLLBACK_DETECTED");
  createHistoryStore(path, [genesisEvent()], { acceptRollback: true });
  assert.equal(openHistoryStore(path).verify().pinnedHeadStatus, "MATCHES");
  // A malformed pin file is refused until accepted, and labelled as what it is (not as removed events).
  const open = openHistoryStore(path);
  writeFileSync(`${path}.head`, "{not json");
  const malformed = code(() => openHistoryStore(path), "ROLLBACK_DETECTED");
  assert.equal(malformed.detail.reason, "PIN_MALFORMED");
  assert.match(malformed.message, /pinned head file is malformed/);
  assert.doesNotMatch(malformed.message, /removed/);
  const seen = open.verify();
  assert.equal(seen.pinnedHeadStatus, "MALFORMED");
  assert.equal(seen.ok, false);
  assert.deepEqual(seen.failures.filter((f) => f.startsWith("PIN_")), [`PIN_MALFORMED: pinned head file is malformed: ${path}.head`]);
  openHistoryStore(path, { acceptRollback: true });
  assert.equal(openHistoryStore(path).verify().pinnedHeadStatus, "MATCHES");
});

test("rollback: acceptRollback with a signer re-pins WITH an attestation; verify() exposes rollbackAcceptedAt and the previous pin", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "accept.jsonl"), 4);
  const path = store.path;
  const pinBefore = store.pinnedHead();
  writeFileSync(path, `${lines(path).slice(0, -2).join("\n")}\n`);
  const accepted = openHistoryStore(path, { acceptRollback: true, signer });
  const report = accepted.verify();
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.pinnedHeadStatus, "MATCHES");
  assert.equal(report.pinnedAttestation, "VERIFIED");
  assert.deepEqual(report.attestedHead, report.head);
  assert.equal(typeof report.rollbackAcceptedAt, "number");
  assert.equal(report.previousPin.position, pinBefore.position);
  assert.deepEqual(report.previousPin.attestation, pinBefore.attestation, "the previous pin keeps its own attestation as evidence");
  // A later plain verify still shows the acceptance until the next write re-pins.
  assert.equal(openHistoryStore(path).verify().rollbackAcceptedAt, report.rollbackAcceptedAt);
  accepted.append(await signedFor(accepted, agentEvent(20)));
  const after = openHistoryStore(path).verify();
  assert.equal(after.rollbackAcceptedAt, undefined);
  assert.equal(after.pinnedAttestation, "VERIFIED");
});

test("B1: a deleted pin on a format-1 history is a rollback signal on open, a failure in verify(), and never silently re-pinned", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "nopin.jsonl"), 6);
  const path = store.path;
  // The review's reproduction: cut the tail (a revocation, say) and delete the pin.
  writeFileSync(path, `${lines(path).slice(0, -3).join("\n")}\n`);
  rmSync(`${path}.head`);
  const missing = code(() => openHistoryStore(path), "ROLLBACK_DETECTED");
  assert.equal(missing.detail.reason, "PIN_MISSING");
  assert.match(missing.message, /pin missing/);
  assert.equal(missing.detail.observedHead.position, 4);
  code(() => openHistoryStore(path, { signer }), "ROLLBACK_DETECTED");
  code(() => store.head(), "ROLLBACK_DETECTED");
  // Inspection reports it instead of throwing: ok false with a reason.
  const inspected = openHistoryStore(path, { inspect: true });
  const report = inspected.verify();
  assert.equal(report.pinnedHeadStatus, "MISSING");
  assert.equal(report.ok, false);
  assert.ok(report.failures[0].startsWith("PIN_MISSING: "), report.failures[0]);
  code(() => inspected.append(agentEvent(99)), "READ_UNAVAILABLE");
  // allowUnpinned: readable and verifiable (a note, not a failure), but a writer still refuses to re-pin it.
  const tolerant = openHistoryStore(path, { allowUnpinned: true, signer });
  assert.equal(tolerant.head().position, 4);
  const tolerated = tolerant.verify();
  assert.equal(tolerated.ok, true);
  assert.equal(tolerated.pinnedHeadStatus, "MISSING");
  assert.ok(tolerated.notes.some((n) => n.startsWith("PIN_MISSING")));
  assert.equal(tolerant.verify({ allowUnpinned: false }).ok, false);
  const refused = code(() => tolerant.append(agentEvent(99)), "ROLLBACK_DETECTED");
  assert.equal(refused.detail.reason, "PIN_MISSING");
  assert.equal(statSync(`${path}.head`, { throwIfNoEntry: false }), undefined, "no pin was written");
  // acceptRollback re-pins deliberately: attested (a signer is configured), with rollbackAcceptedAt and no previous pin.
  const accepted = openHistoryStore(path, { acceptRollback: true, signer }).verify();
  assert.equal(accepted.ok, true);
  assert.equal(accepted.pinnedHeadStatus, "MATCHES");
  assert.equal(accepted.pinnedAttestation, "VERIFIED");
  assert.equal(typeof accepted.rollbackAcceptedAt, "number");
  assert.equal(accepted.previousPin, undefined);
  // Genesis-only histories and empty files need no pin (a creation may crash before its first pin).
  const genesisOnly = createHistoryStore(join(dir, "genesis.jsonl"), [genesisEvent()], { signer });
  rmSync(`${genesisOnly.path}.head`);
  const young = openHistoryStore(genesisOnly.path).verify();
  assert.equal(young.pinnedHeadStatus, "UNPINNED");
  assert.equal(young.ok, true);
  // A long-lived instance whose pin disappears refuses its next write instead of re-pinning.
  const live = await trellisStore(join(dir, "live.jsonl"), 1);
  rmSync(`${live.path}.head`);
  const before = readFileSync(live.path);
  assert.equal(code(() => live.append(agentEvent(5)), "ROLLBACK_DETECTED").detail.reason, "PIN_MISSING");
  assert.deepEqual(readFileSync(live.path), before);
});

test("B1: a pin without an owner attestation, or with a foreign one, fails verification; writers without the key carry the last attestation", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "attest.jsonl"), 2);
  const path = store.path, headPath = `${path}.head`;
  const original = JSON.parse(readFileSync(headPath, "utf8"));
  // Stripped attestation.
  const { attestation, ...stripped } = original;
  writeFileSync(headPath, JSON.stringify(stripped));
  // Refused on open (R1): an unattested pin is not the owner's word. verify() (inspection) reports it as before.
  assert.equal(code(() => openHistoryStore(path), "ROLLBACK_DETECTED").detail.reason, "PIN_UNATTESTED");
  const report = openHistoryStore(path, { inspect: true }).verify();
  assert.equal(report.pinnedHeadStatus, "MATCHES");
  assert.equal(report.pinnedAttestation, "MISSING");
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.startsWith("PIN_ATTESTATION_MISSING")));
  assert.equal(openHistoryStore(path, { allowUnpinned: true }).verify().ok, true);
  // An attestation by a key the genesis does not declare, and one over another head of the file.
  const stranger = signerFromKeyPair(suites.generateKeyPair("ed25519", owner.keyId));
  const { attestHeadSync } = await import("../src/signer.ts");
  writeFileSync(headPath, JSON.stringify({ ...original, attestation: attestHeadSync(stranger, DOMAIN, store.head(), "sha256") }));
  assert.equal(code(() => openHistoryStore(path), "ROLLBACK_DETECTED").detail.reason, "PIN_ATTESTATION_INVALID");
  assert.equal(openHistoryStore(path, { inspect: true }).verify().pinnedAttestation, "INVALID");
  writeFileSync(headPath, JSON.stringify({ ...original, attestation: attestHeadSync(signer, DOMAIN, { ...store.head(), hash: `0x${"ab".repeat(32)}` }, "sha256") }));
  const notPrefix = code(() => openHistoryStore(path), "ROLLBACK_DETECTED");
  assert.equal(notPrefix.detail.reason, "PIN_ATTESTED_NOT_PREFIX");
  assert.equal(notPrefix.detail.attestedHead.hash, `0x${"ab".repeat(32)}`);
  const foreign = openHistoryStore(path, { inspect: true }).verify();
  assert.equal(foreign.pinnedAttestation, "INVALID");
  assert.ok(foreign.failures.some((f) => f.startsWith("PIN_ATTESTATION_INVALID")));
  writeFileSync(headPath, JSON.stringify(original));
  // A writer without the owner key (a runtime host) pins its head and carries the owner's attestation of the earlier head.
  const attested = store.head();
  const runtimeHost = openHistoryStore(path);
  runtimeHost.append(await signedFor(runtimeHost, agentEvent(7)));
  const pin = runtimeHost.pinnedHead();
  assert.equal(pin.position, attested.position + 1);
  assert.deepEqual(pin.attestation.head, attested);
  const carried = openHistoryStore(path).verify();
  assert.equal(carried.ok, true, carried.failures.join("; "));
  assert.equal(carried.pinnedAttestation, "VERIFIED");
  assert.deepEqual(carried.attestedHead, attested);
  assert.ok(carried.notes.some((n) => n.startsWith("PIN_ATTESTED_EARLIER")));
  // repin(): the owner attests the current head without writing an event.
  const repinned = openHistoryStore(path, { signer }).repin();
  assert.deepEqual(repinned.attestation.head, runtimeHost.head());
  assert.deepEqual(openHistoryStore(path).verify().attestedHead, runtimeHost.head());
  code(() => openHistoryStore(path).repin(), "KEY_UNAVAILABLE");
});

/** The review's R1 forgery: cut `drop` records and write a pin WITHOUT attestation at the new head; every field comes from the file. */
const forgeUnattestedPin = (path, drop, extra = {}) => {
  const kept = lines(path).slice(0, -drop);
  writeFileSync(path, `${kept.join("\n")}\n`);
  const head = openHistoryStore(path, { inspect: true }).head();
  writeFileSync(`${path}.head`, JSON.stringify({ version: PINNED_HEAD_VERSION, ...head, recordHash: JSON.parse(kept.at(-1)).recordHash, pinnedAt: 1, ...extra }));
  return head;
};

test("R1: an unattested pin at a truncated head is ROLLBACK_DETECTED (PIN_UNATTESTED) for every opener; no writer and no repin launders it", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "r1.jsonl"), 6);
  const path = store.path;
  const truncated = forgeUnattestedPin(path, 2);
  assert.equal(truncated.position, 5);
  for (const options of [{}, { signer }, { lockTimeoutMs: 10 }]) {
    const error = code(() => openHistoryStore(path, options), "ROLLBACK_DETECTED");
    assert.equal(error.detail.reason, "PIN_UNATTESTED");
    assert.equal(error.detail.pinnedHead.position, 5);
    assert.match(error.message, /carries no owner attestation/);
  }
  // The long-lived owner-keyed instance notices on its next read or write, and writes nothing.
  const pinText = readFileSync(`${path}.head`, "utf8"), fileText = readFileSync(path, "utf8");
  assert.equal(code(() => store.head(), "ROLLBACK_DETECTED").detail.reason, "PIN_UNATTESTED");
  assert.equal(code(() => store.append(agentEvent(40)), "ROLLBACK_DETECTED").detail.reason, "PIN_UNATTESTED");
  // allowUnpinned reads it; writes and repin refuse; nothing on disk changes.
  const tolerant = openHistoryStore(path, { allowUnpinned: true, signer });
  assert.equal(tolerant.head().position, 5);
  assert.equal(code(() => tolerant.append(agentEvent(41)), "ROLLBACK_DETECTED").detail.reason, "PIN_UNATTESTED");
  const refused = code(() => tolerant.repin(), "REPIN_REFUSED");
  assert.equal(refused.detail.reason, "PIN_UNATTESTED");
  assert.match(refused.message, /^repin refused: .*acceptRollback/);
  assert.equal(readFileSync(`${path}.head`, "utf8"), pinText);
  assert.equal(readFileSync(path, "utf8"), fileText);
  // verify() reports exactly what it reported before (inspection).
  const report = openHistoryStore(path, { inspect: true }).verify();
  assert.equal(report.pinnedAttestation, "MISSING");
  assert.ok(report.failures.some((f) => f.startsWith("PIN_ATTESTATION_MISSING")));
  // repin with acceptRollback re-pins deliberately: attested, recording the acceptance and the forged pin it replaced.
  const repinned = openHistoryStore(path, { allowUnpinned: true, signer }).repin({ acceptRollback: true });
  assert.deepEqual(repinned.attestation.head, truncated);
  assert.equal(typeof repinned.rollbackAcceptedAt, "number");
  assert.equal(repinned.previousPin.attestation, undefined);
  const after = openHistoryStore(path).verify();
  assert.equal(after.ok, true, after.failures.join("; "));
  assert.equal(after.pinnedAttestation, "VERIFIED");
  assert.ok(after.notes.some((n) => n.startsWith("ROLLBACK_ACCEPTED")));
  // A repin of a pin that already attests the head leaves it (and its record of the acceptance) as it is.
  assert.deepEqual(openHistoryStore(path, { signer }).repin(), repinned);
});

test("R1: acceptRollback on open re-pins a pin whose attestation is missing, invalid or not a prefix, attested by the signer", async (t) => {
  const dir = workspace(t);
  const { attestHeadSync } = await import("../src/signer.ts");
  const stranger = signerFromKeyPair(suites.generateKeyPair("ed25519", owner.keyId));
  const cases = [
    ["PIN_UNATTESTED", () => ({})],
    ["PIN_ATTESTATION_INVALID", (head) => ({ attestation: attestHeadSync(stranger, DOMAIN, head, "sha256") })],
    // The owner's genuine attestation of the removed head, copied onto a pin at the truncated head.
    ["PIN_ATTESTED_NOT_PREFIX", (_head, old) => ({ attestation: old.attestation })],
  ];
  for (const [reason, attestation] of cases) {
    const store = await trellisStore(join(dir, `${reason}.jsonl`), 4);
    const path = store.path, old = store.pinnedHead();
    const kept = lines(path).slice(0, -2);
    writeFileSync(path, `${kept.join("\n")}\n`);
    const head = openHistoryStore(path, { inspect: true }).head();
    writeFileSync(`${path}.head`, JSON.stringify({ version: PINNED_HEAD_VERSION, ...head, recordHash: JSON.parse(kept.at(-1)).recordHash, pinnedAt: 1, ...attestation(head, old) }));
    assert.equal(code(() => openHistoryStore(path), "ROLLBACK_DETECTED").detail.reason, reason);
    const accepted = openHistoryStore(path, { acceptRollback: true, signer }).verify();
    assert.equal(accepted.ok, true, `${reason}: ${accepted.failures.join("; ")}`);
    assert.equal(accepted.pinnedAttestation, "VERIFIED");
    assert.deepEqual(accepted.attestedHead, head);
    assert.equal(typeof accepted.rollbackAcceptedAt, "number");
    assert.equal(accepted.previousPin.position, head.position);
    assert.equal(openHistoryStore(path).head().position, head.position, `${reason}: readers accept the re-pinned file`);
  }
});

test("R1: a carried-forward attestation (writers without the key, a KMS signer before it answers) is accepted as PIN_ATTESTED_EARLIER", async (t) => {
  const dir = workspace(t);
  // A keyless writer (a runtime host) pins its head and carries the owner's attestation of the earlier head.
  const store = await trellisStore(join(dir, "carried.jsonl"), 2);
  const attested = store.head();
  const runtimeHost = openHistoryStore(store.path);
  runtimeHost.append(await signedFor(runtimeHost, agentEvent(7)));
  runtimeHost.append(await signedFor(runtimeHost, agentEvent(8)));
  assert.deepEqual(runtimeHost.pinnedHead().attestation.head, attested);
  const reader = openHistoryStore(store.path);
  assert.equal(reader.head().position, attested.position + 2);
  assert.ok(reader.verify().notes.some((n) => n.startsWith("PIN_ATTESTED_EARLIER")));
  // A keyless writer never carries a forged attestation forward: it pins without one, and readers then refuse.
  const stranger = signerFromKeyPair(suites.generateKeyPair("ed25519", owner.keyId));
  const { attestHeadSync } = await import("../src/signer.ts");
  const current = JSON.parse(readFileSync(`${store.path}.head`, "utf8"));
  writeFileSync(`${store.path}.head`, JSON.stringify({ ...current, attestation: attestHeadSync(stranger, DOMAIN, attested, "sha256") }));
  runtimeHost.append(await signedFor(runtimeHost, agentEvent(9)));
  assert.equal(runtimeHost.pinnedHead().attestation, undefined);
  assert.equal(code(() => openHistoryStore(store.path), "ROLLBACK_DETECTED").detail.reason, "PIN_UNATTESTED");
  // A KMS (async-only) signer: until it answers, the pin carries the previous attestation, which readers accept; once
  // it answers, the attestation of the newest head replaces it even if the pin has moved on meanwhile.
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const sign = suites.signHashWith(owner);
  const kms = Object.freeze({ keyId: owner.keyId, scheme: owner.scheme, credential: owner.credential, signHash: async (hash) => { await gate; return sign(hash); } });
  const slow = createHistoryStore(join(dir, "kms.jsonl"), [genesisEvent()], { signer: signer });
  slow.append(await signedFor(slow, principalEvent));
  const kmsStore = openHistoryStore(slow.path, { signer: kms });
  const before = kmsStore.head();
  kmsStore.append(await signedFor(kmsStore, agentEvent(0)));
  kmsStore.append(await signedFor(kmsStore, agentEvent(1)));
  assert.deepEqual(kmsStore.pinnedHead().attestation.head, before, "the previous attestation is carried while the KMS has not answered");
  const midway = openHistoryStore(slow.path);
  assert.equal(midway.head().position, before.position + 2);
  assert.ok(midway.verify().notes.some((n) => n.startsWith("PIN_ATTESTED_EARLIER")));
  release();
  await kmsStore.flush();
  assert.deepEqual(kmsStore.pinnedHead().attestation.head, kmsStore.head());
  assert.equal(openHistoryStore(slow.path).verify().ok, true);
});

test("tamper: a modified byte, a broken chain, a truncated line or an unsigned control event is INVALID_HISTORY", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "tamper.jsonl"), 2);
  const path = store.path;
  const original = readFileSync(path, "utf8");
  const expectInvalid = (text, label) => {
    writeFileSync(path, text);
    const opened = openHistoryStore(path);
    code(() => opened.state(), "INVALID_HISTORY");
    code(() => opened.head(), "INVALID_HISTORY");
    code(() => opened.verify(), "INVALID_HISTORY");
    code(() => opened.append(principalEvent), "INVALID_HISTORY");
    code(() => store.head(), "INVALID_HISTORY");
    assert.ok(label);
  };
  expectInvalid(original.replace('"agentId":"agent:1"', '"agentId":"agent:7"'), "edited byte");
  expectInvalid(original.slice(0, -10), "incomplete last record");
  const records = original.split("\n").filter(Boolean);
  const swapped = [records[0], records[2], records[1], records[3]];
  expectInvalid(`${swapped.join("\n")}\n`, "reordered records break the chain");
  const unsigned = records.map((line, index) => {
    if (index !== 2) return line;
    const record = JSON.parse(line);
    delete record.event.data.controlAuthorization;
    return JSON.stringify(record);
  });
  expectInvalid(`${unsigned.join("\n")}\n`, "record hash mismatch after stripping the signature");
  // Restore: the same instance recovers once the file is back.
  writeFileSync(path, original);
  assert.equal(store.head().position, 3);
  assert.equal(store.verify().chain, "OK");
  // Legacy: the reference store and this store reject the same tampered fixture.
  const legacy = join(dir, "legacy.jsonl");
  writeFileSync(legacy, readFileSync(JSONL[0], "utf8").replace('["timestamp",["number",1]]', '["timestamp",["number",2]]'));
  assert.throws(() => new PortableFileEventStore(legacy).readAll(), /integrity check failed/);
  code(() => openHistoryStore(legacy).state(), "INVALID_HISTORY");
});

test("legacy files written by the new engine get a pin from the first append and detect later truncation", (t) => {
  const dir = workspace(t);
  const history = fixture("handover-history.json");
  const path = join(dir, "legacy-pin.jsonl");
  new PortableFileEventStore(path).appendAll(history.slice(0, 5));
  const store = openHistoryStore(path);
  assert.equal(store.pinnedHead(), undefined);
  store.append(history[5]);
  assert.equal(store.pinnedHead().position, 5);
  assert.equal(store.pinnedHead().attestation, undefined, "legacy pins are unattested");
  writeFileSync(path, `${lines(path).slice(0, 4).join("\n")}\n`);
  code(() => openHistoryStore(path), "ROLLBACK_DETECTED");
});

test("write failures: an unopenable file is READ_UNAVAILABLE (nothing written); a failed pin write is WRITE_UNCONFIRMED", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "ro.jsonl"), 1);
  const next = await signedFor(store, agentEvent(1));
  // Make the history unwritable (mode for ordinary users, the immutable attribute for root), then restore it.
  const root = process.getuid?.() === 0;
  const freeze = (on) => (root ? spawnSync("chattr", [on ? "+i" : "-i", store.path]).status === 0 : (chmodSync(store.path, on ? 0o400 : 0o600), true));
  if (freeze(true)) {
    let failure;
    try {
      failure = code(() => store.append(next), "READ_UNAVAILABLE");
    } finally {
      freeze(false);
    }
    assert.equal(failure.detail.mayHaveCommitted, false, "open() failed: nothing can have been written");
    assert.match(failure.message, /nothing was written/);
    assert.equal(store.head().position, 2, "the batch applied to the live state was dropped by re-reading the file");
    store.append(await signedFor(store, agentEvent(1)));
  } else {
    t.diagnostic("cannot make the file unwritable here; skipping the append-failure branch");
    store.append(next);
  }
  // A pin that cannot be written is reported as unconfirmed, although the append itself committed.
  mkdirSync(`${store.path}.head.dir`);
  rmSync(`${store.path}.head`);
  renameSync(`${store.path}.head.dir`, `${store.path}.head`);
  const last = await signedFor(store, agentEvent(2));
  const pinFailure = code(() => store.append(last), "WRITE_UNCONFIRMED");
  assert.equal(pinFailure.detail.mayHaveCommitted, true);
  rmSync(`${store.path}.head`, { recursive: true });
  // The append is on disk, but the history has now lost its pin: that is a rollback signal, not a history to trust silently.
  assert.equal(code(() => openHistoryStore(store.path), "ROLLBACK_DETECTED").detail.reason, "PIN_MISSING");
  assert.equal(openHistoryStore(store.path, { allowUnpinned: true }).head().position, 4, "the unpinned append is on disk");
  // createHistoryStore refuses to open a file it cannot create for a reason other than EEXIST, before writing anything.
  code(() => createHistoryStore(join(dir, "missing-dir", "h.jsonl"), [genesisEvent()]), "READ_UNAVAILABLE");
});

// ---------------------------------------------------------------- performance

// The bound is loose on purpose (typical: 0.4–0.7 ms): CI and shared hosts are noisy, so it is scaled by the machine's
// current speed (helpers/timing.mjs) and the no-fsync round is retried once; an order-of-magnitude regression still fails.
test("performance: 2,000 format-1 appends average ≤ 3 ms each without fsync", async (t) => {
  const dir = workspace(t);
  let round = 0;
  const measure = async (fsync) => {
    const store = createHistoryStore(join(dir, `perf-${fsync}-${(round += 1)}.jsonl`), [genesisEvent()], { signer, fsync });
    store.append(await signedFor(store, principalEvent));
    let total = 0;
    for (let n = 0; n < 2000; n += 1) {
      const event = await signedFor(store, agentEvent(n));
      const started = performance.now();
      store.append(event);
      total += performance.now() - started;
    }
    assert.equal(store.head().position, 2001);
    return total / 2000;
  };
  const withoutFsync = await bestOf(2, () => measure(false));
  const withFsync = await measure(true);
  const factor = loadFactor();
  t.diagnostic(`append latency: ${withoutFsync.toFixed(3)} ms without fsync, ${withFsync.toFixed(3)} ms with fsync (load factor ${factor.toFixed(2)})`);
  assert.ok(withoutFsync <= 3 * factor, `average append ${withoutFsync.toFixed(3)} ms exceeds 3 ms × load factor ${factor.toFixed(2)}`);
  const opened = performance.now();
  const reopened = openHistoryStore(join(dir, "perf-false-1.jsonl"));
  assert.equal(reopened.head().position, 2001);
  t.diagnostic(`open + replay of 2,002 events: ${(performance.now() - opened).toFixed(1)} ms`);
});

test("acceptRollback with an unreadable anchor log is refused before the pin is rewritten", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "rollback-unreadable.jsonl"), 4);
  const path = store.path;
  writeFileSync(path, `${lines(path).slice(0, -2).join("\n")}\n`); // behind the pin
  writeFileSync(`${path}.anchors`, "not json\n", { mode: 0o600 });
  const pinBytes = readFileSync(`${path}.head`);
  assert.throws(() => openHistoryStore(path, { acceptRollback: true }), (e) => e.code === "ANCHOR_LOG_UNREADABLE");
  assert.deepEqual(readFileSync(`${path}.head`), pinBytes, "the pin is unchanged");
  // As verify opens (allowUnpinned): the open succeeds, nothing is re-pinned, verify() reports the unreadable log, writes refuse.
  const verifying = openHistoryStore(path, { acceptRollback: true, allowUnpinned: true });
  assert.deepEqual(readFileSync(`${path}.head`), pinBytes, "the pin is unchanged");
  assert.equal(verifying.verify().anchorLogStatus, "UNREADABLE");
});


test("a programmatic Signer's bad pin attestation is refused (SIGNER_FAILED) and the pin keeps its earlier one; the next open is clean", async (t) => {
  const dir = workspace(t);
  const { createLocalOwner, openLocalOwner, createLocalDomain } = await import("../src/owner.ts");
  const { signerFromKeyPair } = await import("../src/signer.ts");
  const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
  const real = signerFromKeyPair(keyPairFromPrivateKey("ed25519", "owner:1", `0x${"42".repeat(32)}`));
  let bad = false;
  // No signHashSync: the store attests the pin asynchronously, the path a programmatic signer takes.
  const signer = { keyId: real.keyId, scheme: real.scheme, credential: real.credential,
    signHash: async (hash, context) => (bad && context?.purpose === "head-attestation" ? `0x${"00".repeat(64)}` : real.signHash(hash, context)) };
  const historyFile = join(dir, "custom-signer.jsonl"), domain = createLocalDomain();
  const options = { historyFile, domain, owner: "owner", controller: "controller", now: () => Date.now(), signer };
  const owner = await createLocalOwner(options);
  await owner.createAgent({ id: "agent:a" });
  await owner.flush();
  const pinBefore = readFileSync(`${historyFile}.head`, "utf8");
  bad = true;
  await owner.createAgent({ id: "agent:b" });
  await assert.rejects(owner.flush(), (e) => e.code === "SIGNER_FAILED" && e.detail?.reason === "ATTESTATION_INVALID");
  assert.equal(JSON.parse(readFileSync(`${historyFile}.head`, "utf8")).attestation.signature, JSON.parse(pinBefore).attestation.signature, "the earlier attestation is kept");
  bad = false;
  const reopened = await openLocalOwner(options); // before PIN_ATTESTATION_INVALID (a false tamper alarm)
  await reopened.createAgent({ id: "agent:c" });
  await reopened.flush();
});

test("repin with acceptRollback on a truncated format-2 history with an unreadable anchor log is REPIN_REFUSED, the pin unchanged (Astra's reproducer)", async (t) => {
  const dir = workspace(t);
  const { createLocalOwner, createLocalDomain, verifyHistory: verifyFormat2 } = await import("../src/owner.ts");
  const { signerFromKeyPair } = await import("../src/signer.ts");
  const { generateKeyPair } = await import("../src/crypto/suites.ts");
  const path = join(dir, "history.jsonl"), signer = signerFromKeyPair(generateKeyPair("ed25519", "owner:repin"));
  const owner = await createLocalOwner({ historyFile: path, domain: createLocalDomain(), owner: "owner", controller: "controller", now: () => Date.now(), signer, witness: false });
  await owner.createAgent({ id: "agent:a" }); await owner.createAgent({ id: "agent:b" }); await owner.flush();
  writeFileSync(path, `${readFileSync(path, "utf8").trimEnd().split("\n").slice(0, -1).join("\n")}\n`); // behind the pin
  writeFileSync(`${path}.anchors`, "{not json\n");
  const before = readFileSync(`${path}.head`);
  const store = openHistoryStore(path, { acceptRollback: true, allowUnpinned: true, signer, witness: false });
  assert.equal(store.format, "irontrellis-event/2");
  assert.equal(verifyFormat2(path, { acceptRollback: true, signer, witness: false }).anchorLogStatus, "UNREADABLE");
  assert.throws(() => store.repin({ acceptRollback: true }), (e) => e.code === "REPIN_REFUSED" && e.detail?.reason === "ANCHOR_LOG_UNREADABLE");
  store.close();
  assert.deepEqual(readFileSync(`${path}.head`), before, "the pin is unchanged");
});
