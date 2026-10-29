// Key events on the witness (WITNESS-DESIGN §11.3, §11.4), in process on an ephemeral port: POST …/key-events with a
// commitment-only rotation and a pre-rotated rotation (each with the statement for its head), epochs that carry the
// commitment, a genesis commitment known from the registration, the SUPERSEDED entry of a leaked old key's heads (409 SUPERSEDED afterwards, the supersede count in the
// history summary and the version-2 latest note), the admin route and the offline import (same checks, the server lock),
// the replay at start-up and check-log. Every receipt is verified and every checkpoint checked for consistency.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ADMIN_TOKEN, buildKeyEventHistory, core, silentLogger, startWitness, t, tempDir, TestClient, witnessLib } from "./helpers.mjs";

const { checkLog, importKeyEvents, loadConfig, loadWitnessKey } = witnessLib;
const NONCE = Buffer.alloc(32, 7).toString("base64url");

const bundleOf = async (k, position, extra = {}) => ({
  version: "irontrellis-key-event-bundle/1", historyId: k.historyId, ...k.keyEvent(position === k.rotateAt ? k.rotation : k.commitment, position),
  statement: await k.statement(position, position - 1), ...extra,
});

test("key-events: a commitment-only rotation and a pre-rotated rotation, each delivered with the statement for its head; epochs carry the commitment", async () => {
  const { dir, cleanup } = tempDir();
  const handle = await startWitness({ dir });
  const client = new TestClient(handle.url, handle.witness.verifierKey);
  try {
    const k = await buildKeyEventHistory({ name: "ke-http" });
    const id = k.historyId;
    await client.register(k.genesis);
    await client.post(`/v1/histories/${id}/heads`, await k.statement(k.commitAt - 1, null));
    // The commitment-only rotation with the statement for its head in the same request: HEAD c, then ROTATED.
    const committed = await client.post(`/v1/histories/${id}/key-events?nonce=${NONCE}`, k.keyEvent(k.commitment, k.commitAt, { statement: await k.statement(k.commitAt, k.commitAt - 1) }));
    assert.equal(committed.status, 201, committed.text);
    assert.equal(committed.json.receipt.entry.kind, "ROTATED");
    assert.deepEqual(committed.json.latest.head, k.heads[k.commitAt]);
    assert.deepEqual(committed.json.epochs[1].nextKeyDigests, [k.commitment.data.nextKeyDigests[0]]);
    const note = t.verifyLatestNote(committed.json.latestNote, [handle.witness.verifierKey], { historyId: id, nonce: NONCE });
    assert.equal(note.ok, true);
    assert.equal(note.latest.supersedes, 0);
    // Idempotent.
    assert.equal((await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.commitment, k.commitAt))).status, 200);
    const summary = await client.get(`/v1/histories/${id}`);
    assert.deepEqual(summary.json.epochs, [
      { fromPosition: 0, keys: [k.genesis.data.ownerKeys[0]] },
      { fromPosition: k.commitAt + 1, keys: [k.genesis.data.ownerKeys[0]], nextKeyDigests: k.commitment.data.nextKeyDigests },
    ]);
    assert.equal(summary.json.supersedes, 0);
    // A rotation that does not reveal the committed key (a thief of the current key): KEY_EVENT_INVALID.
    await client.post(`/v1/histories/${id}/heads`, await k.statement(k.rotateAt - 1, k.commitAt));
    const thief = await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.plainRotation, k.rotateAt, { statement: await k.statement(k.rotateAt, k.rotateAt - 1) }));
    assert.equal(thief.status, 400);
    assert.equal(thief.json.error.code, "KEY_EVENT_INVALID");
    assert.match(thief.json.error.message, /pre-rotation|committed/);
    // Without its head: KEY_EVENT_HEAD_UNKNOWN; a statement that does not extend the latest: 409 STALE_PREVIOUS with latest.
    assert.equal((await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.rotation, k.rotateAt))).json.error.code, "KEY_EVENT_HEAD_UNKNOWN");
    const stale = await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.rotation, k.rotateAt, { statement: await k.statement(k.rotateAt, 1) }));
    assert.deepEqual([stale.status, stale.json.error.code, stale.json.latest.head.position], [409, "STALE_PREVIOUS", k.rotateAt - 1]);
    const rotated = await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.rotation, k.rotateAt, { statement: await k.statement(k.rotateAt, k.rotateAt - 1) }));
    assert.equal(rotated.status, 201, rotated.text);
    assert.deepEqual(rotated.json.epochs.map((epoch) => epoch.fromPosition), [0, k.commitAt + 1, k.rotateAt + 1]);
    assert.ok(rotated.json.epochs[2].nextKeyDigests.length === 1, "the new epoch's commitment");
    // Idempotent: the same key event again gets the recorded receipt.
    const again = await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.rotation, k.rotateAt));
    assert.deepEqual([again.status, again.json.receipt.index], [200, rotated.json.receipt.index]);
    const report = checkLog(dir, { verifierKey: handle.witness.verifierKey, origin: handle.witness.origin });
    assert.equal(report.ok, true, JSON.stringify(report.problems));
    assert.deepEqual(Object.keys(report.kinds).sort(), ["EQUIVOCATION", "HEAD", "REGISTERED", "ROTATED", "SUPERSEDED"]);
    assert.equal(report.kinds.ROTATED, 2);
  } finally {
    await handle.close();
    cleanup();
  }
});

test("a genesis commitment is known from the registration alone: a rotation that does not reveal the committed key is refused, the pre-rotated one accepted, and OWNER_NEXT_KEYS_COMMITTED is not a key event", async () => {
  const { dir, cleanup } = tempDir();
  const handle = await startWitness({ dir });
  const client = new TestClient(handle.url, handle.witness.verifierKey);
  try {
    const k = await buildKeyEventHistory({ name: "ke-genesis" });
    // The same owner keys, with the commitment moved into the genesis (a fresh history: every control event re-signed).
    const genesis = { ...k.genesis, data: { ...k.genesis.data, nextKeyDigests: k.commitment.data.nextKeyDigests } };
    const hasher = new core.HistoryHasher("irontrellis-event/1");
    const events = [genesis];
    const heads = [{ hash: hasher.push(genesis), position: 0, canonicalTime: 0 }];
    const control = async (event, signer) => {
      const signed = await core.signControlEvent(signer, event, k.domain, heads.at(-1), "sha256");
      events.push(signed);
      heads.push({ hash: hasher.push(signed), position: events.length - 1, canonicalTime: signed.timestamp });
      return signed;
    };
    await control({ id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }, k.signer1);
    const historyId = heads[0].hash;
    const statement = (p, q, signer = k.signer1) => t.signHeadStatement(signer, { version: t.HEAD_STATEMENT_VERSION, historyId, domain: k.domain, head: heads[p], previous: q === null ? null : { hash: heads[q].hash, position: q } });
    const registered = await client.register(genesis);
    assert.ok(registered.status === 201, registered.text);
    const info = await client.get(`/v1/histories/${historyId}`);
    assert.deepEqual(info.json.epochs, [{ fromPosition: 0, keys: genesis.data.ownerKeys, nextKeyDigests: genesis.data.nextKeyDigests }], "epoch 0's commitment from the genesis");
    await client.post(`/v1/histories/${historyId}/heads`, await statement(1, null));
    // A thief of key 1 rotating to its own key: refused (the rotation reveals no committed key).
    const at = heads.at(-1);
    const thief = await core.signControlEvent(k.signer1, { id: "rotation:thief", type: "OWNER_KEYS_ROTATED", timestamp: 2, data: { ownerKeys: [k.plainRotation.data.ownerKeys[0]] } }, k.domain, at, "sha256");
    const thiefHead = { hash: hasher.clone().push(thief), position: 2 };
    const refused = await client.post(`/v1/histories/${historyId}/key-events`, { event: thief, previousHead: { hash: at.hash, position: 1 }, eventHead: thiefHead });
    assert.deepEqual([refused.status, refused.json.error.code], [400, "KEY_EVENT_INVALID"]);
    assert.match(refused.json.error.message, /committed/);
    // An OWNER_NEXT_KEYS_COMMITTED event is no key event (the type does not exist).
    const legacyShaped = { id: "commit:1", type: "OWNER_NEXT_KEYS_COMMITTED", timestamp: 2, data: { nextKeyDigests: k.commitment.data.nextKeyDigests } };
    const notAKeyEvent = await client.post(`/v1/histories/${historyId}/key-events`, { event: legacyShaped, previousHead: { hash: at.hash, position: 1 }, eventHead: thiefHead });
    assert.deepEqual([notAKeyEvent.status, notAKeyEvent.json.error.code], [400, "KEY_EVENT_INVALID"]);
  } finally {
    await handle.close();
    cleanup();
  }
});

test("supersede (§11.4): the owner's pre-rotated rotation overrides the thief's heads after L; 409 SUPERSEDED; counted in the summary and the latest note; replayed at start; check-log VALID, tampering found", async () => {
  const { dir, cleanup } = tempDir();
  let handle = await startWitness({ dir });
  let client = new TestClient(handle.url, handle.witness.verifierKey);
  try {
    const k = await buildKeyEventHistory({ name: "ke-sup" });
    const id = k.historyId, r = k.rotateAt;
    await client.register(k.genesis);
    await client.post(`/v1/histories/${id}/heads`, await k.statement(k.commitAt, null));
    assert.equal((await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.commitment, k.commitAt))).status, 201);
    await client.post(`/v1/histories/${id}/heads`, await k.statement(r - 1, k.commitAt));
    // The thief of key 1: two heads of their own after L = r - 1 (one at r itself, one past it).
    const forged1 = await k.forge(r, r - 1, 1);
    assert.equal((await client.post(`/v1/histories/${id}/heads`, forged1)).status, 201);
    const forged2 = await t.signHeadStatement(k.signer1, { ...forged1.statement, head: { hash: `0x${"b2".repeat(32)}`, position: r + 2, canonicalTime: r + 2 }, previous: { hash: forged1.statement.head.hash, position: r } });
    assert.equal((await client.post(`/v1/histories/${id}/heads`, forged2)).status, 201);
    // Without the next key the thief cannot supersede: its rotation is not pre-rotated (KEY_EVENT_INVALID), and a chain
    // from a head the witness does not hold is refused.
    const thiefChain = await k.statement(r, r - 1, k.signer1);
    assert.equal((await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.plainRotation, r, { chain: thiefChain }))).json.error.code, "KEY_EVENT_INVALID");
    const notHeld = await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.rotation, r, { chain: await k.statement(r, 2, k.signer1) }));
    assert.deepEqual([notHeld.status, notHeld.json.error.code], [409, "SUPERSEDE_REFUSED"]);
    // The owner: the pre-rotated rotation with the chain statement for r (old key) from L.
    const chain = await k.statement(r, r - 1, k.signer1);
    const superseded = await client.post(`/v1/histories/${id}/key-events?nonce=${NONCE}`, k.keyEvent(k.rotation, r, { chain }));
    assert.equal(superseded.status, 201, superseded.text);
    const entry = superseded.json.superseded.entry;
    assert.equal(entry.kind, "SUPERSEDED");
    assert.deepEqual([entry.supersededLatest.position, entry.supersededCount, entry.supersededToIndex], [r + 2, 2, superseded.json.superseded.index]);
    assert.deepEqual(superseded.json.latest.head, k.heads[r], "latest reset to L, then the chain's head r");
    assert.equal(t.verifyLatestNote(superseded.json.latestNote, [handle.witness.verifierKey], { historyId: id, nonce: NONCE }).latest.supersedes, 1);
    // Statements that state or extend a superseded head: 409 SUPERSEDED (where the old key still counts), with the latest.
    const again = await client.post(`/v1/histories/${id}/heads`, forged1);
    assert.deepEqual([again.status, again.json.error.code, again.json.latest.head.position], [409, "SUPERSEDED", r]);
    // One supersede per rotation: a repeat is the recorded key event (idempotent), nothing more.
    assert.equal((await client.post(`/v1/histories/${id}/key-events`, k.keyEvent(k.rotation, r, { chain }))).status, 200);
    // The owner continues with the new key.
    assert.equal((await client.post(`/v1/histories/${id}/heads`, await k.statement(r + 1, r))).status, 201);
    const summary = (await client.get(`/v1/histories/${id}`)).json;
    assert.equal(summary.supersedes, 1);
    assert.equal(summary.lastSupersede.entry.kind, "SUPERSEDED");
    // Restart: the replay rebuilds the same state.
    await handle.close();
    handle = await startWitness({ dir, init: false });
    client = new TestClient(handle.url, handle.witness.verifierKey);
    assert.deepEqual((await client.get(`/v1/histories/${id}`)).json, { ...summary, checkpoint: (await client.get(`/v1/histories/${id}`)).json.checkpoint });
    assert.equal((await client.post(`/v1/histories/${id}/heads`, forged1)).json.error.code, "SUPERSEDED");
    const trust = { verifierKey: handle.witness.verifierKey, origin: handle.witness.origin };
    await handle.close();
    handle = undefined;
    const report = checkLog(dir, trust);
    assert.equal(report.ok, true, JSON.stringify(report.problems));
    assert.equal(report.kinds.SUPERSEDED, 1);
    // A tampered SUPERSEDED line (the count of superseded heads lowered): check-log pinpoints it.
    const path = join(dir, "log.jsonl");
    const lines = readFileSync(path, "utf8").split("\n");
    const at = lines.findIndex((line) => line.includes('"kind":"SUPERSEDED"'));
    const record = JSON.parse(lines[at]);
    record.entry.supersededCount = 1;
    lines[at] = JSON.stringify(record);
    writeFileSync(path, lines.join("\n"));
    const tampered = checkLog(dir, trust);
    assert.equal(tampered.ok, false);
    assert.equal(tampered.problems[0].line, at + 1);
    assert.match(tampered.problems[0].message, /supersededCount/);
  } finally {
    await handle?.close();
    cleanup();
  }
});

test("key-event bundles: POST /v1/admin/key-events needs the admin token and runs the network checks; import-key-events takes the server lock", async () => {
  const { dir, cleanup } = tempDir();
  let handle = await startWitness({ dir });
  const client = new TestClient(handle.url, handle.witness.verifierKey);
  try {
    const k = await buildKeyEventHistory({ name: "ke-admin" });
    const id = k.historyId;
    await client.register(k.genesis);
    await client.post(`/v1/histories/${id}/heads`, await k.statement(k.commitAt - 1, null));
    const commitment = await bundleOf(k, k.commitAt);
    assert.equal((await client.post("/v1/admin/key-events", commitment)).status, 401, "no token");
    assert.equal((await client.post("/v1/admin/key-events", commitment, { authorization: "Bearer itw_wrong" })).status, 401);
    const auth = { authorization: `Bearer ${ADMIN_TOKEN}` };
    assert.equal((await client.post("/v1/admin/key-events", { ...commitment, version: "irontrellis-key-event-bundle/9" }, auth)).json.error.code, "INVALID_REQUEST");
    // The token gates the channel, not the trust: a bundle whose statement is signed by another key is refused like on the network.
    const forged = { ...commitment, statement: await k.statement(k.commitAt, k.commitAt - 1, k.thiefSigner) };
    assert.equal((await client.post("/v1/admin/key-events", forged, auth)).json.error.code, "SIGNATURE_INVALID");
    const imported = await client.post("/v1/admin/key-events", commitment, auth);
    assert.equal(imported.status, 201, imported.text);
    assert.equal(imported.json.receipt.entry.kind, "ROTATED");
    // Offline: while the server runs, the import cannot take the lock; once it is stopped, the rotation bundle goes in.
    await client.post(`/v1/histories/${id}/heads`, await k.statement(k.rotateAt - 1, k.commitAt));
    const rotationBundle = join(dir, "rotation.bundle.json");
    writeFileSync(rotationBundle, JSON.stringify(await bundleOf(k, k.rotateAt)));
    await assert.rejects(importKeyEvents({ dataDir: dir, files: [rotationBundle], logger: silentLogger }), /another witness server holds the lock/);
    await handle.close();
    handle = undefined;
    const outcomes = await importKeyEvents({ dataDir: dir, files: [rotationBundle], logger: silentLogger });
    assert.deepEqual(outcomes.map((o) => [o.status, o.accepted]), [[201, true]]);
    assert.deepEqual((await importKeyEvents({ dataDir: dir, files: [rotationBundle], logger: silentLogger })).map((o) => o.status), [200], "idempotent");
    const key = loadWitnessKey(join(dir, "witness-key.json"));
    const report = checkLog(dir, { verifierKey: key.verifierKey, origin: loadConfig(join(dir, "config.json")).origin });
    assert.equal(report.ok, true, JSON.stringify(report.problems));
    assert.deepEqual(Object.keys(report.kinds).sort(), ["EQUIVOCATION", "HEAD", "REGISTERED", "ROTATED", "SUPERSEDED"]);
    assert.equal(report.kinds.ROTATED, 2);
    handle = await startWitness({ dir, init: false });
    const after = await new TestClient(handle.url, handle.witness.verifierKey).get(`/v1/histories/${id}`);
    assert.deepEqual(after.json.epochs.map((epoch) => epoch.fromPosition), [0, k.commitAt + 1, k.rotateAt + 1]);
  } finally {
    await handle?.close();
    cleanup();
  }
});
