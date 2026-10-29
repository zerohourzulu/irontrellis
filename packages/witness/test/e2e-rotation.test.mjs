// End to end against the REAL witness server process (WITNESS-DESIGN §6 e2e (4), §8.1, §9.2): owner key rotation
// mid-history through `irontrellis owner rotate-key` — the witness records HEAD r (old key), ROTATED (with
// previousHead), HEAD r+1 (new key); an old-key statement for a new head is SIGNATURE_INVALID; old heads keep
// verifying; check-log re-verifies the rotation from the leaf alone. Then a rotation while the witness is down,
// recovered by the next process from the queue persisted in the side file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { renameSync } from "node:fs";
import {
  checkLog, cliFor, core, diskHead, diskState, freshProcess, historyIdOf, ownerOn, historyLog, http, scratch, startProxy, startWitnessServer, t, witnessHistory, witnessLatest,
} from "./e2e-harness.mjs";

const keyIdOf = (history) => core.loadOwnerKeyFile(core.ownerKeyPathFor(history)).keyId;

test("(4) rotation mid-history via the CLI: HEAD r (old key), ROTATED, HEAD r+1 (new key); the old key cannot state new heads; old heads still verify", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "rotation.witness" });
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    for (const agent of ["agent:1", "agent:2"]) await cli.ok(["agent", "create", agent]);
    const id = historyIdOf(history);
    const oldKeyId = keyIdOf(history);
    const rotated = await cli(["owner", "rotate-key", "--reason", "scheduled rotation"], { json: true });
    assert.equal(rotated.code, 0, rotated.stdout + rotated.stderr);
    const newKeyId = keyIdOf(history);
    assert.notEqual(newKeyId, oldKeyId);
    const r = diskHead(history).position;
    assert.equal(diskState(history).events[r].type, "OWNER_KEYS_ROTATED");
    await cli.ok(["agent", "create", "agent:after-rotation"]);

    // The witness log, in order: HEAD r by the old key, ROTATED (previousHead r-1, rotationHead r), HEAD r+1 by the new key.
    const log = await historyLog(server, id);
    const at = log.indexOf(`HEAD ${r} ${oldKeyId}`);
    assert.ok(at >= 0, log.join("\n"));
    assert.deepEqual(log.slice(at), [`HEAD ${r} ${oldKeyId}`, `ROTATED ${r - 1}->${r}`, `HEAD ${r + 1} ${newKeyId}`]);
    const info = await witnessHistory(server, id);
    assert.deepEqual(info.epochs.map((epoch) => [epoch.fromPosition, epoch.keys.map((key) => key.keyId)]), [[0, [oldKeyId]], [r + 1, [newKeyId]]]);
    assert.deepEqual(info.latest.head, diskHead(history));
    const entries = (await http(server.url, "GET", `/v1/entries?start=0&end=1000`)).json.entries;
    const rotatedLeaf = entries.find((entry) => entry.kind === "ROTATED" && entry.historyId === id);
    assert.deepEqual(rotatedLeaf.previousHead, { hash: diskState(history).eventHistoryHashes[r - 1], position: r - 1 });
    assert.deepEqual(rotatedLeaf.rotationHead, { hash: diskState(history).eventHistoryHashes[r], position: r });
    // `init` committed a next key, so the CLI rotation was pre-rotated: the witness validated and recorded the revealed key's
    // proof of possession and the new set's commitment (verifyRotationEvent), and serves epochs without the commitment field.
    assert.deepEqual(rotatedLeaf.rotation.data.nextKeyAuthorizations.map((proof) => proof.keyId), [newKeyId]);
    assert.equal(rotatedLeaf.rotation.data.nextKeyDigests.length, 1);
    assert.deepEqual(rotatedLeaf.rotation.data.nextKeyDigests, diskState(history).ownerKeyEpochs.at(-1).nextKeyDigests);
    assert.equal(rotated.json.preRotated, true);

    // An old-key statement for a new head (crafted with the core API from the retired key file) is refused.
    const retired = core.loadOwnerKeyFile(core.retiredOwnerKeyPathFor(history, oldKeyId));
    const state = diskState(history);
    const newHead = { hash: `0x${"ab".repeat(32)}`, position: state.head.position + 1, canonicalTime: state.head.canonicalTime + 1 };
    const statement = (signer) => t.signHeadStatement(signer, { version: t.HEAD_STATEMENT_VERSION, historyId: id, domain: state.genesis.domain, head: newHead, previous: { hash: state.head.hash, position: state.head.position } });
    const size = (await http(server.url, "GET", "/v1/checkpoint")).text;
    const refused = await http(server.url, "POST", `/v1/histories/${id}/heads`, await statement(retired));
    assert.equal(refused.status, 400, refused.text);
    assert.equal(refused.json.error.code, "SIGNATURE_INVALID");
    assert.equal(refused.json.error.hint, undefined, "a known, retired key: no ROTATION_REQUIRED hint");
    // A key the witness has never seen gets the ROTATION_REQUIRED hint.
    const stranger = core.keyPairFromPrivateKey("ed25519", "owner:stranger", `0x${"77".repeat(32)}`);
    const unknown = await http(server.url, "POST", `/v1/histories/${id}/heads`, await statement({ keyId: stranger.keyId, scheme: stranger.scheme, credential: stranger.credential, signHash: core.signHashWith(stranger) }));
    assert.equal(unknown.json.error.code, "SIGNATURE_INVALID");
    assert.equal(unknown.json.error.hint, "ROTATION_REQUIRED");
    assert.equal((await http(server.url, "GET", "/v1/checkpoint")).text, size, "nothing appended");
    // An old-key statement for an old head (≤ r) is still valid: the held one is ALREADY_WITNESSED, its receipt verifies.
    const heldR = await http(server.url, "GET", `/v1/histories/${id}/heads/${r}`);
    assert.equal(heldR.status, 200);
    assert.equal(t.verifyWitnessReceipt(heldR.json.receipt, [server.verifierKey]).ok, true);
    assert.equal(heldR.json.receipt.entry.signedStatement.keyId, oldKeyId);
    assert.equal(core.verifySignedStatement(heldR.json.receipt.entry.signedStatement, state), true, "the old-key statement of head r verifies against the history's key epochs");
    const resubmitted = await http(server.url, "POST", `/v1/histories/${id}/heads`, heldR.json.receipt.entry.signedStatement);
    assert.equal(resubmitted.json.status, "ALREADY_WITNESSED");
    for (let p = 1; p < r; p += 1) {
      const held = await http(server.url, "GET", `/v1/histories/${id}/heads/${p}`);
      if (held.status === 404) continue; // sync mode states every head, but a head may be skipped by design
      assert.equal(t.verifyWitnessReceipt(held.json.receipt, [server.verifierKey]).ok, true);
      assert.equal(core.verifySignedStatement(held.json.receipt.entry.signedStatement, state), true);
    }
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 0, verdict.stdout);
    assert.equal(verdict.json.report.remoteWitnessStatus, "OK");
    const audit = checkLog(server.dataDir);
    assert.equal(audit.status, "VALID", JSON.stringify(audit.problems));
    assert.equal(audit.kinds.ROTATED, 1);
  } finally {
    await space.cleanup();
  }
});

test("(4) rotation while the witness is down: the old-key statement and the rotation queue in the side file; the next process (`irontrellis witness sync`) recovers", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "rotation-down.witness" });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    await cli.ok(["agent", "create", "agent:1"]);
    const id = historyIdOf(history);
    const pendingOf = () => core.readWitnessState(`${history}.witness.json`).pending;

    // (a) The owner process that rotates has talked to the witness; the witness goes down just before the rotation.
    const oldKeyId = keyIdOf(history);
    freshProcess();
    const owner = ownerOn(history);
    await owner.createAgent({ id: "agent:2" });
    const before = await witnessLatest(server, id);
    assert.deepEqual(before, diskHead(history));
    proxy.down = true;
    // The default two-phase rotation (WITNESS-DESIGN §11.2) refuses while the bound witness is down; --emergency is the old behaviour.
    await assert.rejects(owner.rotateOwnerKey({ reason: "while the witness is down" }), (error) => error.code === "WITNESS_UNAVAILABLE");
    const rotation = await owner.rotateOwnerKey({ reason: "while the witness is down", emergency: true });
    const r = rotation.head.position;
    const newKeyId = rotation.keyId;
    owner.close?.(); // the process ends here
    const pending = pendingOf();
    assert.deepEqual(pending.map((item) => item.kind), ["statement", "rotation"]);
    assert.equal(pending[0].head.position, r);
    assert.equal(Object.values(pending[0].statements)[0].keyId, oldKeyId, "signed by the old key before the key files were swapped, and persisted");
    assert.deepEqual(await witnessLatest(server, id), before, "nothing reached the witness");
    // Only the queued statement can supply the old key's signature now: the retired key file is taken away.
    const retired = core.retiredOwnerKeyPathFor(history, oldKeyId);
    renameSync(retired, `${retired}.away`);
    proxy.down = false;
    const synced = await cli(["witness", "sync"], { json: true });
    assert.equal(synced.code, 0, synced.stdout + synced.stderr);
    assert.equal(synced.json.status.unwitnessedEvents, 0);
    assert.equal(synced.json.status.pending.length, 0);
    assert.deepEqual((await historyLog(server, id)).slice(-2), [`HEAD ${r} ${oldKeyId}`, `ROTATED ${r - 1}->${r}`]);
    await cli.ok(["agent", "create", "agent:after"]);
    assert.deepEqual((await historyLog(server, id)).at(-1), `HEAD ${r + 1} ${newKeyId}`);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));

    // (b) A FRESH process (the CLI) rotates while the witness is down: it never heard the witness, so it cannot sign the
    // statement for head r against a verified `previous` (rule W2) and queues the rotation only. CURRENT BEHAVIOUR
    // (documented in the report): the statement for r is signed later from the retired key file; without that file
    // the witness cannot follow the rotation (KEY_UNAVAILABLE) until the file is back.
    const secondOld = keyIdOf(history);
    proxy.down = true;
    const rotatedCli = await cli(["owner", "rotate-key", "--reason", "fresh process, witness down", "--emergency"]);
    assert.equal(rotatedCli.code, 0, `recorded locally and queued: ${rotatedCli.stdout}\n${rotatedCli.stderr}`);
    const r2 = diskHead(history).position;
    const secondNew = keyIdOf(history);
    await cli.ok(["agent", "create", "agent:queued"]);
    const queued = pendingOf();
    assert.ok(queued.some((item) => item.kind === "rotation" && item.rotationHead.position === r2), JSON.stringify(queued));
    assert.ok(!queued.some((item) => item.kind === "statement" && item.statements !== undefined), "nothing presigned without a verified witness answer");
    const secondRetired = core.retiredOwnerKeyPathFor(history, secondOld);
    renameSync(secondRetired, `${secondRetired}.away`);
    proxy.down = false;
    const stuck = await cli(["witness", "sync"], { json: true });
    assert.equal(stuck.code, 1, stuck.stdout);
    assert.match(stuck.stdout + stuck.stderr, /KEY_UNAVAILABLE|no owner key in force at position/);
    assert.equal((await witnessLatest(server, id)).position, r2 - 1, "the witness stays at the last head before the rotation");
    renameSync(`${secondRetired}.away`, secondRetired);
    const recovered = await cli(["witness", "sync"], { json: true });
    assert.equal(recovered.code, 0, recovered.stdout + recovered.stderr);
    assert.deepEqual((await historyLog(server, id)).slice(-3), [`HEAD ${r2} ${secondOld}`, `ROTATED ${r2 - 1}->${r2}`, `HEAD ${r2 + 1} ${secondNew}`]);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    await cli.ok(["verify"]);
    const audit = checkLog(server.dataDir);
    assert.equal(audit.status, "VALID", JSON.stringify(audit.problems));
    assert.equal(audit.kinds.ROTATED, 2);
  } finally {
    await space.cleanup();
  }
});
