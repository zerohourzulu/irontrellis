// Interop with histories written by core's LocalOwner (createLocalOwner,
// rotateOwnerKey): the genesis and events come from the history file on disk,
// heads from core's prefix hasher, statements are signed with the owner key
// files (the retired one for heads up to each rotation).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { core, startWitness, t, tempDir, TestClient } from "./helpers.mjs";
const { FORMAT1_TEST_TOOLING } = await import("@ramex-labs/irontrellis/internal-format1"); // A-185.3 / A-194: older formats are test tooling

const readEvents = (historyFile) => readFileSync(historyFile, "utf8").split("\n").filter((line) => line !== "").map((line) => JSON.parse(line).event);

test("a LocalOwner history with two key rotations is witnessed end to end", async () => {
  const { dir, cleanup } = tempDir();
  const handle = await startWitness({ dir: join(dir, "witness") });
  try {
    const client = new TestClient(handle.url, handle.witness.verifierKey);
    const historyFile = join(dir, "history.jsonl");
    const domain = { protocol: "irontrellis", version: "1", deploymentId: "deployment:local-owner" };
    let clock = 1_000;
    const owner = await core.createLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now: () => (clock += 1), format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true });
    const key1 = core.loadOwnerKeyFile(core.ownerKeyPathFor(historyFile));
    const first = await owner.rotateOwnerKey({ reason: "scheduled" });
    const key2 = core.loadOwnerKeyFile(core.ownerKeyPathFor(historyFile));
    const second = await owner.rotateOwnerKey({ reason: "scheduled again" });
    const key3 = core.loadOwnerKeyFile(core.ownerKeyPathFor(historyFile));
    await owner.close?.();
    assert.notEqual(key1.keyId, key2.keyId);
    assert.equal(core.loadOwnerKeyFile(first.retiredKeyFile).keyId, key1.keyId);

    const events = readEvents(historyFile);
    const hashes = core.hashEventHistoryPrefixes(events, "irontrellis-event/1");
    const head = (p) => ({ hash: hashes[p], position: p, canonicalTime: events[p].timestamp });
    const at = (p) => ({ hash: hashes[p], position: p });
    const historyId = hashes[0];
    const sign = (signer, p, previous) => t.signHeadStatement(signer, { version: t.HEAD_STATEMENT_VERSION, historyId, domain, head: head(p), previous: previous === null ? null : at(previous) });
    const r1 = first.head.position;
    const r2 = second.head.position;
    assert.equal(first.head.hash, hashes[r1]);
    assert.equal(r2, r1 + 1);

    const registered = await client.register(events[0]);
    assert.equal(registered.status, 201);
    assert.equal(registered.json.historyId, historyId);
    const heads = `/v1/histories/${historyId}/heads`;
    const keyEvents = `/v1/histories/${historyId}/key-events`;
    assert.equal((await client.post(heads, await sign(key1, 0, null))).status, 201);
    assert.equal((await client.post(heads, await sign(key1, r1, 0))).status, 201, "the rotation head is stated by the old key");
    const rot1 = await client.post(keyEvents, { event: events[r1], previousHead: at(r1 - 1), eventHead: at(r1) });
    assert.equal(rot1.status, 201, rot1.text);
    assert.equal(rot1.json.epochs.at(-1).fromPosition, first.fromPosition);
    assert.equal((await client.post(heads, await sign(key2, r2, r1))).status, 201, "the second rotation head is stated by key 2");
    const early = await client.post(heads, await sign(key3, r2, r1));
    assert.equal(early.json.error.code, "SIGNATURE_INVALID");
    const rot2 = await client.post(keyEvents, { event: events[r2], previousHead: at(r1), eventHead: at(r2) });
    assert.equal(rot2.status, 201, rot2.text);
    assert.deepEqual(rot2.json.epochs.map((epoch) => epoch.keys.map((key) => key.keyId)), [[key1.keyId], [key2.keyId], [key3.keyId]]);
    const history = await client.get(`/v1/histories/${historyId}`);
    assert.deepEqual(history.json.latest.head, head(r2));
    // Old statements keep verifying; the retired keys cannot state anything new.
    assert.equal((await client.post(heads, await sign(key1, 0, null))).json.status, "ALREADY_WITNESSED");
    assert.equal((await client.post(heads, await sign(key2, r2, r1))).json.status, "ALREADY_WITNESSED");
  } finally {
    await handle.close();
    cleanup();
  }
});
