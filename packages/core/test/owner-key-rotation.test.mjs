// Owner key rotation: the OWNER_KEYS_ROTATED event, owner key epochs and key validity by
// position (replay, pins, anchor logs), the standalone rotation check a remote witness uses, and
// LocalOwner.rotateOwnerKey with its key-file handling and crash recovery.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const signer = await import("../src/signer.ts");
const anchor = await import("../src/anchor.ts");
const keys = await import("../src/owner-keys.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { replay } = await import("../src/replay.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const suites = await import("../src/crypto/suites.ts");
const { createLocalOwner: createLocalOwnerDefault, openLocalOwner: openLocalOwnerDefault, verifyHistory } = await import("../src/owner.ts");
// These tests cover the format-1 (and legacy) owner API; the API writes format 2 by default (SPEC §19), so format 1 is named for every handle and domain made here.
const createLocalOwner = (options) => createLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const openLocalOwner = (options) => openLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const { IronTrellisError } = await import("../src/input.ts");
const types = await import("../src/types.ts");

const TRELLIS = "irontrellis-event/1";
const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: "deployment:rotation" });
const seed = (n) => `0x${n.toString(16).padStart(64, "0")}`;
const pair = (id, n) => suites.keyPairFromPrivateKey("ed25519", id, seed(n));
const k1 = pair("owner:1", 0x5001), k2 = pair("owner:2", 0x5002), k3 = pair("owner:3", 0x5003), stranger = pair("owner:x", 0x5009);
const s1 = signer.signerFromKeyPair(k1), s2 = signer.signerFromKeyPair(k2), s3 = signer.signerFromKeyPair(k3), sx = signer.signerFromKeyPair(stranger);
const ok = (p) => ({ keyId: p.keyId, scheme: "ed25519", credential: p.credential });
const plain = (v) => JSON.parse(JSON.stringify(v));

const genesis = () => ({
  id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
  data: {
    domain: DOMAIN, versions: { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: [ok(k1)],
    adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:rotation", policyVersion: "policy:rotation/1",
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:rotation", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
  },
});
const agent = (n) => ({ id: `agent:${n}`, type: "AGENT_CREATED", timestamp: 60 + n, data: { agentId: `agent:${n}`, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
const rotation = (id, ownerKeys, extra = {}) => ({ id, type: "OWNER_KEYS_ROTATED", timestamp: 50, data: { ownerKeys, ...extra } });

/** Sign `event` as the next event of `list` with `by`; returns the extended list. */
async function extend(list, event, by) {
  const accepted = replay(list);
  assert.equal(accepted.status, "ACCEPTED", `${accepted.code} ${accepted.reason}`);
  return [...list, plain(await signer.signControlEvent(by, event, DOMAIN, accepted.head, "sha256"))];
}
/** genesis (k1) · principal (k1) · rotation to `to` signed by `by` at position 2. */
async function rotated(to = [ok(k2)], by = s1) {
  let list = [genesis()];
  list = await extend(list, { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }, s1);
  return extend(list, rotation("rotation:1", to, { reason: "scheduled rotation" }), by);
}
const rejectedWith = (list, code, position) => {
  const result = replay(list);
  assert.equal(result.status, "REJECTED");
  assert.equal(result.code, code, result.reason);
  if (position !== undefined) assert.equal(result.position, position);
  return result;
};

// ---------------------------------------------------------------- vocabulary and schema

test("OWNER_KEYS_ROTATED is a format-1 control event that capacity always admits", () => {
  assert.ok(types.EVENT_TYPES.includes("OWNER_KEYS_ROTATED"));
  assert.ok(types.CONTROL_EVENT_TYPES.has("OWNER_KEYS_ROTATED"));
  assert.ok(types.ALWAYS_ADMITTED_EVENT_TYPES.has("OWNER_KEYS_ROTATED"));
  assert.ok(types.TRELLIS_ONLY_EVENT_TYPES.has("OWNER_KEYS_ROTATED"));
});

test("schema: the new set has the genesis owner-key shape, reason is identifier-shaped, nothing else", () => {
  const check = (data) => events.validateEvent({ id: "r", type: "OWNER_KEYS_ROTATED", timestamp: 1, data }, TRELLIS, 5);
  assert.equal(check({ ownerKeys: [ok(k2)] }).ok, true);
  assert.equal(check({ ownerKeys: [ok(k2)], reason: "key compromise" }).ok, true);
  assert.equal(check({ ownerKeys: [ok(k2)], controlAuthorization: { keyId: "x", signature: "0x00" } }).ok, true, "the authorization is not part of the effect schema");
  assert.equal(check({ ownerKeys: [] }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ ownerKeys: [ok(k2), ok(k2)] }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ ownerKeys: [{ ...ok(k2), credential: "0x1234" }] }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ ownerKeys: [ok(k2)], extra: true }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ ownerKeys: [ok(k2)], reason: "" }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ ownerKeys: [ok(k2)], reason: "line\nbreak" }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ ownerKeys: [ok(k2)], reason: "x".repeat(257) }).code, "INVALID_INPUT", "an over-long reason is a named-limit failure");
  assert.equal(check({ ownerKeys: Array.from({ length: 65 }, (_, i) => ({ ...ok(k2), keyId: `k:${i}` })) }).code, "INVALID_INPUT");
  assert.equal(check({}).code, "EVENT_DATA_INVALID");
  // Legacy histories cannot carry it at all.
  assert.equal(events.validateEvent({ id: "r", type: "OWNER_KEYS_ROTATED", timestamp: 1, data: { ownerKeys: [ok(k2)] } }, "continuity-event/0.2", 5).code, "UNSUPPORTED_EVENT_TYPE");
});

// ---------------------------------------------------------------- replay

test("replay: a rotation signed by the current key opens a new epoch from the next position", async () => {
  const list = await extend(await rotated(), agent(1), s2);
  const result = replay(list);
  assert.equal(result.status, "ACCEPTED", `${result.code} ${result.reason}`);
  const state = result.state;
  assert.deepEqual(plain(state.ownerKeyEpochs), [{ fromPosition: 0, keys: [ok(k1)] }, { fromPosition: 3, keys: [ok(k2)] }]);
  assert.deepEqual(plain(keys.ownerKeysAt(state, 0)), [ok(k1)]);
  assert.deepEqual(plain(keys.ownerKeysAt(state, 2)), [ok(k1)], "the rotation's own position is still governed by the old set");
  assert.deepEqual(plain(keys.ownerKeysAt(state, 3)), [ok(k2)]);
  assert.deepEqual(plain(keys.ownerKeysAt(state, 999)), [ok(k2)]);
  assert.deepEqual(plain(keys.ownerKeysAt(state, -1)), []);
  assert.deepEqual(plain(keys.ownerKeysAt(state.ownerKeyEpochs, 3)), [ok(k2)], "epochs work as well as a state");
  assert.equal(list[2].data.reason, "scheduled rotation");
});

test("replay: after a rotation the retired key cannot sign a control event; a carried-over key still can", async () => {
  rejectedWith(await extend(await rotated(), agent(1), s1), "CONTROL_AUTHORIZATION_INVALID", 3);
  const carried = await rotated([ok(k1), ok(k2)]);
  assert.equal(replay(await extend(carried, agent(1), s1)).status, "ACCEPTED");
  assert.equal(replay(await extend(carried, agent(1), s2)).status, "ACCEPTED");
});

test("replay: a rotation signed by a key the history never declared, or by the new key itself, is refused", async () => {
  rejectedWith(await rotated([ok(k2)], sx), "CONTROL_AUTHORIZATION_INVALID", 2);
  rejectedWith(await rotated([ok(k2)], s2), "CONTROL_AUTHORIZATION_INVALID", 2);
});

test("replay: key-set rules — retired ids never return, an id keeps its key, a retired key gets no new name", async () => {
  const once = await rotated();
  // A retired key id cannot come back (even with its old key), signed by the current key.
  rejectedWith(await extend(once, rotation("rotation:2", [ok(k1)]), s2), "TRANSITION_INVALID", 3);
  rejectedWith(await extend(once, rotation("rotation:2", [ok(k2), ok(k1)]), s2), "TRANSITION_INVALID", 3);
  // The same key id with a different public key.
  rejectedWith(await rotated([{ ...ok(k3), keyId: "owner:1" }]), "TRANSITION_INVALID", 2);
  // A retired key under a new id.
  rejectedWith(await extend(once, rotation("rotation:2", [{ ...ok(k1), keyId: "owner:9" }]), s2), "TRANSITION_INVALID", 3);
  // A current key under a second id (an alias).
  rejectedWith(await rotated([ok(k1), { ...ok(k1), keyId: "owner:alias" }]), "TRANSITION_INVALID", 2);
  // Two rotations in a row are fine when each is signed by the set in force.
  const twice = await extend(once, rotation("rotation:2", [ok(k3)]), s2);
  const result = replay(await extend(twice, agent(1), s3));
  assert.equal(result.status, "ACCEPTED", `${result.code} ${result.reason}`);
  assert.deepEqual(result.state.ownerKeyEpochs.map((epoch) => [epoch.fromPosition, epoch.keys.map((key) => key.keyId)]), [[0, ["owner:1"]], [3, ["owner:2"]], [4, ["owner:3"]]]);
  assert.equal(keys.ownerKeyRotationFailure(result.state.ownerKeyEpochs, [ok(k3)]), undefined, "carrying the current set over is allowed");
});

test("replay: a rotation in a legacy history is UNSUPPORTED_EVENT_TYPE", async () => {
  const legacy = JSON.parse(readFileSync(new URL("../../reference-0.2/tests/fixtures/handover-history.json", import.meta.url), "utf8"));
  const last = legacy.at(-1);
  rejectedWith([...legacy, { id: "rotation:legacy", type: "OWNER_KEYS_ROTATED", timestamp: last.timestamp, data: { ownerKeys: [ok(k2)] } }], "UNSUPPORTED_EVENT_TYPE", legacy.length);
});

// ---------------------------------------------------------------- head attestations by position

test("attestations: the head at the rotation and every older head verify under the old key; later heads only under the new", async () => {
  const list = await extend(await extend(await rotated(), agent(1), s2), agent(2), s2);
  const state = replay(list).state;
  const head = (p) => ({ hash: state.eventHistoryHashes[p], position: p, canonicalTime: list[p].timestamp });
  const by = async (s, p) => signer.attestHead(s, DOMAIN, head(p), "sha256");
  assert.equal(keys.verifyHeadAttestationAt(await by(s1, 1), state), true, "an old head attested by the old key still verifies");
  assert.equal(keys.verifyHeadAttestationAt(await by(s1, 2), state), true, "the head that ends with the rotation belongs to the old set");
  assert.equal(keys.verifyHeadAttestationAt(await by(s2, 2), state), false);
  assert.equal(keys.verifyHeadAttestationAt(await by(s1, 3), state), false, "a post-rotation head attested by the retired key fails");
  assert.equal(keys.verifyHeadAttestationAt(await by(s2, 3), state), true);
  assert.equal(keys.verifyHeadAttestationAt(await by(s2, 4), state), true);
  assert.equal(keys.verifyHeadAttestationAt(null, state), false);
  assert.equal(keys.verifyHeadAttestationAt({ ...(await by(s2, 3)), head: { ...head(3), position: -1 } }, state), false);
  // The witness context follows the same rule.
  const context = anchor.anchorContextOf(state);
  assert.deepEqual(plain(context.ownerKeys), [ok(k2)]);
  assert.deepEqual(plain(anchor.contextKeysAt(context, 2)), [ok(k1)]);
  assert.deepEqual(plain(anchor.contextKeysAt({ domain: DOMAIN, algorithm: "sha256", ownerKeys: [ok(k1)] }, 3)), [ok(k1)], "an rc.1 context without ownerKeysAt is position-blind");
});

// ---------------------------------------------------------------- the standalone check (remote witness)

test("verifyRotationEvent: checks schema, signature over previousHead and key-set rules without the history", async () => {
  const list = await rotated();
  const prefix = replay(list.slice(0, 2));
  const previousHead = { hash: prefix.head.hash, position: prefix.head.position };
  const epochs = [{ fromPosition: 0, keys: [ok(k1)] }];
  const verified = keys.verifyRotationEvent(list[2], { domain: DOMAIN, previousHead, epochs });
  assert.equal(verified.ok, true, verified.reason);
  assert.equal(verified.position, 2);
  assert.equal(verified.fromPosition, 3);
  assert.equal(verified.reason, "scheduled rotation");
  assert.deepEqual(plain(verified.keys), [ok(k2)]);
  assert.deepEqual(plain(verified.epochs), plain(replay(list).state.ownerKeyEpochs), "the witness ends with the epochs replay derives");
  // A bare key set is refused, never read as "an epoch without a commitment"; so is a malformed epoch list.
  const bare = keys.verifyRotationEvent(list[2], { domain: DOMAIN, previousHead, keys: [ok(k1)] });
  assert.equal(bare.code, "INVALID_INPUT", "keys alone are refused");
  assert.match(bare.reason, /epochs seeded from the genesis/);
  assert.equal(keys.verifyRotationEvent(list[2], { domain: DOMAIN, previousHead, epochs, keys: [ok(k1)] }).code, "INVALID_INPUT", "keys beside epochs are refused too");
  for (const [label, bad] of [
    ["empty", []], ["not a list", { fromPosition: 0, keys: [ok(k1)] }], ["not genesis first", [{ fromPosition: 1, keys: [ok(k1)] }]],
    ["no keys", [{ fromPosition: 0, keys: [] }]], ["positions not increasing", [{ fromPosition: 0, keys: [ok(k1)] }, { fromPosition: 0, keys: [ok(k1)] }]],
    ["empty commitment", [{ fromPosition: 0, keys: [ok(k1)], nextKeyDigests: [] }]], ["non-hash commitment", [{ fromPosition: 0, keys: [ok(k1)], nextKeyDigests: ["owner:2"] }]],
  ]) assert.equal(keys.verifyRotationEvent(list[2], { domain: DOMAIN, previousHead, epochs: bad }).code, "INVALID_INPUT", label);
  assert.equal(keys.verifyRotationEvent(list[2], { domain: DOMAIN, previousHead: { ...previousHead, hash: `0x${"ab".repeat(32)}` }, epochs }).code, "CONTROL_AUTHORIZATION_INVALID");
  assert.equal(keys.verifyRotationEvent(list[2], { domain: DOMAIN, previousHead: { ...previousHead, position: 5 }, epochs }).code, "CONTROL_AUTHORIZATION_INVALID");
  assert.equal(keys.verifyRotationEvent(list[2], { domain: { ...DOMAIN, deploymentId: "elsewhere" }, previousHead, epochs }).code, "CONTROL_AUTHORIZATION_INVALID");
  assert.equal(keys.verifyRotationEvent(list[2], { domain: DOMAIN, previousHead, epochs: [{ fromPosition: 0, keys: [ok(k3)] }] }).code, "CONTROL_AUTHORIZATION_INVALID");
  assert.equal(keys.verifyRotationEvent(list[1], { domain: DOMAIN, previousHead, epochs }).code, "INVALID_INPUT", "only a rotation event");
  assert.equal(keys.verifyRotationEvent(list[2], { domain: DOMAIN, previousHead }).code, "INVALID_INPUT", "the prior key set is required");
  // Key-set rules against the witness's epochs: re-introducing a retired id.
  const second = await extend(list, rotation("rotation:2", [ok(k1)]), s2);
  const at = replay(list).head;
  const again = keys.verifyRotationEvent(second[3], { domain: DOMAIN, previousHead: { hash: at.hash, position: at.position }, epochs: verified.epochs });
  assert.equal(again.ok, false);
  assert.equal(again.code, "TRANSITION_INVALID");
});

// ---------------------------------------------------------------- LocalOwner.rotateOwnerKey

const TD = { protocol: "irontrellis", version: "1", deploymentId: "rotation-owner" };
// These tests pin the phase-B rotation rules, which still govern an owner key set without a next-key commitment: the
// histories are created with `nextKey: false` (a history commits a next key by default; pre-rotation, where the first
// set has a commitment, is tested in pre-rotation.test.mjs). A rotation still commits the NEW set to a fresh next key by
// default, so a second rotation here is pre-rotated through `<history>.owner-next-key.json`.
async function setup(t, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-rotation-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), owner: "operations", controller: "operator", now: () => (tick += 1), domain: TD, nextKey: false, ...extra };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  return { owner, config, dir, history: config.historyFile };
}
const pinOf = (history) => JSON.parse(readFileSync(`${history}.head`, "utf8"));
const stateOf = (history) => openHistoryStore(history).state();
const hasCode = (code) => (error) => error instanceof IronTrellisError && error.code === code;

test("rotateOwnerKey: a new key file replaces the old one, which is archived 0600; later writes and pins use the new key", async (t) => {
  const { owner, config, history } = await setup(t);
  const oldKey = readFileSync(`${history}.owner-key.json`, "utf8");
  const before = owner.verify().head;
  const result = await owner.rotateOwnerKey({ reason: "scheduled" });
  assert.equal(result.keyId, "owner:2");
  assert.deepEqual(result.retired, ["owner:1"]);
  assert.equal(result.head.position, before.position + 1);
  assert.equal(result.fromPosition, result.head.position + 1);
  assert.equal(result.keyFile, `${history}.owner-key.json`);
  assert.equal(result.retiredKeyFile, `${history}.owner-key.owner_1.retired.json`);
  assert.equal(readFileSync(result.retiredKeyFile, "utf8"), oldKey);
  if (process.platform !== "win32") assert.equal(statSync(result.retiredKeyFile).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  if (process.platform !== "win32") assert.equal(statSync(result.keyFile).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  assert.equal(existsSync(signer.pendingOwnerKeyPathFor(history)), false);
  assert.equal(signer.loadOwnerKeyFile(result.keyFile).keyId, "owner:2");
  const rotationEvent = owner.exportHistory().at(-1);
  assert.equal(rotationEvent.type, "OWNER_KEYS_ROTATED");
  assert.equal(rotationEvent.data.controlAuthorization.keyId, "owner:1");
  assert.equal(rotationEvent.data.reason, "scheduled");
  assert.equal(pinOf(history).attestation.keyId, "owner:1", "the head that ends with the rotation is attested under the old set");
  await owner.createAgent({ id: "alex" });
  assert.equal(owner.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:2");
  assert.equal(pinOf(history).attestation.keyId, "owner:2");
  assert.equal(owner.verify().ok, true);
  // Reopened from the files alone.
  const reopened = openLocalOwner(config);
  await reopened.createRole({ id: "desk" });
  assert.equal(reopened.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:2");
  assert.equal(verifyHistory(history).ok, true);
  assert.deepEqual(stateOf(history).ownerKeyEpochs.map((e) => e.keys.map((k) => k.keyId)), [["owner:1"], ["owner:2"]]);
  // A second rotation picks owner:3 and archives owner:2.
  const again = await reopened.rotateOwnerKey();
  assert.equal(again.keyId, "owner:3");
  assert.ok(existsSync(`${history}.owner-key.owner_2.retired.json`));
  await reopened.createAgent({ id: "cleo" });
  assert.equal(verifyHistory(history).ok, true);
});

test("rotateOwnerKey: an anchor and a pin attested before the rotation keep verifying; a new head signed by the retired key does not", async (t) => {
  const { owner, history } = await setup(t);
  const oldSigner = signer.loadOwnerKeyFile(`${history}.owner-key.json`);
  const store = openHistoryStore(history, { signer: oldSigner });
  await anchor.anchorHead(store, oldSigner, undefined, { id: "anchor:before", anchoredAt: 102 });
  store.close();
  await owner.rotateOwnerKey();
  await owner.createAgent({ id: "alex" });
  const report = verifyHistory(history);
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.anchorLogStatus, "OK");
  assert.ok(report.anchorLogHeads.every((h) => h.status === "PREFIX_OK" && h.keyId === "owner:1"));
  // The retired key attests the current (post-rotation) head: the anchor log entry is ANCHOR_LOG_INVALID ...
  const state = stateOf(history);
  const forged = await signer.attestHead(oldSigner, TD, state.head, "sha256");
  writeFileSync(`${history}.anchors`, `${readFileSync(`${history}.anchors`, "utf8")}${JSON.stringify({ attestation: forged, receivedAt: 1 })}\n`);
  const witnessed = verifyHistory(history);
  assert.equal(witnessed.ok, false);
  assert.ok(witnessed.failures.some((line) => line.startsWith("ANCHOR_LOG_INVALID")));
  // ... and a pin carrying it fails the open.
  const pin = pinOf(history);
  writeFileSync(`${history}.head`, `${JSON.stringify({ ...pin, attestation: forged })}\n`);
  assert.throws(() => openHistoryStore(history), (e) => e.code === "ROLLBACK_DETECTED" && e.detail.reason === "PIN_ATTESTATION_INVALID");
});

test("rotateOwnerKey: a store still holding the retired key never writes an invalid pin attestation", async (t) => {
  const { owner, history } = await setup(t);
  const oldSigner = signer.loadOwnerKeyFile(`${history}.owner-key.json`);
  await owner.rotateOwnerKey();
  const newSigner = signer.loadOwnerKeyFile(`${history}.owner-key.json`);
  const stale = openHistoryStore(history, { signer: oldSigner });
  const head = stale.head();
  const event = await signer.signControlEvent(newSigner, { id: "agent:alex", type: "AGENT_CREATED", timestamp: head.canonicalTime, data: { agentId: "alex", principalId: "operations", controllerId: "operator", initialControlEpoch: 1 } }, TD, head, "sha256");
  stale.append(event);
  const pin = pinOf(history);
  assert.equal(pin.attestation.keyId, "owner:1");
  assert.equal(pin.attestation.head.position, head.position, "the pin carries the last valid attestation");
  const report = verifyHistory(history);
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.ok(report.notes.some((line) => line.startsWith("PIN_ATTESTED_EARLIER")));
  assert.throws(() => stale.repin(), (e) => e.code === "KEY_UNAVAILABLE");
  stale.setSigner(newSigner);
  stale.repin();
  await stale.flush(); // an asynchronous signer attests the synchronous re-pin afterwards
  assert.equal(pinOf(history).attestation.keyId, "owner:2");
  // A control event signed by the retired key is refused by replay.
  const late = await signer.signControlEvent(oldSigner, { id: "agent:late", type: "AGENT_CREATED", timestamp: head.canonicalTime, data: { agentId: "late", principalId: "operations", controllerId: "operator", initialControlEpoch: 1 } }, TD, stale.head(), "sha256");
  assert.throws(() => stale.append(late), (e) => e.code === "CONTROL_AUTHORIZATION_INVALID");
});

test("rotateOwnerKey: a handle opened before another handle rotated picks up the new key file on its next control write", async (t) => {
  const { config, history } = await setup(t);
  const a = openLocalOwner(config), b = openLocalOwner(config);
  await a.rotateOwnerKey();
  await b.createAgent({ id: "alex" });
  assert.equal(b.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:2");
  assert.equal(pinOf(history).attestation.keyId, "owner:2");
  assert.equal(verifyHistory(history).ok, true);
});

test("rotateOwnerKey crash recovery: event recorded but files not swapped → the next open completes the swap", async (t) => {
  const { config, history } = await setup(t);
  const oldSigner = signer.loadOwnerKeyFile(`${history}.owner-key.json`);
  const pending = signer.createOwnerKeyFile(signer.pendingOwnerKeyPathFor(history), "owner:2");
  const store = openHistoryStore(history, { signer: oldSigner });
  const head = store.head();
  const event = await signer.signControlEvent(oldSigner, { id: "rotation:crash", type: "OWNER_KEYS_ROTATED", timestamp: head.canonicalTime, data: { ownerKeys: [{ keyId: "owner:2", scheme: "ed25519", credential: pending.credential }] } }, TD, head, "sha256");
  store.append(event);
  store.close();
  // The process "died" here: the key file still holds the retired key, the new one is pending.
  assert.equal(signer.loadOwnerKeyFile(`${history}.owner-key.json`).keyId, "owner:1");
  const owner = openLocalOwner(config);
  assert.equal(signer.loadOwnerKeyFile(`${history}.owner-key.json`).keyId, "owner:2");
  assert.equal(existsSync(signer.pendingOwnerKeyPathFor(history)), false);
  assert.equal(signer.loadOwnerKeyFile(`${history}.owner-key.owner_1.retired.json`).keyId, "owner:1");
  await owner.createAgent({ id: "alex" });
  assert.equal(owner.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:2");
  assert.equal(verifyHistory(history).ok, true);
});

test("rotateOwnerKey crash recovery: a pending key the history never declared is removed and a new rotation proceeds", async (t) => {
  const { owner, config, history } = await setup(t);
  signer.createOwnerKeyFile(signer.pendingOwnerKeyPathFor(history), "owner:2");
  const reopened = openLocalOwner(config);
  assert.equal(existsSync(signer.pendingOwnerKeyPathFor(history)), false);
  assert.equal(signer.loadOwnerKeyFile(`${history}.owner-key.json`).keyId, "owner:1");
  // Also inside rotateOwnerKey itself (an open that did not settle it, e.g. a handle opened earlier).
  signer.createOwnerKeyFile(signer.pendingOwnerKeyPathFor(history), "owner:2");
  const result = await owner.rotateOwnerKey();
  assert.equal(result.keyId, "owner:2");
  assert.equal(existsSync(signer.pendingOwnerKeyPathFor(history)), false);
  await reopened.createAgent({ id: "alex" });
  assert.equal(verifyHistory(history).ok, true);
});

test("rotateOwnerKey: retire lists, key ids, newSigner (async) and refusals", async (t) => {
  const { owner, history } = await setup(t);
  await assert.rejects(owner.rotateOwnerKey({ retire: ["owner:9"] }), hasCode("INVALID_INPUT"));
  await assert.rejects(owner.rotateOwnerKey({ retire: [] }), hasCode("INVALID_INPUT"), "a generated key cannot replace a key file whose key stays in force");
  await assert.rejects(owner.rotateOwnerKey({ retire: "some" }), hasCode("INVALID_INPUT"));
  await assert.rejects(owner.rotateOwnerKey({ keyId: "owner:1" }), hasCode("INVALID_INPUT"));
  await assert.rejects(owner.rotateOwnerKey({ reason: "x".repeat(257) }), hasCode("INVALID_INPUT"));
  await assert.rejects(owner.rotateOwnerKey({ unknown: true }), hasCode("INVALID_INPUT"));
  // Keeping the key-file key in force while a generated key replaces the file is refused; with newSigner it is allowed.
  const kms = suites.generateKeyPair("ed25519", "kms:1");
  const local = signer.signerFromKeyPair(kms);
  const asyncSigner = Object.freeze({ keyId: local.keyId, scheme: local.scheme, credential: local.credential, signHash: local.signHash });
  await assert.rejects(owner.rotateOwnerKey({ newSigner: asyncSigner, keyId: "other" }), hasCode("INVALID_INPUT"));
  const added = await owner.rotateOwnerKey({ newSigner: asyncSigner });
  assert.deepEqual(added.retired, ["owner:1"], "retire defaults to all");
  await owner.flush();
  assert.equal(existsSync(`${history}.owner-key.json`), false, "a retired key file is archived away");
  assert.ok(existsSync(`${history}.owner-key.owner_1.retired.json`));
  await owner.createAgent({ id: "alex" });
  await owner.flush();
  assert.equal(owner.exportHistory().at(-1).data.controlAuthorization.keyId, "kms:1");
  assert.equal(pinOf(history).attestation.keyId, "kms:1");
  // Now add a generated key file alongside the KMS key (retire nothing of the KMS key is impossible: the file must hold a key; retire kms explicitly).
  const withFile = await owner.rotateOwnerKey({ retire: ["kms:1"], keyId: "owner:file" });
  assert.equal(withFile.keyId, "owner:file");
  assert.equal(signer.loadOwnerKeyFile(`${history}.owner-key.json`).keyId, "owner:file");
  await owner.createAgent({ id: "cleo" });
  assert.equal(verifyHistory(history).ok, true);
  assert.deepEqual(stateOf(history).ownerKeyEpochs.map((e) => e.keys.map((k) => k.keyId)), [["owner:1"], ["kms:1"], ["owner:file"]]);
});

test("rotateOwnerKey: a partial retire list keeps the other keys; the key file's key must go when a generated key replaces it", async (t) => {
  const { owner, history } = await setup(t);
  const backup = signer.signerFromKeyPair(suites.generateKeyPair("ed25519", "backup:1"));
  // Add a key and retire nothing: the key file keeps owner:1, which stays in force; the handle now signs with backup:1.
  const added = await owner.rotateOwnerKey({ newSigner: backup, retire: [] });
  assert.deepEqual(added.ownerKeys.map((k) => k.keyId), ["owner:1", "backup:1"]);
  assert.deepEqual(added.retired, []);
  assert.equal(signer.loadOwnerKeyFile(`${history}.owner-key.json`).keyId, "owner:1");
  await owner.createAgent({ id: "alex" });
  assert.equal(owner.exportHistory().at(-1).data.controlAuthorization.keyId, "backup:1");
  // A generated key may not replace the key file while its key stays in force.
  await assert.rejects(owner.rotateOwnerKey({ retire: ["backup:1"] }), hasCode("INVALID_INPUT"));
  const next = await owner.rotateOwnerKey({ retire: ["owner:1"] });
  assert.equal(next.keyId, "owner:2");
  assert.deepEqual(next.ownerKeys.map((k) => k.keyId), ["backup:1", "owner:2"]);
  assert.equal(owner.exportHistory().at(-1).data.controlAuthorization.keyId, "backup:1", "the rotation is signed by the handle's current key");
  assert.equal(signer.loadOwnerKeyFile(`${history}.owner-key.json`).keyId, "owner:2");
  assert.ok(existsSync(`${history}.owner-key.owner_1.retired.json`));
  await owner.createAgent({ id: "cleo" });
  assert.equal(owner.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:2");
  assert.equal(verifyHistory(history).ok, true);
});

test("rotateOwnerKey: legacy histories have no owner keys; the rotation is admitted even when the history is full", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-rotation-legacy-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const legacy = await createLocalOwner({
    historyFile: join(dir, "legacy.jsonl"), owner: "operations", controller: "operator", now: () => 100, format: "continuity-event/0.2", [FORMAT1_TEST_TOOLING]: true,
    domain: { protocol: "continuity", version: "0.2", deploymentId: "rotation-legacy", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000000" },
  });
  await assert.rejects(legacy.rotateOwnerKey(), hasCode("INVALID_INPUT"));
  const { owner, history } = await setup(t, { maxEvents: 3 });
  await assert.rejects(owner.createAgent({ id: "alex" }), (e) => e instanceof IronTrellisError && e.code.startsWith("CAPACITY"));
  const result = await owner.rotateOwnerKey({ reason: "compromise" });
  assert.equal(result.keyId, "owner:2");
  assert.equal(verifyHistory(history).ok, true);
});
