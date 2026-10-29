// Pre-rotation: next-key commitments. The genesis commitment (`nextKeyDigests`, part of the history id), epochs whose
// commitment is fixed by the event that opens them, the rotation rules when the epoch being left has a commitment
// (revealed keys, proof of possession, the next commitment), the commitment-only rotation that gives an uncommitted
// epoch one (and the refusal of a rotation that keeps every key and commits nothing), the standalone checks a witness
// uses, and the owner API: the commitment at creation, commitNextKey, rotateOwnerKey / prepareOwnerKeyRotation /
// commitOwnerKeyRotation with the next-key files, every crash window of the three key files, and ownerKeyStatus.
// (Provenance: OWNER_NEXT_KEYS_COMMITTED, a separate commitment event, was removed by the coherence pass.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const signer = await import("../src/signer.ts");
const keys = await import("../src/owner-keys.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { replay } = await import("../src/replay.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const suites = await import("../src/crypto/suites.ts");
const { hashCanonical } = await import("../src/hash.ts");
const { createLocalOwner: createLocalOwnerDefault, openLocalOwner: openLocalOwnerDefault, verifyHistory, ownerKeyStatusOf, NEXT_KEY_ON_HOST_WARNING } = await import("../src/owner.ts");
// These tests cover the format-1 (and legacy) owner API; the API writes format 2 by default (SPEC §19), so format 1 is named for every handle and domain made here.
const createLocalOwner = (options) => createLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const openLocalOwner = (options) => openLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const { IronTrellisError } = await import("../src/input.ts");
const { capacityOf, assertCapacityTransition } = await import("../src/capacity.ts");
const types = await import("../src/types.ts");

const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: "deployment:pre-rotation" });
const seed = (n) => `0x${n.toString(16).padStart(64, "0")}`;
const pair = (id, n) => suites.keyPairFromPrivateKey("ed25519", id, seed(n));
const k1 = pair("owner:1", 0x6001), k2 = pair("owner:2", 0x6002), k3 = pair("owner:3", 0x6003), k4 = pair("owner:4", 0x6004), attacker = pair("owner:x", 0x6009);
const s1 = signer.signerFromKeyPair(k1), s2 = signer.signerFromKeyPair(k2), s3 = signer.signerFromKeyPair(k3), s4 = signer.signerFromKeyPair(k4), sx = signer.signerFromKeyPair(attacker);
const ok = (p) => ({ keyId: p.keyId, scheme: "ed25519", credential: p.credential });
const plain = (v) => JSON.parse(JSON.stringify(v));
const digest = (p) => keys.ownerKeyDigest(p);
const hasCode = (code) => (error) => error instanceof IronTrellisError && error.code === code;

/** The genesis (owner key k1), with the next-key commitment `digests` when given. */
const genesis = (digests) => ({
  id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
  data: {
    domain: DOMAIN, versions: { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: [ok(k1)], ...(digests === undefined ? {} : { nextKeyDigests: digests }),
    adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:pre", policyVersion: "policy:pre/1",
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:pre", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
  },
});
const principal = { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } };
const agent = (n) => ({ id: `agent:${n}`, type: "AGENT_CREATED", timestamp: 60 + n, data: { agentId: `agent:${n}`, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
const rotation = (id, ownerKeys, extra = {}) => ({ id, type: "OWNER_KEYS_ROTATED", timestamp: 50, data: { ownerKeys, ...extra } });

/** Sign `event` as the next event of `list` with `by` (and, for a pre-rotated rotation, the proofs by `reveal`); returns the extended list. */
async function extend(list, event, by, reveal = []) {
  const accepted = replay(list);
  assert.equal(accepted.status, "ACCEPTED", `${accepted.code} ${accepted.reason}`);
  // Timestamps never decrease: an event scripted earlier than the head takes the head's time.
  const timed = { ...event, timestamp: Math.max(event.timestamp, accepted.head.canonicalTime) };
  let signed = await signer.signControlEvent(by, timed, DOMAIN, accepted.head, "sha256");
  if (reveal.length > 0) {
    const challenge = events.controlAuthorizationHash({
      domain: DOMAIN, eventId: signed.id, eventType: signed.type, timestamp: signed.timestamp, previousHead: { hash: accepted.head.hash, position: accepted.head.position },
      effectHash: events.controlEffectHash(signed, "sha256"),
    }, "sha256");
    const proofs = await Promise.all(reveal.map(async ([keyId, s]) => ({ keyId, scheme: "ed25519", signature: await s.signHash(challenge) })));
    signed = { ...signed, data: { ...signed.data, nextKeyAuthorizations: proofs } };
  }
  return [...list, plain(signed)];
}
/** genesis (k1, committed to `to`) · principal (position 1). */
async function committed(to = [digest(k2)]) {
  return extend([genesis(to)], principal, s1);
}
/** genesis (k1, no commitment) · principal. */
const uncommitted = () => extend([genesis()], principal, s1);
const rejectedWith = (list, code, reasonPrefix) => {
  const result = replay(list);
  assert.equal(result.status, "REJECTED", "expected a rejection");
  assert.equal(result.code, code, result.reason);
  if (reasonPrefix !== undefined) assert.ok(result.reason.startsWith(reasonPrefix), result.reason);
  return result;
};

// ---------------------------------------------------------------- digest, vocabulary, schema

test("ownerKeyDigest: sha256 over {version, scheme, normalised credential}; the key id is not part of it", () => {
  const expected = hashCanonical({ version: "irontrellis-owner-key-digest/1", scheme: "ed25519", credential: k2.credential }, "sha256");
  assert.equal(keys.ownerKeyDigest(ok(k2)), expected);
  assert.equal(keys.OWNER_KEY_DIGEST_VERSION, "irontrellis-owner-key-digest/1");
  assert.equal(keys.ownerKeyDigest({ ...ok(k2), keyId: "anything" }), expected);
  assert.equal(keys.ownerKeyDigest({ scheme: "ed25519", credential: k2.credential.toUpperCase().replace("0X", "0x") }), expected);
  assert.notEqual(keys.ownerKeyDigest(ok(k3)), expected);
  const eth = suites.generateKeyPair("eip191-personal-sign-keccak256", "eth");
  assert.equal(keys.ownerKeyDigest({ scheme: eth.scheme, credential: eth.credential.toUpperCase().replace("0X", "0x") }), keys.ownerKeyDigest(eth));
});

test("the commitment is a genesis field (committed by the history id) or rides on a rotation: there is no separate commitment event type", () => {
  assert.equal(types.EVENT_TYPES.includes("OWNER_NEXT_KEYS_COMMITTED"), false);
  const unknown = events.validateEvent({ id: "c", type: "OWNER_NEXT_KEYS_COMMITTED", timestamp: 10, data: { nextKeyDigests: [digest(k2)] } }, "irontrellis-event/1", 3);
  assert.equal(unknown.code, "UNSUPPORTED_EVENT_TYPE");
  assert.ok(types.ALWAYS_ADMITTED_EVENT_TYPES.has("OWNER_KEYS_ROTATED"), "a rotation (a commitment-only one included) is always admitted");
  // The commitment changes the history id: the same genesis without it is another history.
  assert.notEqual(replay([genesis([digest(k2)])]).head.hash, replay([genesis()]).head.hash);
});

test("schema: nextKeyDigests (genesis and rotation) is 1..64 distinct lowercase hashes, never a genesis owner key; nextKeyAuthorizations 1..64 {keyId, scheme, signature} with one entry per key id", () => {
  const g = (digests) => events.validateEvent(genesis(digests), "irontrellis-event/1", 0);
  assert.equal(g([digest(k2)]).ok, true);
  assert.equal(g([digest(k2), digest(k3)]).ok, true);
  assert.equal(g([]).code, "EVENT_DATA_INVALID");
  assert.equal(g([digest(k2), digest(k2)]).code, "EVENT_DATA_INVALID");
  assert.equal(g([digest(k2).toUpperCase().replace("0X", "0x")]).code, "EVENT_DATA_INVALID");
  assert.equal(g(Array.from({ length: 65 }, (_, i) => `0x${i.toString(16).padStart(64, "0")}`)).code, "INVALID_INPUT", "the 64-member bound is a named limit");
  const clash = g([digest(k2), digest(k1)]);
  assert.equal(clash.code, "EVENT_DATA_INVALID", "a digest naming a genesis owner key could never be revealed");
  assert.match(clash.reason, /names owner key owner:1/);
  assert.equal(events.validateGenesis(genesis([digest(k1)]).data, "irontrellis-event/1").ok, false, "validateGenesis (stores, witnesses) refuses it too");
  const legacy = { ...genesis([digest(k2)]), data: { ...genesis([digest(k2)]).data } };
  assert.equal(events.validateEvent(legacy, "continuity-event/0.2", 0).ok, false, "legacy genesis has no such field");
  const v = (event) => events.validateEvent(event, "irontrellis-event/1", 3);
  const sig = `0x${"11".repeat(64)}`;
  assert.equal(v(rotation("r", [ok(k2)], { nextKeyDigests: [digest(k3)], nextKeyAuthorizations: [{ keyId: "owner:2", scheme: "ed25519", signature: sig }] })).ok, true);
  assert.equal(v(rotation("r", [ok(k2)], { nextKeyAuthorizations: [] })).code, "EVENT_DATA_INVALID");
  assert.equal(v(rotation("r", [ok(k2)], { nextKeyAuthorizations: [{ keyId: "owner:2", scheme: "ed25519", signature: `0x${"11".repeat(65)}` }] })).code, "EVENT_DATA_INVALID", "an ed25519 proof is 64 bytes");
  assert.equal(v(rotation("r", [ok(k2)], { nextKeyAuthorizations: [{ keyId: "owner:2", scheme: "ed25519", signature: sig }, { keyId: "owner:2", scheme: "ed25519", signature: sig }] })).code, "EVENT_DATA_INVALID");
  assert.equal(v(rotation("r", [ok(k2)], { nextKeyAuthorizations: [{ keyId: "owner:2", scheme: "ed25519", signature: sig, extra: true }] })).code, "EVENT_DATA_INVALID");
  assert.equal(v(rotation("r", [ok(k2)], { nextKeyDigests: [] })).code, "EVENT_DATA_INVALID");
  assert.equal(v(rotation("r", [ok(k2)], { nextKeyDigests: Array.from({ length: 65 }, (_, i) => `0x${i.toString(16).padStart(64, "0")}`) })).code, "INVALID_INPUT");
  // Another control event cannot carry the rotation-only fields (its schema is closed).
  assert.equal(v({ ...agent(1), data: { ...agent(1).data, nextKeyAuthorizations: [{ keyId: "owner:2", scheme: "ed25519", signature: sig }] } }).code, "EVENT_DATA_INVALID");
});

test("controlEffectHash leaves out both signatures over the challenge, and binds everything else (new keys and the next commitment)", () => {
  const base = rotation("r", [ok(k2)], { nextKeyDigests: [digest(k3)] });
  const hash = events.controlEffectHash(base, "sha256");
  const withSigs = { ...base, data: { ...base.data, controlAuthorization: { keyId: "owner:1", signature: "0x00" }, nextKeyAuthorizations: [{ keyId: "owner:2", scheme: "ed25519", signature: "0x00" }] } };
  assert.equal(events.controlEffectHash(withSigs, "sha256"), hash);
  assert.deepEqual(Object.keys(events.signedControlEffect(withSigs.data)).sort(), ["nextKeyDigests", "ownerKeys"]);
  assert.notEqual(events.controlEffectHash(rotation("r", [ok(k2)], { nextKeyDigests: [digest(k4)] }), "sha256"), hash);
  assert.notEqual(events.controlEffectHash(rotation("r", [ok(k3)], { nextKeyDigests: [digest(k3)] }), "sha256"), hash);
  // A rotation without the optional fields hashes its plain data.
  const plainRotation = rotation("r", [ok(k2)]);
  assert.equal(events.controlEffectHash(plainRotation, "sha256"), hashCanonical(plainRotation.data, "sha256"));
});

// ---------------------------------------------------------------- replay: where a commitment comes from

test("replay: the genesis commitment is epoch 0's, fixed from position 0; a history without one has an uncommitted epoch 0", async () => {
  const list = await committed([digest(k2), digest(k3)]);
  const accepted = replay(list);
  assert.equal(accepted.status, "ACCEPTED");
  assert.deepEqual(plain(accepted.state.ownerKeyEpochs), [{ fromPosition: 0, keys: [ok(k1)], nextKeyDigests: [digest(k2), digest(k3)] }]);
  assert.deepEqual(plain(replay(await uncommitted()).state.ownerKeyEpochs), [{ fromPosition: 0, keys: [ok(k1)] }]);
  // A genesis whose commitment names its own owner key is refused at position 0.
  rejectedWith([genesis([digest(k1)])], "EVENT_DATA_INVALID");
});

test("replay: a commitment-only rotation (every key kept, nextKeyDigests) gives an uncommitted epoch its commitment; without nextKeyDigests it changes nothing and is refused", async () => {
  const list = await extend(await uncommitted(), rotation("commit:1", [ok(k1)], { reason: "next-key commitment", nextKeyDigests: [digest(k2)] }), s1);
  const state = replay(list).state;
  assert.deepEqual(plain(state.ownerKeyEpochs), [{ fromPosition: 0, keys: [ok(k1)] }, { fromPosition: 3, keys: [ok(k1)], nextKeyDigests: [digest(k2)] }]);
  // The same key keeps signing; the committed key must reveal itself next time.
  const after = await extend(list, agent(1), s1);
  assert.equal(replay(after).status, "ACCEPTED");
  assert.equal(replay(await extend(after, rotation("r", [ok(k2)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:2", s2]])).status, "ACCEPTED");
  rejectedWith(await extend(after, rotation("r", [ok(attacker)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:x", sx]]), "TRANSITION_INVALID", "owner key rotation: new owner key owner:x is not one of the next keys");
  // Keeping every key without a commitment is a no-op rotation: refused.
  rejectedWith(await extend(await uncommitted(), rotation("noop", [ok(k1)]), s1), "TRANSITION_INVALID", "owner key rotation: a rotation that keeps every owner key changes nothing");
  // A two-key set in another order is still "every key kept".
  let two = await uncommitted();
  two = await extend(two, rotation("add", [ok(k1), ok(k2)]), s1);
  rejectedWith(await extend(two, rotation("noop", [ok(k2), ok(k1)]), s1), "TRANSITION_INVALID", "owner key rotation: a rotation that keeps every owner key changes nothing");
  assert.equal(replay(await extend(two, rotation("commit", [ok(k2), ok(k1)], { nextKeyDigests: [digest(k3)] }), s1)).status, "ACCEPTED");
  // Dropping a key (retiring it) without a commitment is a real change: accepted.
  assert.equal(replay(await extend(two, rotation("retire", [ok(k2)]), s1)).status, "ACCEPTED");
});

test("replay: an epoch's commitment is never replaced: a commitment-only rotation out of a committed epoch is refused (it reveals no committed key)", async () => {
  const list = await committed();
  // A leaked current key cannot replace the commitment, not even with the same digest.
  rejectedWith(await extend(list, rotation("commit:2", [ok(k1)], { nextKeyDigests: [digest(attacker)] }), s1), "TRANSITION_INVALID", "owner key rotation: the owner keys in force committed to next keys; the rotation must reveal");
  rejectedWith(await extend(list, rotation("commit:3", [ok(k1)], { nextKeyDigests: [digest(k2)] }), s1), "TRANSITION_INVALID", "owner key rotation: the owner keys in force committed to next keys; the rotation must reveal");
  // After a rotation that carries one, the new epoch is committed too.
  let carried = await uncommitted();
  carried = await extend(carried, rotation("rotation:1", [ok(k2)], { nextKeyDigests: [digest(k3)] }), s1);
  assert.deepEqual(plain(replay(carried).state.ownerKeyEpochs.at(-1).nextKeyDigests), [digest(k3)]);
  rejectedWith(await extend(carried, rotation("commit:1", [ok(k2)], { nextKeyDigests: [digest(k4)] }), s2), "TRANSITION_INVALID", "owner key rotation: the owner keys in force committed to next keys; the rotation must reveal");
  // Unsigned or signed by an unknown key: CONTROL_AUTHORIZATION_INVALID.
  rejectedWith(await extend(await uncommitted(), rotation("commit:x", [ok(k1)], { nextKeyDigests: [digest(k2)] }), sx), "CONTROL_AUTHORIZATION_INVALID");
});

test("replay: a commitment may not name a key the history already declared", async () => {
  const list = await uncommitted();
  rejectedWith(await extend(list, rotation("c", [ok(k1)], { nextKeyDigests: [digest(k1)] }), s1), "TRANSITION_INVALID", "owner key rotation: next-key digest");
  rejectedWith(await extend(list, rotation("c", [ok(k1)], { nextKeyDigests: [digest(k2), digest(k1)] }), s1), "TRANSITION_INVALID", "owner key rotation: next-key digest");
  rejectedWith(await extend(list, rotation("c", [ok(k2)], { nextKeyDigests: [digest(k1)] }), s1), "TRANSITION_INVALID", "owner key rotation: next-key digest");
});

// ---------------------------------------------------------------- replay: rotations out of a committed epoch

test("replay: a pre-rotated rotation (committed key revealed, proof of possession, next commitment) is accepted and chains", async () => {
  let list = await committed();
  list = await extend(list, rotation("rotation:1", [ok(k2)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:2", s2]]);
  list = await extend(list, agent(1), s2);
  list = await extend(list, rotation("rotation:2", [ok(k3)], { nextKeyDigests: [digest(k4)] }), s2, [["owner:3", s3]]);
  list = await extend(list, agent(2), s3);
  const result = replay(list);
  assert.equal(result.status, "ACCEPTED", result.reason);
  assert.deepEqual(plain(result.state.ownerKeyEpochs), [
    { fromPosition: 0, keys: [ok(k1)], nextKeyDigests: [digest(k2)] },
    { fromPosition: 3, keys: [ok(k2)], nextKeyDigests: [digest(k3)] },
    { fromPosition: 5, keys: [ok(k3)], nextKeyDigests: [digest(k4)] },
  ]);
  // The revealed key may take any fresh key id: the commitment covers the key, not its id.
  const renamed = await extend(await committed(), rotation("rotation:1", [{ ...ok(k2), keyId: "hsm:7" }], { nextKeyDigests: [digest(k3)] }), s1, [["hsm:7", s2]]);
  assert.equal(replay(renamed).status, "ACCEPTED");
  // A carried-over key plus a revealed one.
  const both = await extend(await committed(), rotation("rotation:1", [ok(k1), ok(k2)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:2", s2]]);
  assert.equal(replay(both).status, "ACCEPTED");
});

test("replay: the leaked current key alone cannot rotate a committed epoch, whatever it signs", async () => {
  const list = await committed();
  // To the attacker's own key, with the attacker's proof and a commitment of its own choosing.
  rejectedWith(await extend(list, rotation("r", [ok(attacker)], { nextKeyDigests: [digest(k4)] }), s1, [["owner:x", sx]]), "TRANSITION_INVALID", "owner key rotation: new owner key owner:x is not one of the next keys");
  // Revealing the committed public key without its private key: no valid proof.
  rejectedWith(await extend(list, rotation("r", [ok(k2)], { nextKeyDigests: [digest(k4)] }), s1), "TRANSITION_INVALID", "owner key rotation: no revealed next key signed");
  rejectedWith(await extend(list, rotation("r", [ok(k2)], { nextKeyDigests: [digest(k4)] }), s1, [["owner:2", sx]]), "TRANSITION_INVALID", "owner key rotation: next-key authorization by owner:2 does not verify");
  // Dropping keys without revealing any (here: keeping the current key only).
  rejectedWith(await extend(list, rotation("r", [ok(k1)], { nextKeyDigests: [digest(k4)] }), s1), "TRANSITION_INVALID", "owner key rotation: the owner keys in force committed to next keys; the rotation must reveal");
  // A rotation that ends the commitment chain.
  rejectedWith(await extend(list, rotation("r", [ok(k2)]), s1, [["owner:2", s2]]), "TRANSITION_INVALID", "owner key rotation: a pre-rotated rotation must commit");
});

test("replay: proofs must be by revealed keys, in their scheme, over this event; the signatures do not sign each other", async () => {
  const list = await committed();
  // A proof by a carried-over key names no revealed key.
  rejectedWith(await extend(list, rotation("r", [ok(k1), ok(k2)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:2", s2], ["owner:1", s1]]), "TRANSITION_INVALID", "owner key rotation: next-key authorization by owner:1 names no owner key");
  // A proof lifted from another event (same keys, another id) does not verify here.
  const good = await extend(list, rotation("r", [ok(k2)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:2", s2]]);
  const other = await extend(list, rotation("r-other", [ok(k2)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:2", s2]]);
  const lifted = structuredClone(other);
  lifted.at(-1).data.nextKeyAuthorizations = good.at(-1).data.nextKeyAuthorizations;
  rejectedWith(lifted, "TRANSITION_INVALID", "owner key rotation: next-key authorization by owner:2 does not verify");
  // Editing the next commitment after signing breaks the owner signature (it is bound), not the replay order.
  const edited = structuredClone(good);
  edited.at(-1).data.nextKeyDigests = [digest(k4)];
  rejectedWith(edited, "CONTROL_AUTHORIZATION_INVALID");
  // Swapping the proof for another valid-looking one by the same key over another challenge: the owner signature still verifies, the proof does not.
  const swapped = structuredClone(good);
  swapped.at(-1).data.nextKeyAuthorizations = [{ keyId: "owner:2", scheme: "ed25519", signature: await s2.signHash(`0x${"ab".repeat(32)}`) }];
  rejectedWith(swapped, "TRANSITION_INVALID", "owner key rotation: next-key authorization by owner:2 does not verify");
  // Removing the proofs is detected (not silently accepted as a non-pre-rotated rotation).
  const stripped = structuredClone(good);
  delete stripped.at(-1).data.nextKeyAuthorizations;
  rejectedWith(stripped, "TRANSITION_INVALID", "owner key rotation: no revealed next key signed");
  // The next commitment may not name a declared key (the new set's own key included).
  rejectedWith(await extend(list, rotation("r", [ok(k2)], { nextKeyDigests: [digest(k2)] }), s1, [["owner:2", s2]]), "TRANSITION_INVALID", "owner key rotation: next-key digest");
});

test("replay: an epoch without a commitment rotates freely; it may start one, and proofs, when present, must verify", async () => {
  const list = await uncommitted();
  assert.equal(replay(await extend(list, rotation("r", [ok(k2)]), s1)).status, "ACCEPTED");
  assert.equal(replay(await extend(list, rotation("r", [ok(k2)], { nextKeyDigests: [digest(k3)] }), s1)).status, "ACCEPTED");
  assert.equal(replay(await extend(list, rotation("r", [ok(k2)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:2", s2]])).status, "ACCEPTED");
  rejectedWith(await extend(list, rotation("r", [ok(k2)]), s1, [["owner:2", sx]]), "TRANSITION_INVALID", "owner key rotation: next-key authorization by owner:2 does not verify");
});

// ---------------------------------------------------------------- standalone checks (what a witness runs)

test("verifyRotationEvent returns preRotated, commitmentOnly and the new epoch's nextKeyDigests; a verifier without the commitment judges it not pre-rotated", async () => {
  const list = await committed();
  const extended = await extend(list, rotation("rotation:1", [ok(k2)], { nextKeyDigests: [digest(k3)] }), s1, [["owner:2", s2]]);
  const state = replay(list).state;
  const previousHead = { hash: state.head.hash, position: state.head.position };
  const verdict = keys.verifyRotationEvent(extended.at(-1), { domain: DOMAIN, previousHead, epochs: state.ownerKeyEpochs });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.preRotated, true);
  assert.equal(verdict.commitmentOnly, false);
  assert.deepEqual(verdict.nextKeyDigests, [digest(k3)]);
  assert.equal(verdict.fromPosition, 3);
  assert.deepEqual(plain(verdict.epochs.at(-1)), { fromPosition: 3, keys: [ok(k2)], nextKeyDigests: [digest(k3)] });
  // A verifier that does not know the genesis commitment: same rotation, not pre-rotated, still valid.
  const unaware = keys.verifyRotationEvent(extended.at(-1), { domain: DOMAIN, previousHead, epochs: [{ fromPosition: 0, keys: [ok(k1)] }] });
  assert.equal(unaware.ok, true);
  assert.equal(unaware.preRotated, false);
  // Without the proof: refused against the commitment, TRANSITION_INVALID.
  const stripped = structuredClone(extended.at(-1));
  delete stripped.data.nextKeyAuthorizations;
  const refused = keys.verifyRotationEvent(stripped, { domain: DOMAIN, previousHead, epochs: state.ownerKeyEpochs });
  assert.deepEqual([refused.ok, refused.code], [false, "TRANSITION_INVALID"]);
  // A plain rotation: preRotated false, no nextKeyDigests.
  const base = await uncommitted();
  const plainRotation = await extend(base, rotation("r", [ok(k2)]), s1);
  const baseState = replay(base).state;
  const plainVerdict = keys.verifyRotationEvent(plainRotation.at(-1), { domain: DOMAIN, previousHead: { hash: baseState.head.hash, position: 1 }, epochs: baseState.ownerKeyEpochs });
  assert.equal(plainVerdict.ok, true);
  assert.equal(plainVerdict.preRotated, false);
  assert.equal(Object.hasOwn(plainVerdict, "nextKeyDigests"), false);
  // A commitment-only rotation: same keys, commitmentOnly, the extended epochs.
  const commitOnly = await extend(base, rotation("commit", [ok(k1)], { nextKeyDigests: [digest(k2), digest(k3)] }), s1);
  const c = keys.verifyRotationEvent(commitOnly.at(-1), { domain: DOMAIN, previousHead: { hash: baseState.head.hash, position: 1 }, epochs: baseState.ownerKeyEpochs });
  assert.equal(c.ok, true, c.reason);
  assert.deepEqual([c.position, c.fromPosition, c.preRotated, c.commitmentOnly], [2, 3, false, true]);
  assert.deepEqual(plain(c.epochs), [{ fromPosition: 0, keys: [ok(k1)] }, { fromPosition: 3, keys: [ok(k1)], nextKeyDigests: [digest(k2), digest(k3)] }]);
  // Bad signature, wrong type, no head, no epochs.
  const genesisEpochs = [{ fromPosition: 0, keys: [ok(k1)] }];
  assert.equal(keys.verifyRotationEvent(commitOnly.at(-1), { domain: DOMAIN, previousHead: { hash: `0x${"00".repeat(32)}`, position: 1 }, epochs: genesisEpochs }).code, "CONTROL_AUTHORIZATION_INVALID");
  assert.equal(keys.verifyRotationEvent(list[1], { domain: DOMAIN, previousHead: { hash: replay([genesis()]).head.hash, position: 0 }, epochs: genesisEpochs }).code, "INVALID_INPUT", "a principal is not a rotation");
  assert.equal(keys.verifyRotationEvent(commitOnly.at(-1), { domain: DOMAIN, previousHead: null, epochs: genesisEpochs }).code, "INVALID_INPUT");
  assert.equal(keys.verifyRotationEvent(commitOnly.at(-1), { domain: DOMAIN, previousHead: { hash: baseState.head.hash, position: 1 }, epochs: [] }).code, "INVALID_INPUT");
});

test("verifyRotationEvent never drops a genesis commitment: a bare key set is refused, epochs from the genesis refuse the leaked-key re-commit", async () => {
  // The leaked current key (owner:1) of a genesis-committed epoch re-commits to a key of its choice.
  const list = await committed();
  const state = replay(list).state;
  const previousHead = { hash: state.head.hash, position: state.head.position };
  const leaked = await extend(list, rotation("leak", [ok(k1)], { nextKeyDigests: [digest(k3)] }), s1);
  assert.equal(replay(leaked).status, "REJECTED", "replay refuses it");
  // Seeded from the genesis (with its nextKeyDigests), the standalone check refuses it the same way.
  const seeded = [{ fromPosition: 0, keys: state.genesis.ownerKeys, nextKeyDigests: state.genesis.nextKeyDigests }];
  assert.ok(Array.isArray(seeded[0].nextKeyDigests) && seeded[0].nextKeyDigests.length > 0, "the genesis commits");
  const verdict = keys.verifyRotationEvent(leaked.at(-1), { domain: DOMAIN, previousHead, epochs: seeded });
  assert.deepEqual([verdict.ok, verdict.code], [false, "TRANSITION_INVALID"]);
  // The genesis key set alone, without its commitment, is not accepted as a shortcut.
  const bare = keys.verifyRotationEvent(leaked.at(-1), { domain: DOMAIN, previousHead, keys: state.genesis.ownerKeys });
  assert.deepEqual([bare.ok, bare.code], [false, "INVALID_INPUT"]);
});

// ---------------------------------------------------------------- key files

test("next-key files: same record as an owner key file under another version; neither loader accepts the other's file", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-next-key-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const nextPath = join(dir, "h.owner-next-key.json"), keyPath = join(dir, "h.owner-key.json");
  const next = signer.createNextOwnerKeyFile(nextPath, "owner:2");
  if (process.platform !== "win32") assert.equal(statSync(nextPath).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  const record = JSON.parse(readFileSync(nextPath, "utf8"));
  assert.deepEqual(Object.keys(record).sort(), ["credential", "keyId", "privateKey", "scheme", "version"]);
  assert.equal(record.version, signer.OWNER_NEXT_KEY_VERSION);
  assert.equal(signer.loadNextOwnerKeyFile(nextPath).credential, next.credential);
  assert.throws(() => signer.loadOwnerKeyFile(nextPath), (e) => e.code === "KEY_UNAVAILABLE" && /next-key file/.test(e.message));
  signer.createOwnerKeyFile(keyPath);
  assert.throws(() => signer.loadNextOwnerKeyFile(keyPath), (e) => e.code === "KEY_UNAVAILABLE" && /owner key file/.test(e.message));
  assert.throws(() => signer.createNextOwnerKeyFile(nextPath), (e) => e.code === "KEY_EXISTS");
  assert.deepEqual(readdirSync(dir).sort(), ["h.owner-key.json", "h.owner-next-key.json"], "no temporary file is left behind");
  const promoted = signer.promoteNextOwnerKeyFile(nextPath, join(dir, "promoted.json"), "owner:7");
  assert.equal(promoted.keyId, "owner:7");
  assert.equal(signer.loadOwnerKeyFile(join(dir, "promoted.json")).credential, next.credential);
  if (process.platform !== "win32") assert.equal(statSync(join(dir, "promoted.json")).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  writeFileSync(join(dir, "loose.json"), readFileSync(nextPath), { mode: 0o644 });
  if (process.platform !== "win32") assert.throws(() => signer.loadNextOwnerKeyFile(join(dir, "loose.json")), (e) => e.code === "KEY_UNAVAILABLE" && /0600/.test(e.message)); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  assert.equal(signer.nextOwnerKeyPathFor("/x/h.jsonl"), "/x/h.jsonl.owner-next-key.json");
  assert.equal(signer.pendingNextOwnerKeyPathFor("/x/h.jsonl"), "/x/h.jsonl.owner-next-key.pending.json");
});

// ---------------------------------------------------------------- owner API

const TD = { protocol: "irontrellis", version: "1", deploymentId: "pre-rotation-owner" };
async function setup(t, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-pre-rotation-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), owner: "operations", controller: "operator", now: () => (tick += 1), domain: TD, ...extra };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  const history = config.historyFile;
  const paths = { key: `${history}.owner-key.json`, pending: `${history}.owner-key.pending.json`, next: `${history}.owner-next-key.json`, pendingNext: `${history}.owner-next-key.pending.json` };
  return { owner, config, dir, history, paths };
}
const stateOf = (history) => openHistoryStore(history).state();
const keyAt = (path, load = signer.loadOwnerKeyFile) => load(path).credential;
/** Moves the next key off the host (here: another directory), as the operator should. */
const offline = (h) => { const to = join(h.dir, "..", `${h.dir.split("/").at(-1)}-usb.json`); renameSync(h.paths.next, to); h.t?.after(() => rmSync(to, { force: true })); return to; };

test("createLocalOwner commits a next key by default, in the genesis; the key file is 0600 and cannot be loaded as the owner key", async (t) => {
  const { owner, history, paths } = await setup(t);
  const list = owner.exportHistory();
  assert.deepEqual(list.map((e) => e.type), ["DEPLOYMENT_INITIALIZED", "PRINCIPAL_CREATED", "AGENT_CREATED"], "no separate commitment event");
  const next = signer.loadNextOwnerKeyFile(paths.next);
  assert.equal(next.keyId, "owner:2", "it proposes the next free owner:N");
  assert.deepEqual(list[0].data.nextKeyDigests, [keys.ownerKeyDigest(next)], "the genesis commits to it (part of the history id)");
  if (process.platform !== "win32") assert.equal(statSync(paths.next).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  assert.throws(() => signer.loadOwnerKeyFile(paths.next), (e) => e.code === "KEY_UNAVAILABLE");
  assert.deepEqual(stateOf(history).ownerKeyEpochs.map((e) => e.nextKeyDigests), [[keys.ownerKeyDigest(next)]]);
  // One write: the first pin already covers the commitment.
  assert.equal(verifyHistory(history).ok, true);
  const status = owner.ownerKeyStatus();
  assert.deepEqual([status.commitment.position, status.commitment.source, status.commitment.eventId], [0, "GENESIS", list[0].id]);
  assert.deepEqual([status.keyRotations, status.commitmentRotations], [0, 0]);
  assert.equal(status.nextKeyFile.state, "COMMITTED");
  assert.equal(status.nextKeyOnHost, true);
  assert.ok(status.warnings.some((w) => w.code === "NEXT_KEY_ON_HOST" && w.message.endsWith(NEXT_KEY_ON_HOST_WARNING)));
  assert.equal(NEXT_KEY_ON_HOST_WARNING, "move it offline; pre-rotation only protects you if the next key is not on this host");
});

test("createLocalOwner: nextKey false opts out; nextSigner commits to a given key without a file; an existing next-key file is KEY_EXISTS unless reused; a failed creation removes both key files", async (t) => {
  const none = await setup(t, { nextKey: false });
  assert.equal(none.owner.exportHistory()[2].type, "AGENT_CREATED");
  assert.equal(Object.hasOwn(none.owner.exportHistory()[0].data, "nextKeyDigests"), false);
  assert.equal(existsSync(none.paths.next), false);
  assert.equal(none.owner.ownerKeyStatus().commitment, null);
  assert.ok(none.owner.ownerKeyStatus().warnings.some((w) => w.code === "NO_NEXT_KEY_COMMITMENT"));
  const hsm = await setup(t, { nextSigner: s4 });
  assert.deepEqual(hsm.owner.exportHistory()[0].data.nextKeyDigests, [digest(k4)]);
  assert.equal(existsSync(hsm.paths.next), false);
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-pre-rotation-exists-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const historyFile = join(dir, "h.jsonl");
  const base = { historyFile, owner: "o", controller: "o", now: () => 5, domain: TD };
  const planted = signer.createNextOwnerKeyFile(`${historyFile}.owner-next-key.json`, "owner:9");
  await assert.rejects(createLocalOwner(base), hasCode("KEY_EXISTS"));
  assert.equal(existsSync(`${historyFile}.owner-key.json`), false, "the owner key made for the refused creation is removed");
  const reused = await createLocalOwner({ ...base, reuseExistingKey: true });
  assert.deepEqual(reused.exportHistory()[0].data.nextKeyDigests, [keys.ownerKeyDigest(planted)]);
  // A creation that fails after both files were made removes both.
  const failDir = mkdtempSync(join(tmpdir(), "irontrellis-pre-rotation-fail-"));
  t.after(() => rmSync(failDir, { recursive: true, force: true }));
  const failing = { ...base, historyFile: join(failDir, "h.jsonl"), witness: { witnesses: [{ url: "https://127.0.0.1:1/", verifierKey: "x+00000000+AQ==" }] } };
  await assert.rejects(createLocalOwner(failing));
  assert.deepEqual(readdirSync(failDir), []);
  await assert.rejects(createLocalOwner({ ...base, historyFile: join(failDir, "same.jsonl"), signer: s1, nextSigner: s1 }), hasCode("INVALID_INPUT"));
  assert.deepEqual(readdirSync(failDir), []);
  await assert.rejects(createLocalOwner({ ...base, historyFile: join(failDir, "both.jsonl"), nextKey: false, nextSigner: s4 }), hasCode("INVALID_INPUT"));
});

test("rotateOwnerKey with a commitment: refused without the next key (KEY_UNAVAILABLE) or with another key; the next key becomes the owner key and a fresh one is committed", async (t) => {
  const h = await setup(t);
  h.t = t;
  const oldKey = readFileSync(h.paths.key);
  const committedKey = signer.loadNextOwnerKeyFile(h.paths.next);
  const usb = offline(h);
  const status = h.owner.ownerKeyStatus();
  assert.equal(status.nextKeyFile, null);
  assert.deepEqual(status.warnings, [], "committed, and the next key is off the host");
  await assert.rejects(h.owner.rotateOwnerKey(), (e) => hasCode("KEY_UNAVAILABLE")(e) && /committed to a next key/.test(e.message));
  const stray = join(h.dir, "stray.json");
  signer.createNextOwnerKeyFile(stray);
  await assert.rejects(h.owner.rotateOwnerKey({ nextKeyFile: stray }), (e) => hasCode("KEY_UNAVAILABLE")(e) && /does not hold the next key/.test(e.message));
  await assert.rejects(h.owner.rotateOwnerKey({ nextKeyFile: h.paths.key }), hasCode("KEY_UNAVAILABLE"), "an owner key file is not a next-key file");
  await assert.rejects(h.owner.rotateOwnerKey({ newSigner: s3 }), hasCode("INVALID_INPUT"));
  await assert.rejects(h.owner.rotateOwnerKey({ nextKeyFile: usb, nextKey: false }), hasCode("INVALID_INPUT"));
  await assert.rejects(h.owner.rotateOwnerKey({ nextKeyFile: usb, nextSigner: s2 }), hasCode("INVALID_INPUT"));
  assert.equal(h.owner.exportHistory().length, 3, "nothing was recorded by the refusals");
  assert.deepEqual(readdirSync(h.dir).filter((n) => n.includes("pending")), [], "and nothing was left staged");
  const before = h.owner.verify().head;
  const result = await h.owner.rotateOwnerKey({ nextKeyFile: usb, reason: "drill" });
  assert.equal(result.preRotated, true);
  assert.equal(result.keyId, "owner:2");
  assert.equal(result.head.position, before.position + 1);
  assert.equal(result.keyFile, h.paths.key);
  assert.equal(result.nextKeyFile, h.paths.next);
  assert.equal(keyAt(h.paths.key), committedKey.credential, "the committed key is the owner key file now");
  assert.deepEqual(readFileSync(result.retiredKeyFile), oldKey);
  const fresh = signer.loadNextOwnerKeyFile(h.paths.next);
  assert.equal(fresh.keyId, "owner:3");
  assert.deepEqual(result.nextKeyDigests, [keys.ownerKeyDigest(fresh)]);
  const event = h.owner.exportHistory().at(-1);
  assert.deepEqual(event.data.nextKeyAuthorizations.map((p) => p.keyId), ["owner:2"]);
  assert.equal(event.data.controlAuthorization.keyId, "owner:1");
  assert.deepEqual(readdirSync(h.dir).filter((n) => n.includes("pending") || n.includes(".tmp-")), []);
  await h.owner.createAgent({ id: "alex" });
  assert.equal(h.owner.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:2");
  assert.equal(verifyHistory(h.history).ok, true);
  // The next rotation takes the default next-key file beside the history (here still on the host) and chains on.
  const again = await openLocalOwner(h.config).rotateOwnerKey();
  assert.equal(again.preRotated, true);
  assert.equal(again.keyId, "owner:3");
  assert.equal(signer.loadNextOwnerKeyFile(h.paths.next).keyId, "owner:4");
  assert.equal(verifyHistory(h.history).ok, true);
  assert.deepEqual(stateOf(h.history).ownerKeyEpochs.map((e) => e.keys.map((k) => k.keyId)), [["owner:1"], ["owner:2"], ["owner:3"]]);
});

test("rotateOwnerKey with a commitment: KMS signers (nextSigner, async; newNextSigner) and the stale next-key file", async (t) => {
  const h = await setup(t, { nextSigner: s2 });
  const asyncOf = (s) => Object.freeze({ keyId: s.keyId, scheme: s.scheme, credential: s.credential, signHash: s.signHash });
  await assert.rejects(h.owner.rotateOwnerKey({ nextSigner: asyncOf(s3) }), hasCode("KEY_UNAVAILABLE"));
  const result = await h.owner.rotateOwnerKey({ nextSigner: asyncOf(s2), newNextSigner: asyncOf(s3) });
  await h.owner.flush();
  assert.equal(result.preRotated, true);
  assert.equal(result.keyId, "owner:2");
  assert.deepEqual(result.nextKeyDigests, [digest(k3)]);
  assert.equal(result.nextKeyFile, undefined);
  assert.equal(existsSync(h.paths.key), false, "the retired key file is archived away (the new key is a caller's signer)");
  await h.owner.createAgent({ id: "alex" });
  await h.owner.flush();
  assert.equal(h.owner.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:2");
  // From a KMS key back to a key file: the committed next key s3 given as a file.
  const dir = h.dir;
  const file = join(dir, "k3.json");
  writeFileSync(file, `${JSON.stringify({ version: signer.OWNER_NEXT_KEY_VERSION, keyId: "owner:3", scheme: "ed25519", credential: k3.credential, privateKey: k3.privateKey })}\n`, { mode: 0o600 });
  const back = await h.owner.rotateOwnerKey({ nextKeyFile: file });
  assert.equal(back.keyFile, h.paths.key);
  assert.equal(keyAt(h.paths.key), k3.credential);
  assert.equal(existsSync(file), true, "a next-key file outside the history's directory is left alone");
  // Now: a stale copy of the revealed key beside the history (rotation with newNextSigner from the default path).
  const h2 = await setup(t);
  const revealed = signer.loadNextOwnerKeyFile(h2.paths.next);
  const done = await h2.owner.rotateOwnerKey({ newNextSigner: s4 });
  assert.equal(done.preRotated, true);
  assert.equal(keyAt(h2.paths.key), revealed.credential);
  assert.equal(existsSync(h2.paths.next), false, "the revealed key's next-key file is removed once the owner key file holds it");
  // A stale file reported by status.
  writeFileSync(h2.paths.next, `${JSON.stringify({ version: signer.OWNER_NEXT_KEY_VERSION, keyId: "x", scheme: "ed25519", credential: revealed.credential, privateKey: JSON.parse(readFileSync(h2.paths.key, "utf8")).privateKey })}\n`, { mode: 0o600 });
  assert.equal(h2.owner.ownerKeyStatus().nextKeyFile.state, "IN_FORCE");
  assert.ok(h2.owner.ownerKeyStatus().warnings.some((w) => w.code === "NEXT_KEY_STALE"));
});

test("rotateOwnerKey without a commitment: phase-B behaviour, and it starts one by default (nextKey false keeps it off)", async (t) => {
  const h = await setup(t, { nextKey: false });
  await assert.rejects(h.owner.rotateOwnerKey({ nextKeyFile: h.paths.next }), hasCode("INVALID_INPUT"));
  const off = await h.owner.rotateOwnerKey({ nextKey: false });
  assert.equal(off.preRotated, false);
  assert.equal(off.nextKeyDigests, undefined);
  assert.equal(existsSync(h.paths.next), false);
  const on = await h.owner.rotateOwnerKey();
  assert.equal(on.preRotated, false);
  assert.equal(signer.loadNextOwnerKeyFile(h.paths.next).keyId, "owner:4");
  assert.deepEqual(on.nextKeyDigests, [keys.ownerKeyDigest(signer.loadNextOwnerKeyFile(h.paths.next))]);
  assert.equal((await h.owner.rotateOwnerKey()).preRotated, true);
  assert.equal(verifyHistory(h.history).ok, true);
});

test("commitNextKey: a commitment-only rotation (the owner keys unchanged), once per epoch; KEY_EXISTS for a stray next-key file; nextSigner, nextPublicKey", async (t) => {
  const h = await setup(t, { nextKey: false });
  signer.createNextOwnerKeyFile(h.paths.next, "stray");
  await assert.rejects(h.owner.commitNextKey(), hasCode("KEY_EXISTS"));
  rmSync(h.paths.next);
  await assert.rejects(h.owner.commitNextKey({ nextSigner: signer.loadOwnerKeyFile(h.paths.key) }), hasCode("INVALID_INPUT"), "not a declared key");
  await assert.rejects(h.owner.commitNextKey({ other: 1 }), hasCode("INVALID_INPUT"));
  const current = h.owner.ownerKeyStatus().ownerKeys;
  const result = await h.owner.commitNextKey();
  const next = signer.loadNextOwnerKeyFile(h.paths.next);
  assert.equal(result.nextKeyFile, h.paths.next);
  assert.equal(result.keyId, "owner:2");
  assert.deepEqual(result.nextKeyDigests, [keys.ownerKeyDigest(next)]);
  const event = h.owner.exportHistory().at(-1);
  assert.equal(event.type, "OWNER_KEYS_ROTATED");
  assert.equal(event.id, result.eventId);
  assert.deepEqual(plain(event.data.ownerKeys), plain(current), "every owner key kept");
  assert.equal(event.data.reason, "next-key commitment");
  assert.equal(Object.hasOwn(event.data, "nextKeyAuthorizations"), false);
  assert.equal(existsSync(h.paths.pendingNext), false);
  const status = h.owner.ownerKeyStatus();
  assert.deepEqual([status.commitment.source, status.commitment.position, status.keyRotations, status.commitmentRotations], ["COMMITMENT", result.head.position, 0, 1]);
  assert.equal(status.nextKeyFile.state, "COMMITTED");
  assert.equal(signer.loadOwnerKeyFile(h.paths.key).keyId, "owner:1", "the owner key file is untouched");
  await h.owner.createAgent({ id: "after-commit" });
  assert.equal(h.owner.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:1", "the same key keeps signing");
  await assert.rejects(h.owner.commitNextKey(), (e) => hasCode("TRANSITION_REJECTED")(e) && /already have a next-key commitment/.test(e.message));
  await assert.rejects(h.owner.commitNextKey({ nextSigner: s4 }), hasCode("TRANSITION_REJECTED"));
  assert.equal((await h.owner.rotateOwnerKey()).preRotated, true);
  // With a signer, on a fresh history.
  const k = await setup(t, { nextKey: false });
  const viaSigner = await k.owner.commitNextKey({ nextSigner: s4 });
  assert.deepEqual(viaSigner.nextKeyDigests, [digest(k4)]);
  assert.equal(viaSigner.nextKeyFile, undefined);
  const p = await setup(t, { nextKey: false });
  const viaPublicKey = await p.owner.commitNextKey({ nextPublicKey: k3.credential, reason: "offline key" });
  assert.deepEqual([viaPublicKey.nextKeyDigests, viaPublicKey.keyId], [[digest(k3)], "owner:2"]);
  assert.equal(p.owner.exportHistory().at(-1).data.reason, "offline key");
  await assert.rejects(p.owner.commitNextKey({ nextPublicKey: k4.credential }), hasCode("TRANSITION_REJECTED"), "already committed");
  const q = await setup(t, { nextKey: false });
  await assert.rejects(q.owner.commitNextKey({ nextPublicKey: "not a key" }), hasCode("INVALID_INPUT"));
  // Legacy histories have no owner keys.
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-pre-rotation-legacy-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const legacy = await createLocalOwner({
    historyFile: join(dir, "legacy.jsonl"), owner: "operations", controller: "operator", now: () => 100, format: "continuity-event/0.2", [FORMAT1_TEST_TOOLING]: true,
    domain: { protocol: "continuity", version: "0.2", deploymentId: "pre-legacy", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000000" },
  });
  assert.deepEqual(legacy.exportHistory().map((e) => e.type), ["DEPLOYMENT_INITIALIZED", "PRINCIPAL_CREATED"], "no commitment in a legacy history");
  await assert.rejects(legacy.commitNextKey(), hasCode("INVALID_INPUT"));
  assert.equal(legacy.ownerKeyStatus().commitment, null);
});

test("commitments and rotations are always admitted, even when the history is full", async (t) => {
  const h = await setup(t, { nextKey: false, maxEvents: 3 });
  await assert.rejects(h.owner.createAgent({ id: "alex" }), (e) => e.code.startsWith("CAPACITY"));
  await h.owner.commitNextKey();
  assert.equal((await h.owner.rotateOwnerKey({ reason: "full" })).preRotated, true);
  assert.equal(capacityOf(stateOf(h.history)).mode, "CONTROL_ONLY");
  assert.doesNotThrow(() => assertCapacityTransition(stateOf(h.history), [rotation("c", [ok(k4)], { nextKeyDigests: [digest(k3)] })]));
});

// ---------------------------------------------------------------- prepare / commit

test("prepareOwnerKeyRotation computes the head in memory and appends nothing; commitOwnerKeyRotation appends exactly that event, once", async (t) => {
  const h = await setup(t);
  const before = h.owner.exportHistory().length;
  const prepared = await h.owner.prepareOwnerKeyRotation({ reason: "two-phase" });
  assert.equal(h.owner.exportHistory().length, before, "nothing appended");
  assert.equal(prepared.previousHead.position, before - 1);
  assert.equal(prepared.head.position, before);
  assert.equal(prepared.head.canonicalTime, prepared.event.timestamp);
  assert.equal(prepared.preRotated, true);
  assert.equal(prepared.signedBy, "owner:1");
  assert.deepEqual(prepared.files, { pendingKeyFile: h.paths.pending, pendingNextKeyFile: h.paths.pendingNext, nextKeySource: h.paths.next });
  assert.ok(existsSync(h.paths.pending) && existsSync(h.paths.pendingNext));
  // The prepared event verifies standalone against the prepared previous head (what a witness will be given).
  const state = stateOf(h.history);
  const verdict = keys.verifyRotationEvent(plain(prepared.event), { domain: TD, previousHead: prepared.previousHead, epochs: state.ownerKeyEpochs });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.preRotated, true);
  assert.equal(Object.isFrozen(prepared), true);
  const result = await h.owner.commitOwnerKeyRotation(prepared);
  assert.deepEqual(result.head, prepared.head, "the appended head is the prepared head");
  assert.deepEqual(plain(h.owner.exportHistory().at(-1)), plain(prepared.event));
  await assert.rejects(h.owner.commitOwnerKeyRotation(prepared), hasCode("INVALID_INPUT"), "a prepared rotation is committed once");
  await assert.rejects(h.owner.commitOwnerKeyRotation({ ...prepared }), hasCode("INVALID_INPUT"), "only this handle's own prepared record");
  assert.equal(verifyHistory(h.history).ok, true);
});

test("prepare/commit: a history that moved in between is HISTORY_CONFLICT and the staged files go; staged files removed by another process: KEY_UNAVAILABLE, nothing appended", async (t) => {
  const h = await setup(t);
  const nextKey = readFileSync(h.paths.next);
  const prepared = await h.owner.prepareOwnerKeyRotation();
  await h.owner.createAgent({ id: "alex" });
  await assert.rejects(h.owner.commitOwnerKeyRotation(prepared), hasCode("HISTORY_CONFLICT"));
  assert.equal(existsSync(h.paths.pending), false);
  assert.equal(existsSync(h.paths.pendingNext), false);
  assert.deepEqual(readFileSync(h.paths.next), nextKey, "the committed next key is untouched");
  // Another process opens the history between prepare and commit: it removes staged files no epoch declares.
  const again = await h.owner.prepareOwnerKeyRotation();
  openLocalOwner(h.config);
  assert.equal(existsSync(h.paths.pending), false);
  const length = h.owner.exportHistory().length;
  await assert.rejects(h.owner.commitOwnerKeyRotation(again), (e) => hasCode("KEY_UNAVAILABLE")(e) && /nothing was recorded/.test(e.message));
  assert.equal(h.owner.exportHistory().length, length);
  // A prepared rotation that is simply dropped: the next rotation settles its files and proceeds.
  await h.owner.prepareOwnerKeyRotation();
  const done = await h.owner.rotateOwnerKey();
  assert.equal(done.preRotated, true);
  assert.equal(verifyHistory(h.history).ok, true);
});

// ---------------------------------------------------------------- crash windows (three key files: current, next, retired)

/**
 * Brings a history to one crash window of a pre-rotated rotation: the rotation is prepared (Kp and Np staged), then
 * `crash` edits files and history as the process would have left them. Returns what recovery must produce.
 */
async function crashAt(t, crash) {
  const h = await setup(t);
  const A = signer.loadOwnerKeyFile(h.paths.key), B = signer.loadNextOwnerKeyFile(h.paths.next);
  const prepared = await h.owner.prepareOwnerKeyRotation();
  const C = signer.loadNextOwnerKeyFile(h.paths.pendingNext);
  h.owner.close();
  const record = () => {
    const store = openHistoryStore(h.history, { signer: A });
    store.append(structuredClone(plain(prepared.event)));
    store.close();
  };
  await crash({ h, record, A, B, C, prepared });
  return { h, A, B, C, prepared };
}
const retiredPath = (h) => `${h.history}.owner-key.owner_1.retired.json`;
const assertRolledBack = ({ h, A, B }) => {
  const owner = openLocalOwner(h.config);
  assert.equal(existsSync(h.paths.pending), false);
  assert.equal(existsSync(h.paths.pendingNext), false);
  assert.equal(keyAt(h.paths.key), A.credential);
  assert.equal(keyAt(h.paths.next, signer.loadNextOwnerKeyFile), B.credential);
  assert.equal(owner.exportHistory().at(-1).type, "AGENT_CREATED");
  return owner;
};
const assertCompleted = async ({ h, A, B, C }) => {
  const owner = openLocalOwner(h.config);
  assert.equal(existsSync(h.paths.pending), false);
  assert.equal(existsSync(h.paths.pendingNext), false);
  assert.equal(keyAt(h.paths.key), B.credential, "current: the revealed key");
  assert.equal(keyAt(h.paths.next, signer.loadNextOwnerKeyFile), C.credential, "next: the fresh committed key");
  assert.equal(keyAt(retiredPath(h)), A.credential, "retired: the old key");
  await owner.createAgent({ id: "after-crash" });
  assert.equal(owner.exportHistory().at(-1).data.controlAuthorization.keyId, "owner:2");
  assert.equal(verifyHistory(h.history).ok, true);
  assert.equal(owner.ownerKeyStatus().nextKeyFile.state, "COMMITTED");
  return owner;
};

test("crash window 1: only the owner key was staged (Kp), nothing recorded → the next open removes it; the next key is untouched", async (t) => {
  const s = await crashAt(t, ({ h }) => { rmSync(h.paths.pendingNext); });
  const owner = assertRolledBack(s);
  assert.equal((await owner.rotateOwnerKey()).preRotated, true, "the rotation can be run again");
});

test("crash window 2: both keys staged (Kp, Np), nothing recorded → both removed", async (t) => {
  const s = await crashAt(t, () => {});
  const owner = assertRolledBack(s);
  assert.equal((await owner.rotateOwnerKey()).preRotated, true);
  assert.equal(verifyHistory(s.h.history).ok, true);
});

test("crash window 3: the rotation recorded, no file moved → the open archives the old key, installs the revealed one, then the fresh next key", async (t) => {
  await assertCompleted(await crashAt(t, ({ record }) => record()));
});

test("crash window 4: recorded and the old key archived, the staged owner key not yet moved", async (t) => {
  await assertCompleted(await crashAt(t, ({ h, record }) => { record(); copyFileSync(h.paths.key, retiredPath(h)); }));
});

test("crash window 5: recorded, the owner key file swapped, the fresh next key still pending (the next-key file still holds the revealed key)", async (t) => {
  const s = await crashAt(t, ({ h, record }) => { record(); copyFileSync(h.paths.key, retiredPath(h)); renameSync(h.paths.pending, h.paths.key); });
  assert.equal(ownerKeyStatusOf(s.h.history, stateOf(s.h.history)).nextKeyFile.state, "IN_FORCE", "before recovery: a stale copy");
  await assertCompleted(s);
});

test("crash window 6: every file in place (the last rename done), nothing left to settle", async (t) => {
  await assertCompleted(await crashAt(t, ({ h, record }) => {
    record(); copyFileSync(h.paths.key, retiredPath(h)); renameSync(h.paths.pending, h.paths.key); renameSync(h.paths.pendingNext, h.paths.next);
  }));
});

test("crash window 7: recorded while the revealed key came from outside the directory (next-key file already offline)", async (t) => {
  const h = await setup(t);
  const A = signer.loadOwnerKeyFile(h.paths.key), B = signer.loadNextOwnerKeyFile(h.paths.next);
  const usb = join(h.dir, "usb-next.json");
  renameSync(h.paths.next, usb);
  const prepared = await h.owner.prepareOwnerKeyRotation({ nextKeyFile: usb });
  const C = signer.loadNextOwnerKeyFile(h.paths.pendingNext);
  h.owner.close();
  const store = openHistoryStore(h.history, { signer: A });
  store.append(structuredClone(plain(prepared.event)));
  store.close();
  await assertCompleted({ h, A, B, C });
});

test("crash windows of commitNextKey: staged but not recorded → removed; recorded but not moved → moved into place", async (t) => {
  const h = await setup(t, { nextKey: false });
  const A = signer.loadOwnerKeyFile(h.paths.key);
  const staged = signer.createNextOwnerKeyFile(h.paths.pendingNext, "owner:2");
  openLocalOwner(h.config);
  assert.equal(existsSync(h.paths.pendingNext), false, "never recorded: removed");
  const again = signer.createNextOwnerKeyFile(h.paths.pendingNext, "owner:2");
  const store = openHistoryStore(h.history, { signer: A });
  store.append(plain(await signer.signControlEvent(A, { ...rotation("commit:crash", [ok(A)], { nextKeyDigests: [keys.ownerKeyDigest(again)] }), timestamp: store.head().canonicalTime }, TD, store.head(), "sha256")));
  store.close();
  const owner = openLocalOwner(h.config);
  assert.equal(existsSync(h.paths.pendingNext), false);
  assert.equal(keyAt(h.paths.next, signer.loadNextOwnerKeyFile), again.credential);
  assert.notEqual(staged.credential, again.credential);
  assert.equal(owner.ownerKeyStatus().nextKeyFile.state, "COMMITTED");
  assert.equal((await owner.rotateOwnerKey()).preRotated, true);
  // Handles with a caller's signer settle the next-key files too.
  const k = await setup(t, { nextKey: false, signer: s1 });
  const pending = signer.createNextOwnerKeyFile(k.paths.pendingNext, "owner:2");
  const kstore = openHistoryStore(k.history, { signer: s1 });
  kstore.append(plain(await signer.signControlEvent(s1, { ...rotation("commit:kms", [ok(s1)], { nextKeyDigests: [keys.ownerKeyDigest(pending)] }), timestamp: kstore.head().canonicalTime }, TD, kstore.head(), "sha256")));
  kstore.close();
  openLocalOwner(k.config);
  assert.equal(keyAt(k.paths.next, signer.loadNextOwnerKeyFile), pending.credential);
});

test("a next-key file holding a key the history never declared is never overwritten: the rotation refuses (KEY_EXISTS) until it is moved", async (t) => {
  const h = await setup(t, { nextKey: false });
  const stray = signer.createNextOwnerKeyFile(h.paths.next, "stray");
  await assert.rejects(h.owner.rotateOwnerKey(), (e) => hasCode("KEY_EXISTS")(e) && /never declared/.test(e.message));
  assert.equal(keyAt(h.paths.next, signer.loadNextOwnerKeyFile), stray.credential);
  assert.equal(h.owner.exportHistory().at(-1).type, "AGENT_CREATED", "nothing recorded");
  assert.equal(h.owner.ownerKeyStatus().nextKeyFile.state, "UNCOMMITTED");
  // Without a staged next key (nextKey false, or newNextSigner) the file is not in the way.
  assert.equal((await h.owner.rotateOwnerKey({ nextKey: false })).preRotated, false);
  rmSync(h.paths.next);
  assert.equal((await h.owner.rotateOwnerKey()).nextKeyFile, h.paths.next);
});

test("recovery never overwrites a next-key file that holds the committed key or a key the history never declared", async (t) => {
  const h = await setup(t);
  // A pending next key that some epoch committed to but is not the current commitment, beside the committed key: left alone.
  const committedKey = readFileSync(h.paths.next);
  signer.createNextOwnerKeyFile(h.paths.pendingNext, "stray");
  openLocalOwner(h.config);
  assert.equal(existsSync(h.paths.pendingNext), false, "an uncommitted pending key is removed");
  assert.deepEqual(readFileSync(h.paths.next), committedKey);
  // Unreadable pending files are left for the operator, and block a rotation with KEY_EXISTS.
  writeFileSync(h.paths.pendingNext, "{", { mode: 0o600 });
  const owner = openLocalOwner(h.config);
  assert.equal(existsSync(h.paths.pendingNext), true);
  await assert.rejects(owner.rotateOwnerKey(), hasCode("KEY_EXISTS"));
  assert.ok(owner.ownerKeyStatus().pending.includes(h.paths.pendingNext));
  rmSync(h.paths.pendingNext);
  assert.equal((await owner.rotateOwnerKey()).preRotated, true);
});
