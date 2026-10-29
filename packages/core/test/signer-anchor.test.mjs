// Owner signer (key file, control-event signing, head attestations) and
// anchoring (local, http and rekor witnesses with injected fetch, the
// ANCHOR_RECORDED event, end-to-end anchoring through the store and verify()).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { appendFileSync, chmodSync, copyFileSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fixturePath } from "./reference.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const signer = await import("../src/signer.ts");
const anchor = await import("../src/anchor.ts");
const { createHistoryStore: createHistoryStoreStrict, openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const createHistoryStore = (path, events, options = {}) => createHistoryStoreStrict(path, events, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { applyEvent, createReplayState, replay } = await import("../src/replay.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const suites = await import("../src/crypto/suites.ts");
const { hashCanonical, sha256Hex } = await import("../src/hash.ts");

const TRELLIS = "irontrellis-event/1";
const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: "deployment:anchor-test" });
const owner = suites.generateKeyPair("ed25519", "owner:anchor");
const local = signer.signerFromKeyPair(owner);
const ownerKeys = [{ keyId: owner.keyId, scheme: "ed25519", credential: owner.credential }];
const genesisEvent = () => ({
  id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
  data: {
    domain: DOMAIN, versions: { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys,
    adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:anchor", policyVersion: "policy:anchor/1",
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:anchor", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
  },
});
const principalEvent = { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } };
const agentEvent = (n) => ({ id: `agent:${n}`, type: "AGENT_CREATED", timestamp: n + 2, data: { agentId: `agent:${n}`, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
const workspace = (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-anchor-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const code = async (fn, expected) => {
  try { await fn(); } catch (error) { assert.equal(error.code, expected, error.message); return error; }
  assert.fail(`expected ${expected}`);
};
const trellisStore = async (path, agents, options = {}) => {
  const store = createHistoryStore(path, [genesisEvent()], { signer: local, ...options });
  store.append(await signer.signControlEvent(local, principalEvent, DOMAIN, store.head(), "sha256"));
  for (let n = 0; n < agents; n += 1) store.append(await signer.signControlEvent(local, agentEvent(n), DOMAIN, store.head(), "sha256"));
  return store;
};

// ---------------------------------------------------------------- signer

test("owner key file: create (0600, exclusive), load, and every defect is KEY_UNAVAILABLE", async (t) => {
  const dir = workspace(t);
  const path = signer.ownerKeyPathFor(join(dir, "history.jsonl"));
  assert.equal(path, join(dir, "history.jsonl.owner-key.json"));
  const created = signer.createOwnerKeyFile(path, "owner:file");
  if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  const record = JSON.parse(readFileSync(path, "utf8"));
  assert.equal(record.version, signer.OWNER_KEY_VERSION);
  assert.deepEqual([record.keyId, record.scheme, record.credential], ["owner:file", "ed25519", created.credential]);
  assert.match(record.privateKey, /^0x[0-9a-f]{64}$/);
  await code(() => signer.createOwnerKeyFile(path), "KEY_EXISTS");
  const loaded = signer.loadOwnerKeyFile(path);
  assert.deepEqual([loaded.keyId, loaded.scheme, loaded.credential], [created.keyId, created.scheme, created.credential]);
  const hash = hashCanonical({ probe: 1 }, "sha256");
  assert.equal(await loaded.signHash(hash), await created.signHash(hash));
  assert.equal(loaded.signHashSync(hash), await created.signHash(hash), "sync and async signing agree (Ed25519 is deterministic)");
  assert.equal(suites.suiteFor("ed25519").verify(hash, loaded.signHashSync(hash), loaded.credential), true);
  await code(() => signer.loadOwnerKeyFile(join(dir, "missing.json")), "KEY_UNAVAILABLE");
  // Each defect is written with the right mode, so the refusal is about the content.
  const privately = (name, text) => { writeFileSync(join(dir, name), text, { mode: 0o600 }); return join(dir, name); };
  for (const [name, text, why] of [["bad1.json", "not json", /unreadable/], ["bad2.json", JSON.stringify({ ...record, version: "other" }), /malformed/],
    ["bad3.json", JSON.stringify({ ...record, credential: owner.credential }), /does not match/], ["bad4.json", JSON.stringify({ ...record, privateKey: "0x12" }), /invalid/]]) {
    const error = await code(() => signer.loadOwnerKeyFile(privately(name, text)), "KEY_UNAVAILABLE");
    assert.match(error.message, why);
  }
  // An eip191 signer from a key pair has no sync path.
  const secp = signer.signerFromKeyPair(suites.generateKeyPair("eip191-personal-sign-keccak256", "owner:secp"));
  assert.equal(secp.signHashSync, undefined);
  assert.equal(suites.suiteFor(secp.scheme).verify(hash, await secp.signHash(hash), secp.credential), true);
});

test("signControlEvent binds the event to its predecessor head and matches a hand-built signature", async () => {
  const state = createReplayState(TRELLIS);
  assert.equal(applyEvent(state, genesisEvent()).ok, true);
  const genesisHead = state.head;
  const signed = await signer.signControlEvent(local, principalEvent, DOMAIN, genesisHead, "sha256");
  assert.deepEqual(Object.keys(signed.data), ["principalId", "controlAuthorization"]);
  assert.equal(signed.data.controlAuthorization.keyId, owner.keyId);
  const manual = await suites.signHashWith(owner)(events.controlAuthorizationHash({
    domain: DOMAIN, eventId: "principal", eventType: "PRINCIPAL_CREATED", timestamp: 1,
    previousHead: { hash: state.head.hash, position: 0 }, effectHash: hashCanonical(principalEvent.data, "sha256"),
  }, "sha256"));
  assert.equal(signed.data.controlAuthorization.signature, manual);
  assert.equal(applyEvent(state, signed).ok, true);
  // Re-signing an already signed event replaces the authorization rather than nesting it.
  const again = await signer.signControlEvent(local, signed, DOMAIN, genesisHead, "sha256");
  assert.equal(again.data.controlAuthorization.signature, manual);
  // Signed for the wrong predecessor: rejected by replay.
  const moved = await signer.signControlEvent(local, agentEvent(0), DOMAIN, { hash: state.eventHistoryHashes[0], position: 0, canonicalTime: 0 }, "sha256");
  assert.equal(applyEvent(state, moved).code, "CONTROL_AUTHORIZATION_INVALID");
  const right = await signer.signControlEvent(local, agentEvent(0), DOMAIN, state.head, "sha256");
  assert.equal(applyEvent(state, right).ok, true);
  // A key the genesis does not declare signs a valid-looking event that replay rejects.
  const stranger = signer.signerFromKeyPair(suites.generateKeyPair("ed25519", "owner:stranger"));
  const foreign = await signer.signControlEvent(stranger, agentEvent(1), DOMAIN, state.head, "sha256");
  assert.equal(applyEvent(state, foreign).code, "CONTROL_AUTHORIZATION_INVALID");
});

test("head attestations: sync and async agree; verification rejects other domains, keys, heads and malformed input", async () => {
  const head = { hash: sha256Hex(Buffer.from("head")), position: 7, canonicalTime: 99 };
  const attestation = await signer.attestHead(local, DOMAIN, head, "sha256");
  assert.deepEqual(signer.attestHeadSync(local, DOMAIN, head, "sha256"), attestation);
  assert.equal(attestation.version, "irontrellis-head-attestation/1");
  assert.deepEqual(attestation.head, head);
  assert.equal(attestation.keyId, owner.keyId);
  assert.equal(attestation.scheme, "ed25519");
  assert.equal(signer.verifyHeadAttestation(attestation, DOMAIN, ownerKeys, "sha256"), true);
  assert.equal(signer.verifyHeadAttestation(attestation, { ...DOMAIN, deploymentId: "other" }, ownerKeys, "sha256"), false);
  assert.equal(signer.verifyHeadAttestation(attestation, DOMAIN, [], "sha256"), false);
  assert.equal(signer.verifyHeadAttestation(attestation, DOMAIN, ownerKeys, "keccak256"), false);
  assert.equal(signer.verifyHeadAttestation({ ...attestation, head: { ...head, position: 8 } }, DOMAIN, ownerKeys, "sha256"), false);
  assert.equal(signer.verifyHeadAttestation({ ...attestation, signature: `0x${"00".repeat(64)}` }, DOMAIN, ownerKeys, "sha256"), false);
  assert.equal(signer.verifyHeadAttestation({ ...attestation, keyId: "other" }, DOMAIN, ownerKeys, "sha256"), false);
  assert.equal(signer.verifyHeadAttestation(null, DOMAIN, ownerKeys, "sha256"), false);
  assert.equal(signer.verifyHeadAttestation({ ...attestation, head: "x" }, DOMAIN, ownerKeys, "sha256"), false);
  // Extra head fields are ignored by the hash (the attested head is exactly {hash, position, canonicalTime}).
  const wide = await signer.attestHead(local, DOMAIN, { ...head, extra: true }, "sha256");
  assert.equal(wide.signature, attestation.signature);
  // A secp256k1 owner key attests too (async only).
  const secp = suites.generateKeyPair("eip191-personal-sign-keccak256", "owner:secp");
  const secpAttestation = await signer.attestHead(signer.signerFromKeyPair(secp), DOMAIN, head, "sha256");
  assert.equal(signer.verifyHeadAttestation(secpAttestation, DOMAIN, [{ keyId: secp.keyId, scheme: secp.scheme, credential: secp.credential }], "sha256"), true);
  assert.equal(signer.attestHeadSync(signer.signerFromKeyPair(secp), DOMAIN, head, "sha256"), undefined);
});

test("owner key file: a key readable by group or others is refused with the required mode (POSIX)", { skip: process.platform === "win32" && "no POSIX modes" }, async (t) => {
  const dir = workspace(t);
  const path = join(dir, "h.jsonl.owner-key.json");
  signer.createOwnerKeyFile(path);
  for (const mode of [0o644, 0o640, 0o604, 0o660, 0o666]) {
    chmodSync(path, mode);
    const error = await code(() => signer.loadOwnerKeyFile(path), "KEY_UNAVAILABLE");
    assert.match(error.message, /must be mode 0600/);
    assert.ok(error.message.includes(`0${mode.toString(8)}`), error.message);
    assert.equal(error.detail.requiredMode, 0o600);
  }
  for (const mode of [0o600, 0o400]) {
    chmodSync(path, mode);
    assert.equal(signer.loadOwnerKeyFile(path).keyId, "owner:1");
  }
});

// ---------------------------------------------------------------- anchoring

test("local anchor log end to end: ANCHOR_RECORDED replays, verify() shows PREFIX_OK, the anchor log verifies the receipt", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "history.jsonl"), 2);
  const witness = anchor.localAnchorLog(`${store.path}.anchors`);
  assert.equal(witness.kind, "local");
  assert.equal(witness.name, "local-head-file");
  assert.equal(anchor.anchorsPathFor(store.path), `${store.path}.anchors`);
  assert.equal(witness.location, `${store.path}.anchors`);
  const context = { domain: DOMAIN, algorithm: "sha256", ownerKeys };
  const anchored = store.head();
  const result = await anchor.anchorHead(store, local, witness, { id: "anchor:1", anchoredAt: 50 });
  assert.equal(result.head.position, anchored.position + 1);
  assert.deepEqual(result.attestation.head, anchored);
  assert.equal(result.event.type, "ANCHOR_RECORDED");
  assert.deepEqual(result.event.data.anchoredHead, anchored);
  assert.equal(result.event.data.anchor, "local-head-file");
  assert.equal(result.event.data.anchoredAt, 50);
  assert.equal(result.event.timestamp, 50);
  assert.deepEqual(result.event.data.receipt, result.receipt);
  assert.equal(result.receipt.file, "history.jsonl.anchors");
  assert.match(result.receipt.entryHash, /^0x[0-9a-f]{64}$/);
  assert.equal(typeof result.event.data.controlAuthorization.signature, "string");
  // The anchor log holds the attestation; the receipt verifies against it.
  const log = readFileSync(`${store.path}.anchors`, "utf8").split("\n").filter(Boolean);
  assert.equal(log.length, 1);
  assert.deepEqual(JSON.parse(log[0]).attestation, result.attestation);
  // verify() re-checks the attestation's signature, so it needs the context; without one it answers false.
  assert.equal(await witness.verify(result.attestation, result.receipt, context), true);
  assert.equal(await witness.verify(result.attestation, result.receipt), false);
  assert.equal(await witness.verify({ ...result.attestation, keyId: "other" }, result.receipt, context), false);
  assert.equal(await witness.verify({ ...result.attestation, signature: `0x${"00".repeat(64)}` }, result.receipt, context), false);
  assert.equal(await witness.verify(result.attestation, { ...result.receipt, entryHash: `0x${"0".repeat(64)}` }, context), false);
  assert.deepEqual(witness.entries().map((entry) => entry.attestation), [result.attestation]);
  // submit() with a context refuses an attestation the owner keys did not sign, before touching the log.
  await code(() => witness.submit({ ...result.attestation, signature: `0x${"00".repeat(64)}` }, context), "ANCHOR_LOG_REJECTED");
  assert.equal(witness.entries().length, 1);
  // Replay (fresh) sees the anchor; verify() reports PREFIX_OK; a reopened store agrees.
  const fresh = replay(store.readAll());
  assert.equal(fresh.status, "ACCEPTED");
  assert.deepEqual(fresh.state.anchors, [{ head: anchored, anchor: "local-head-file", eventId: "anchor:1", eventPosition: anchored.position + 1 }]);
  const report = openHistoryStore(store.path).verify();
  assert.deepEqual(report.anchors, [{ head: anchored, anchor: "local-head-file", eventId: "anchor:1", status: "PREFIX_OK" }]);
  assert.equal(report.pinnedHeadStatus, "MATCHES");
  assert.equal(report.pinnedAttestation, "VERIFIED");
  // verify() reads the anchor log itself: the anchored head is a prefix.
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.anchorLogStatus, "OK");
  assert.deepEqual(report.anchorLogHeads.map((w) => [w.log, w.location, w.head.position, w.status]), [["local-head-file", `${store.path}.anchors`, anchored.position, "PREFIX_OK"]]);
  // More history, then a second anchor: both anchors stay prefixes.
  store.append(await signer.signControlEvent(local, { ...agentEvent(5), timestamp: 55 }, DOMAIN, store.head(), "sha256"));
  const second = await anchor.anchorHead(store, local, witness, { id: "anchor:2", anchoredAt: 60 });
  assert.equal(second.head.position, 6);
  assert.deepEqual(store.verify().anchors.map((entry) => [entry.eventId, entry.status, entry.head.position]), [["anchor:1", "PREFIX_OK", 3], ["anchor:2", "PREFIX_OK", 5]]);
  assert.equal(readFileSync(`${store.path}.anchors`, "utf8").split("\n").filter(Boolean).length, 2);
  // Legacy histories cannot be anchored.
  const legacy = JSON.parse(readFileSync(fixturePath("handover-history.json"), "utf8"));
  const legacyStore = createHistoryStore(join(dir, "legacy.jsonl"), legacy);
  await code(() => anchor.anchorHead(legacyStore, local, witness, { id: "anchor:x", anchoredAt: 1 }), "UNSUPPORTED_VERSION");
});

test("anchorRecordedEvent bounds the receipt to a 64 KiB protocol record", async () => {
  const attestation = await signer.attestHead(local, DOMAIN, { hash: sha256Hex(Buffer.from("x")), position: 1, canonicalTime: 1 }, "sha256");
  const witness = { kind: "custom", name: "mine", submit: async () => ({}) };
  const event = anchor.anchorRecordedEvent(attestation, witness, { note: "ok", n: 1 }, 5, "anchor:c");
  assert.equal(event.data.anchor, "custom");
  assert.deepEqual(event.data.receipt, { n: 1, note: "ok" });
  assert.throws(() => anchor.anchorRecordedEvent(attestation, witness, "text", 5, "a"), { code: "RECEIPT_INVALID" });
  assert.throws(() => anchor.anchorRecordedEvent(attestation, witness, { big: "x".repeat(70_000) }, 5, "a"), { code: "RECEIPT_INVALID" });
  assert.throws(() => anchor.anchorRecordedEvent(attestation, witness, { many: Array.from({ length: 20 }, (_, i) => `v${i}`.repeat(2_000)) }, 5, "a"), { code: "RECEIPT_INVALID" });
  assert.throws(() => anchor.anchorRecordedEvent(attestation, witness, { f: 1.5 }, 5, "a"), { code: "RECEIPT_INVALID" });
});

test("anchors are evidence about a head, never a witness binding: there is no http anchor witness, and \"http-witness\" is not an anchor literal", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "http.jsonl"), 1);
  assert.equal(anchor.httpWitness, undefined, "removed: an unverified webhook whose body was recorded verbatim (coherence F1/F11)");
  assert.deepEqual([...events.ANCHOR_NAMES], ["local-head-file", "rekor-v2", "custom"]);
  assert.equal(Object.hasOwn(anchor.ANCHOR_KIND_NAMES, "http"), false);
  // A witness object claiming the removed kind is refused before anything is signed or written.
  const before = store.head();
  const fake = { kind: "http", name: "http-witness", submit: async () => ({ id: "w-1" }) };
  await code(() => anchor.anchorHead(store, local, fake, { id: "anchor:http", anchoredAt: 70 }), "INVALID_INPUT");
  assert.deepEqual(store.head(), before);
  // An owner-signed ANCHOR_RECORDED naming "http-witness" is refused by the closed schema.
  const unsigned = { id: "anchor:http", type: "ANCHOR_RECORDED", timestamp: 70, data: { anchoredHead: before, anchor: "http-witness", receipt: { id: "w-1" }, anchoredAt: 70 } };
  const signed = await signer.signControlEvent(local, unsigned, DOMAIN, before, "sha256");
  assert.equal(events.validateEvent(signed, TRELLIS, before.position + 1).code, "EVENT_DATA_INVALID");
  // A custom anchor whose receipt looks like a binding is just an anchor: recorded, and nothing is bound.
  const custom = { kind: "custom", name: "custom", submit: async () => ({ action: "BIND", witnesses: [{ url: "https://evil.example", verifierKey: "evil.example+00000000+AQ==" }] }) };
  const recorded = await anchor.anchorHead(store, local, custom, { id: "anchor:custom", anchoredAt: 71 });
  assert.equal(recorded.event.data.anchor, "custom");
  assert.deepEqual(store.state().boundWitnesses, []);
  assert.equal(store.state().boundPolicy, undefined);
});

test("rekor witness: hashedrekord v2 request shape over the attestation hash, with an injected fetch", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "rekor.jsonl"), 1);
  const calls = [];
  const entry = { logIndex: "1234", logId: { keyId: "abc=" }, kindVersion: { kind: "hashedrekord", version: "0.0.2" }, integratedTime: "1700000000",
    inclusionProof: { logIndex: "1234", rootHash: "cm9vdA==", treeSize: "1235", hashes: ["aGFzaA=="], checkpoint: { envelope: "rekor.sigstore.dev - 1\n1235\nroot\n" } } };
  const fetchImpl = async (url, init) => { calls.push({ url, init }); return { ok: true, status: 201, text: async () => JSON.stringify(entry) }; };
  const witness = anchor.rekorAnchor({ baseUrl: "https://rekor.example/", fetch: fetchImpl });
  assert.equal(witness.kind, "rekor");
  assert.equal(witness.name, "rekor-v2");
  const result = await anchor.anchorHead(store, local, witness, { id: "anchor:rekor", anchoredAt: 90 });
  assert.deepEqual(result.receipt, entry);
  assert.equal(result.event.data.anchor, "rekor-v2");
  assert.equal(calls[0].url, "https://rekor.example/api/v2/log/entries");
  assert.equal(calls[0].init.method, "POST");
  const body = JSON.parse(calls[0].init.body);
  assert.deepEqual(Object.keys(body), ["hashedRekordRequestV002"]);
  const request = body.hashedRekordRequestV002;
  const artifact = Buffer.from(signer.headAttestationHash(DOMAIN, result.attestation.head, "sha256").slice(2), "hex");
  assert.equal(request.digest, Buffer.from(sha256Hex(artifact).slice(2), "hex").toString("base64"));
  assert.equal(request.signature.content, Buffer.from(result.attestation.signature.slice(2), "hex").toString("base64"));
  assert.equal(request.signature.verifier.keyDetails, "PKIX_ED25519");
  const spki = Buffer.from(request.signature.verifier.publicKey.rawBytes, "base64");
  assert.equal(spki.subarray(-32).toString("hex"), owner.credential.slice(2));
  // The block is self-consistent: the DER public key verifies the signature over the artifact.
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  assert.equal(nodeVerify(null, artifact, key, Buffer.from(request.signature.content, "base64")), true);
  assert.equal(store.verify().anchors[0].status, "PREFIX_OK");
  // Without context, or with a non-Ed25519 owner key, the witness refuses before any network call.
  await code(() => witness.submit(result.attestation), "INVALID_INPUT");
  const secp = suites.generateKeyPair("eip191-personal-sign-keccak256", "owner:secp");
  const secpAttestation = await signer.attestHead(signer.signerFromKeyPair(secp), DOMAIN, store.head(), "sha256");
  await code(() => witness.submit(secpAttestation, { domain: DOMAIN, algorithm: "sha256", ownerKeys: [{ keyId: secp.keyId, scheme: secp.scheme, credential: secp.credential }] }), "UNSUPPORTED_VERSION");
  await code(() => witness.submit(secpAttestation, { domain: DOMAIN, algorithm: "sha256", ownerKeys }), "KEY_UNAVAILABLE");
  assert.equal(calls.length, 1);
  assert.equal(anchor.REKOR_DEFAULT_BASE_URL, "https://rekor.sigstore.dev");
});

// ---------------------------------------------------------------- B1: verify() consults the witnesses

const { verifyHistory } = await import("../src/owner.ts");
const lines = (path) => readFileSync(path, "utf8").split("\n").filter(Boolean);
/** A 9-event history anchored twice in the default local log; returns the store and a copy of the file and pin at the first anchor. */
const anchoredHistory = async (dir) => {
  const store = await trellisStore(join(dir, "h.jsonl"), 3);
  await anchor.anchorHead(store, local, undefined, { id: "anchor:1", anchoredAt: 40 });
  copyFileSync(store.path, join(dir, "old.jsonl"));
  copyFileSync(`${store.path}.head`, join(dir, "old.jsonl.head"));
  for (let n = 3; n < 6; n += 1) store.append(await signer.signControlEvent(local, { ...agentEvent(n), timestamp: 41 + n }, DOMAIN, store.head(), "sha256"));
  await anchor.anchorHead(store, local, undefined, { id: "anchor:2", anchoredAt: 60 });
  return store;
};

test("B1: anchorHead defaults to the local log <history>.anchors, which verify() reads", async (t) => {
  const dir = workspace(t);
  const store = await anchoredHistory(dir);
  assert.equal(lines(`${store.path}.anchors`).length, 2);
  const report = verifyHistory(store.path);
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.anchorLogStatus, "OK");
  assert.deepEqual(report.anchorLogHeads.map((w) => w.status), ["PREFIX_OK", "PREFIX_OK"]);
  assert.equal(report.rollback, false);
});

test("B1: truncation plus a deleted pin fails verification: the pin is MISSING and the witness holds a newer head", async (t) => {
  const dir = workspace(t);
  const store = await anchoredHistory(dir);
  // The review's reproduction: drop the tail (after the witness saw it) and delete the pin; the anchor log stays.
  writeFileSync(store.path, `${lines(store.path).slice(0, -3).join("\n")}\n`);
  rmSync(`${store.path}.head`);
  await code(() => openHistoryStore(store.path), "ROLLBACK_DETECTED");
  const report = verifyHistory(store.path);
  assert.equal(report.ok, false);
  assert.equal(report.rollback, true);
  assert.equal(report.pinnedHeadStatus, "MISSING");
  assert.equal(report.anchorLogStatus, "ROLLBACK");
  assert.ok(report.failures.some((f) => f.startsWith("PIN_MISSING")));
  assert.ok(report.failures.some((f) => f.startsWith("ANCHOR_LOG_ROLLBACK") && /position 8/.test(f) && /ends at position 6/.test(f)), report.failures.join("\n"));
  assert.deepEqual(report.anchorLogHeads.map((w) => [w.head.position, w.status]), [[4, "PREFIX_OK"], [8, "NEWER_THAN_FILE"]]);
  // allowUnpinned only waives the pin; the witness still fails it.
  const tolerated = verifyHistory(store.path, { allowUnpinned: true });
  assert.equal(tolerated.ok, false);
  assert.deepEqual(tolerated.failures.map((f) => f.split(":")[0]), ["ANCHOR_LOG_ROLLBACK"]);
  // Accepting the rollback re-pins (attested) and records it, but the witness keeps failing until its log is archived deliberately.
  const accepted = verifyHistory(store.path, { acceptRollback: true, signer: local });
  assert.equal(accepted.pinnedHeadStatus, "MATCHES");
  assert.equal(accepted.pinnedAttestation, "VERIFIED");
  assert.equal(typeof accepted.rollbackAcceptedAt, "number");
  assert.equal(accepted.ok, false);
  assert.ok(accepted.notes.some((n) => n.startsWith("ANCHOR_LOG_AFTER_ACCEPTED_ROLLBACK")));
  assert.deepEqual(verifyHistory(store.path).failures.map((f) => f.split(":")[0]), ["ANCHOR_LOG_ROLLBACK"]);
});

test("B1: an old copy restored with its old pin verifies its pin, but the anchor log proves it is not the latest", async (t) => {
  const dir = workspace(t);
  const store = await anchoredHistory(dir);
  renameSync(join(dir, "old.jsonl"), store.path);
  renameSync(join(dir, "old.jsonl.head"), `${store.path}.head`);
  const report = verifyHistory(store.path);
  assert.equal(report.pinnedHeadStatus, "MATCHES");
  assert.equal(report.pinnedAttestation, "VERIFIED");
  assert.equal(report.ok, false);
  assert.equal(report.anchorLogStatus, "ROLLBACK");
  assert.deepEqual(report.failures.map((f) => f.split(":")[0]), ["ANCHOR_LOG_ROLLBACK"]);
  // The pin is consistent with the file; only the witness sees the loss. Accepting it records the acceptance in the pin
  // (the old pin becomes previousPin), and the witness keeps failing verification until its log is archived.
  const accepted = verifyHistory(store.path, { acceptRollback: true, signer: local });
  assert.equal(accepted.ok, false);
  assert.equal(typeof accepted.rollbackAcceptedAt, "number");
  assert.equal(accepted.pinnedAttestation, "VERIFIED");
  assert.ok(accepted.notes.some((n) => n.startsWith("ANCHOR_LOG_AFTER_ACCEPTED_ROLLBACK")));
  // Accepting again changes nothing: the pin already records the acceptance of this head.
  assert.equal(verifyHistory(store.path, { acceptRollback: true, signer: local }).rollbackAcceptedAt, accepted.rollbackAcceptedAt);
  renameSync(`${store.path}.anchors`, join(dir, "archived.anchors"));
  const archived = verifyHistory(store.path);
  assert.equal(archived.anchorLogStatus, "MISSING", "the history itself records a local anchor, so a vanished log is noticed");
  assert.equal(archived.ok, false);
  // The archived log, handed over explicitly, still shows what was lost.
  const explicit = verifyHistory(store.path, { anchorLogs: [anchor.localAnchorLog(join(dir, "archived.anchors"))] });
  assert.equal(explicit.anchorLogStatus, "ROLLBACK");
});

test("R2: opening a history consults <history>.anchors: a restored older copy with its genuine pin is ANCHOR_LOG_ROLLBACK", async (t) => {
  const dir = workspace(t);
  const store = await anchoredHistory(dir);
  const newest = store.head();
  renameSync(join(dir, "old.jsonl"), store.path);
  renameSync(join(dir, "old.jsonl.head"), `${store.path}.head`);
  // Every opener refuses, the owner-keyed writer included; the long-lived instance refuses on its next read.
  for (const options of [{}, { signer: local }]) {
    const error = await code(() => openHistoryStore(store.path, options), "ROLLBACK_DETECTED");
    assert.equal(error.detail.reason, "ANCHOR_LOG_ROLLBACK");
    assert.equal(error.detail.anchorLogPath, `${store.path}.anchors`);
    assert.equal(error.detail.anchoredHead.position, 8);
    assert.equal(error.detail.observedHead.position, 5);
  }
  assert.equal((await code(() => store.head(), "ROLLBACK_DETECTED")).detail.reason, "ANCHOR_LOG_ROLLBACK");
  // allowUnpinned reads it (reads only); every write refuses, and repin refuses to attest it.
  const tolerant = openHistoryStore(store.path, { allowUnpinned: true, signer: local });
  assert.equal(tolerant.head().position, 5);
  const pinBefore = readFileSync(`${store.path}.head`, "utf8");
  assert.equal((await code(() => tolerant.append(agentEvent(9)), "ROLLBACK_DETECTED")).detail.reason, "ANCHOR_LOG_ROLLBACK");
  const refused = await code(() => tolerant.repin(), "REPIN_REFUSED");
  assert.equal(refused.detail.reason, "ANCHOR_LOG_ROLLBACK");
  assert.equal(readFileSync(`${store.path}.head`, "utf8"), pinBefore, "nothing was re-pinned");
  // An anchor log kept elsewhere, handed to repin, is consulted too.
  renameSync(`${store.path}.anchors`, join(dir, "offsite.anchors"));
  const offsite = anchor.localAnchorLog(join(dir, "offsite.anchors"));
  assert.equal((await code(() => openHistoryStore(store.path, { signer: local }).repin({ anchorLogs: [offsite] }), "REPIN_REFUSED")).detail.reason, "ANCHOR_LOG_ROLLBACK");
  renameSync(join(dir, "offsite.anchors"), `${store.path}.anchors`);
  // acceptRollback proceeds and records the acceptance; plain readers keep refusing until the log is archived deliberately.
  const accepted = openHistoryStore(store.path, { acceptRollback: true, signer: local });
  assert.equal(typeof accepted.pinnedHead().rollbackAcceptedAt, "number");
  assert.equal(accepted.pinnedHead().previousPin.position, 5);
  assert.equal((await code(() => openHistoryStore(store.path), "ROLLBACK_DETECTED")).detail.reason, "ANCHOR_LOG_ROLLBACK");
  renameSync(`${store.path}.anchors`, join(dir, "archived.anchors"));
  assert.equal(openHistoryStore(store.path).head().position, 5);
  assert.ok(newest.position > 5);
});

test("an anchor log entry whose head position is -0 is malformed (canonical U53; fuzz VAST-FUZZ-01 F4)", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "h.jsonl"), 2);
  await anchor.anchorHead(store, local, undefined, { id: "anchor:1", anchoredAt: 40 });
  const log = `${store.path}.anchors`;
  const entry = JSON.parse(readFileSync(log, "utf8"));
  entry.attestation.head.position = 987654321;
  writeFileSync(log, `${JSON.stringify(entry).replace(":987654321", ":-0")}\n`); // JSON.stringify writes -0 as 0
  assert.match(readFileSync(log, "utf8"), /"position":-0[,}]/);
  const error = await code(() => openHistoryStore(store.path), "ANCHOR_LOG_UNREADABLE");
  assert.match(error.message, /is not an anchor log entry/);
});

test("R2: an unreadable anchor log fails the open (ANCHOR_LOG_UNREADABLE) unless allowUnpinned; acceptRollback cannot accept it", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "h.jsonl"), 2);
  const log = `${store.path}.anchors`;
  writeFileSync(log, "{not json\n");
  const error = await code(() => openHistoryStore(store.path), "ANCHOR_LOG_UNREADABLE");
  assert.equal(error.detail.reason, "ANCHOR_LOG_UNREADABLE");
  assert.equal(error.detail.anchorLogPath, log);
  await code(() => openHistoryStore(store.path, { acceptRollback: true, signer: local }), "ANCHOR_LOG_UNREADABLE");
  const tolerant = openHistoryStore(store.path, { allowUnpinned: true, signer: local });
  assert.equal(tolerant.head().position, 3);
  await code(() => tolerant.append(agentEvent(9)), "ANCHOR_LOG_UNREADABLE");
  assert.equal((await code(() => tolerant.repin({ acceptRollback: true }), "REPIN_REFUSED")).detail.reason, "ANCHOR_LOG_UNREADABLE");
  // The owner API keeps the code (it does not become READ_UNAVAILABLE); verifyHistory reports it instead of throwing.
  const { openLocalOwner } = await import("../src/owner.ts");
  assert.throws(() => openLocalOwner({ historyFile: store.path, domain: DOMAIN, owner: "owner", controller: "controller", now: () => 100, signer: local }), (e) => e.code === "ANCHOR_LOG_UNREADABLE");
  assert.equal(verifyHistory(store.path).anchorLogStatus, "UNREADABLE");
  assert.equal(verifyHistory(store.path, { acceptRollback: true, signer: local }).anchorLogStatus, "UNREADABLE");
  // A forged entry (no owner key signed it) proves nothing either way: readers open, verify() fails it.
  const stranger = signer.signerFromKeyPair(suites.generateKeyPair("ed25519", owner.keyId));
  writeFileSync(log, `${JSON.stringify({ attestation: await signer.attestHead(stranger, DOMAIN, { ...store.head(), position: 99 }, "sha256"), receivedAt: 1 })}\n`);
  assert.equal(openHistoryStore(store.path).head().position, 3);
  assert.equal(verifyHistory(store.path).anchorLogStatus, "INVALID");
});

test("B1: a rewritten history (same length, other events) is NOT_A_PREFIX of the anchored head", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "h.jsonl"), 2);
  await anchor.anchorHead(store, local, undefined, { id: "anchor:1", anchoredAt: 40 });
  // Rebuild the same deployment with a different event at position 2, as long as the anchored head, and pin it properly.
  const log = readFileSync(`${store.path}.anchors`);
  rmSync(store.path); rmSync(`${store.path}.head`);
  // A new history is not created beside an anchor log that holds heads it does not contain.
  assert.equal((await code(() => createHistoryStore(store.path, [genesisEvent()], { signer: local }), "ROLLBACK_DETECTED")).detail.reason, "ANCHOR_LOG_ROLLBACK");
  rmSync(`${store.path}.anchors`);
  const forged = createHistoryStore(store.path, [genesisEvent()], { signer: local });
  forged.append(await signer.signControlEvent(local, principalEvent, DOMAIN, forged.head(), "sha256"));
  for (const n of [7, 8, 9]) forged.append(await signer.signControlEvent(local, agentEvent(n), DOMAIN, forged.head(), "sha256"));
  writeFileSync(`${store.path}.anchors`, log);
  const report = verifyHistory(store.path);
  assert.equal(report.pinnedHeadStatus, "MATCHES");
  assert.equal(report.ok, false);
  assert.equal(report.anchorLogStatus, "ROLLBACK");
  assert.equal(report.anchorLogHeads[0].status, "NOT_A_PREFIX");
  assert.match(report.failures[0], /^ANCHOR_LOG_ROLLBACK: .* not a prefix of this history/);
  // Readers refuse the rewritten history too, although its own pin is genuinely attested.
  const refused = await code(() => openHistoryStore(store.path), "ROLLBACK_DETECTED");
  assert.equal(refused.detail.reason, "ANCHOR_LOG_ROLLBACK");
  assert.match(refused.message, /is not a prefix of history/);
});

test("B1: an unreadable anchor log or a forged anchor log entry fails verification; no log is informational", async (t) => {
  const dir = workspace(t);
  const store = await trellisStore(join(dir, "h.jsonl"), 1);
  const none = verifyHistory(store.path);
  assert.equal(none.ok, true);
  assert.equal(none.anchorLogStatus, "NONE");
  assert.ok(none.notes.some((n) => n.startsWith("ANCHOR_LOG_NONE")));
  const log = `${store.path}.anchors`;
  writeFileSync(log, "{not json\n");
  let report = verifyHistory(store.path);
  assert.equal(report.anchorLogStatus, "UNREADABLE");
  assert.equal(report.ok, false);
  assert.ok(report.failures[0].startsWith("ANCHOR_LOG_UNREADABLE"));
  writeFileSync(log, `${JSON.stringify({ attestation: await signer.attestHead(local, DOMAIN, store.head(), "sha256"), receivedAt: 1 })}`);
  assert.equal(verifyHistory(store.path).anchorLogStatus, "UNREADABLE", "a torn last line is not silently skipped");
  const stranger = signer.signerFromKeyPair(suites.generateKeyPair("ed25519", owner.keyId));
  writeFileSync(log, `${JSON.stringify({ attestation: await signer.attestHead(stranger, DOMAIN, store.head(), "sha256"), receivedAt: 1 })}\n`);
  report = verifyHistory(store.path);
  assert.equal(report.anchorLogStatus, "INVALID");
  assert.equal(report.anchorLogHeads[0].status, "SIGNATURE_INVALID");
  assert.ok(report.failures[0].startsWith("ANCHOR_LOG_INVALID"));
  rmSync(log);
  // Other anchor logs: a custom log is consulted through options.anchorLogs; an anchor target that cannot list its heads is refused.
  const custom = anchor.localAnchorLog(join(dir, "elsewhere.anchors"));
  await anchor.anchorHead(store, local, custom, { id: "anchor:c", anchoredAt: 50 });
  const without = verifyHistory(store.path);
  assert.equal(without.anchorLogStatus, "MISSING", "the history records an anchor in a log verify() was not given");
  assert.ok(without.failures[0].includes('"elsewhere.anchors"'));
  const withCustom = verifyHistory(store.path, { anchorLogs: [custom, anchor.localAnchorLog(join(dir, "elsewhere.anchors"))] });
  assert.equal(withCustom.ok, true, withCustom.failures.join("; "));
  assert.equal(withCustom.anchorLogHeads.length, 1, "the same log is read once");
  await code(() => verifyHistory(store.path, { anchorLogs: [anchor.rekorAnchor({ baseUrl: "https://w.example" })] }), "INVALID_INPUT");
  await code(() => store.verify({ anchorLogs: [anchor.rekorAnchor({ baseUrl: "https://w.example" })] }), "INVALID_INPUT");
  // A legacy history has no witnesses to check.
  const legacy = createHistoryStore(join(dir, "legacy.jsonl"), JSON.parse(readFileSync(fixturePath("handover-history.json"), "utf8")));
  const legacyReport = legacy.verify();
  assert.equal(legacyReport.anchorLogStatus, "NOT_APPLICABLE");
  assert.equal(legacyReport.ok, true);
});

test("B1: a legacy history without a pin is UNPINNED and says why (legacy files predate pinning)", async () => {
  const report = openHistoryStore(fixturePath("handover-history.jsonl")).verify();
  assert.equal(report.pinnedHeadStatus, "UNPINNED");
  assert.equal(report.ok, true);
  assert.ok(report.notes.some((n) => n.startsWith("PIN_UNPINNED") && /legacy files predate pinning/.test(n)));
  assert.equal(verifyHistory(fixturePath("handover-history.jsonl")).ok, true);
});
