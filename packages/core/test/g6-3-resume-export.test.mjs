// Resume roots and export views under owner approval policies (A-101.0 with A-111.1, A-101.1, A-120.0; the G6.x holds
// were lifted on 2026-10-12): the resume-root class test as a function (A-101.2 and A-111.4 names), FULL_REPLAY with the
// reason when a pin is not a root, an in-file co-signed checkpoint seeding a resume under M_eff(35) = 2, the append epoch
// at the file head (A-120.3: a last rotation that lowers or raises the checkpoint threshold), and the export verifier:
// a 2-of-3 key event, a single-signed one refused by the state-free verifier, and asserted roots at `from`.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, openLocalOwner, resumeRootFailure, humanAttestationHash, HUMAN_ATTESTATION_VERSION } = core;
const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair, attestHeadSync } = await import("../src/signer.ts");
const { openHistoryStore, storeCounters, resetStoreCountersForTests } = await import("../src/store.ts");

const pair = (keyId, n) => keyPairFromPrivateKey("ed25519", keyId, `0x${n.toString(16).padStart(64, "0")}`);
const pub = (p) => ({ keyId: p.keyId, scheme: "ed25519", credential: p.credential });
const O1 = pair("owner:1", 0xa001), O2 = pair("owner:2", 0xa002), O3 = pair("owner:3", 0xa003), A1 = pair("agent:1", 0xa101), AT1 = pair("attester:1", 0xa301), AT2 = pair("attester:2", 0xa302);
const statement = (domain, subject, attester, notBefore, expiresAt) => {
  const body = { version: HUMAN_ATTESTATION_VERSION, audience: domain, subject: pub(subject), profile: "phl:ceremony/1", attesterKeyId: attester.keyId, evidenceDigest: `0x${"cd".repeat(32)}`, notBefore, expiresAt };
  return { ...body, signature: signerFromKeyPair(attester).signHashSync(humanAttestationHash({ ...body, signature: "" })) };
};
const cosign = async (prepared, ...pairs) => Promise.all(pairs.map((p) => core.authorizeControlEvent(signerFromKeyPair(p), prepared)));

async function owner(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g63-resume-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 1000;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => (tick += 1), signer: signerFromKeyPair(O1), witness: false, ...options };
  return { handle: await createLocalOwner(config), config };
}
/** How a CHECKPOINT_RESUME open loads the file, and the FULL_REPLAY note `verify` gives (if any). */
const resumeOf = (config) => {
  resetStoreCountersForTests();
  const store = openHistoryStore(config.historyFile, { trust: "CHECKPOINT_RESUME", witness: false });
  const loadedBy = store.loadedBy(), report = store.verify();
  store.close?.();
  assert.equal(report.ok, true, JSON.stringify(report.failures));
  return { loadedBy, note: report.notes.find((note) => note.startsWith("FULL_REPLAY")), resumes: storeCounters.resumes };
};

test("A-101.0 (a)(b) and A-111.1 (c) as a function: the A-101.2 / A-111.4 resume-root cases", () => {
  const domain = createLocalDomain();
  const epoch = (keys, policy) => ({ fromPosition: 0, keys: keys.map(pub), ...(policy === undefined ? {} : { policy }) });
  const declared = epoch([O1, O2, A1], { threshold: 1, keyClasses: { "agent:1": "AGENT" } });
  // resume-root-human-both-policies, and the default policy: a root.
  assert.equal(resumeRootFailure(pub(O1), 5, declared, declared), undefined);
  assert.equal(resumeRootFailure(pub(O1), 5, epoch([O1]), epoch([O1])), undefined);
  // resume-root-agent-at-pin-head: (a).
  assert.match(resumeRootFailure(pub(A1), 5, declared, epoch([O1, O2, A1])), /AGENT .*A-101\.0 \(a\)/);
  // resume-root-reclassified-agent-at-file-head: owner:2 is HUMAN at the pin's head, AGENT in the append epoch: (b).
  assert.match(resumeRootFailure(pub(O2), 5, declared, epoch([O1, O2, A1], { threshold: 1, keyClasses: { "owner:2": "AGENT" } })), /A-101\.0 \(b\)/);
  // G61-X-11: a credential the append epoch does not hold is not AGENT there (DECLARED): (b) holds.
  assert.equal(resumeRootFailure(pub(O3), 5, epoch([O3]), declared), undefined);
  // resume-root-lapsed-signer: under ATTESTED the signer must be HUMAN at head.canonicalTime: (a).
  const attested = epoch([O1, O2], { threshold: 1, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations: [statement(domain, O1, AT1, 0, 10), statement(domain, O2, AT2, 0, 100)] });
  assert.match(resumeRootFailure(pub(O1), 12, attested, attested), /LAPSED .*A-101\.0 \(a\)/);
  // A-111.1 I19 freshness: (a)'s time test only; a pin signed at 5 under [0, 10) stays a root later.
  assert.equal(resumeRootFailure(pub(O1), 5, attested, attested), undefined);
  // (b) under ATTESTED: the credential must be the subject of a statement in the append epoch's policy (any interval).
  const without = { ...attested, policy: { ...attested.policy, attestations: [attested.policy.attestations[1]] } };
  assert.match(resumeRootFailure(pub(O1), 5, attested, without), /no human attestation .*A-101\.0 \(b\)/);
  // resume-root-pin-under-checkpoint-threshold-2: (c).
  assert.match(resumeRootFailure(pub(O1), 5, declared, epoch([O1, O2], { threshold: 1, byType: { STATE_CHECKPOINT: 2 } })), /A-111\.1 \(c\)/);
  assert.match(resumeRootFailure(pub(O1), 5, declared, epoch([O1, O2], { threshold: 2 })), /A-111\.1 \(c\)/);
});

test("A-111.4: under M_eff(STATE_CHECKPOINT) = 2 the pin is not a resume root (FULL_REPLAY with the reason); a co-signed in-file checkpoint seeds the resume", async (t) => {
  const { handle, config } = await owner(t, { coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 1, byType: { STATE_CHECKPOINT: 2 } } });
  await handle.createAgent({ id: "bea" });
  handle.close();
  const pinOnly = resumeOf(config);
  assert.equal(pinOnly.loadedBy, "FULL_REPLAY");
  assert.match(pinOnly.note, /^FULL_REPLAY: the pin's attestation of \d+: .*A-111\.1 \(c\)/);
  const reopened = openLocalOwner(config);
  const head = reopened.verify().head, root = reopened.stateRoot();
  const prepared = await reopened.prepareControlEvent({ type: "STATE_CHECKPOINT", data: { checkpointId: "checkpoint:cosigned", derivationVersion: "irontrellis-state/2", head: { hash: head.hash, position: head.position }, stateRoot: root.stateRoot, recordCount: root.recordCount, projectionHead: root.projectionHead } });
  assert.equal(prepared.required, 2);
  await reopened.submitControlEvent(prepared, await cosign(prepared, O1, O2));
  await reopened.createAgent({ id: "cal" });
  reopened.close();
  const resumed = resumeOf(config);
  assert.deepEqual([resumed.loadedBy, resumed.note], ["CHECKPOINT_RESUME", undefined]); // the pin is tried first and refused, then the checkpoint seeds it
});

test("A-120.3: the append epoch decides (c): a last rotation that lowers STATE_CHECKPOINT from 2 to 1 makes the pin a root; one that raises it from 1 to 2 stops it being one", async (t) => {
  {
    const { handle, config } = await owner(t, { coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 1, byType: { STATE_CHECKPOINT: 2 } } });
    await handle.createAgent({ id: "bea" });
    assert.equal(resumeOf(config).loadedBy, "FULL_REPLAY");
    await handle.rotateOwnerPolicy({ ownerPolicy: { threshold: 1, labels: { "owner:2": "phone" } } });
    handle.close();
    const lowered = resumeOf(config);
    assert.deepEqual([lowered.loadedBy, lowered.note], ["CHECKPOINT_RESUME", undefined]);
  }
  {
    const { handle, config } = await owner(t, { coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 1 } });
    await handle.createAgent({ id: "bea" });
    assert.equal(resumeOf(config).loadedBy, "CHECKPOINT_RESUME");
    await handle.rotateOwnerPolicy({ ownerPolicy: { threshold: 1, byType: { STATE_CHECKPOINT: 2 } } });
    handle.close();
    const raised = resumeOf(config);
    assert.equal(raised.loadedBy, "FULL_REPLAY");
    assert.match(raised.note, /A-111\.1 \(c\)/);
  }
});

test("A-101.1 / A-101.2 export: a 2-of-3 key event verifies, a single-signed one is refused by the state-free verifier, and the asserted root at from must satisfy A-101.0", async (t) => {
  const policy = { threshold: 1, byType: { OWNER_KEYS_ROTATED: 2 } };
  const { handle } = await owner(t, { coOwnerKeys: [pub(O2), pub(O3)], ownerPolicy: policy });
  await handle.createAgent({ id: "bea" });
  const prepared = await handle.prepareOwnerPolicyRotation({ ownerPolicy: { ...policy, labels: { "owner:3": "safe" } } });
  const rotated = await handle.submitControlEvent(prepared, await cosign(prepared, O1, O2));
  await handle.createAgent({ id: "cal" });
  await handle.createAgent({ id: "dee" });
  const at = rotated.head.position;
  const view = JSON.parse(JSON.stringify(handle.exportView({ fromPosition: at + 1, toPosition: at + 2, include: { fromRecords: true, referencedEvents: true, keyEvents: true, attestations: true } })));
  const ok = core.verifyExportView(view);
  assert.equal(ok.ok, true, JSON.stringify(ok.failures));
  assert.deepEqual(ok.ownerKeyEpochs.map((e) => e.policy?.labels), [undefined, { "owner:3": "safe" }]);
  // The same key event signed by owner:1 alone: what the export verifier asks the state-free verifier (A-120.1).
  const key = view.keyEvents.find((k) => k.position === at);
  const { additionalControlAuthorizations, ...single } = key.event.data;
  assert.equal(additionalControlAuthorizations.length, 1);
  const verdict = core.verifyRotationEvent({ ...key.event, data: single }, { domain: view.domain, previousHead: key.headBefore, epochs: [ok.ownerKeyEpochs[0]], openedAt: [view.referencedEvents?.find((e) => e.position === 0)?.event.timestamp ?? 0] });
  assert.deepEqual([verdict.ok, verdict.code], [false, "CONTROL_AUTHORIZATION_INVALID"]);
  // An asserted root at from: owner:1's attestation authenticates it; under A-101.0 an AGENT key's does not.
  const withAttestation = (signer) => {
    const v = structuredClone(view);
    v.attestations.from = attestHeadSync(signerFromKeyPair(signer), v.domain, v.from.head, "sha256", { stateRoot: v.from.stateRoot, projectionHead: v.from.projectionHead });
    v.fromAuthenticated = true;
    return core.verifyExportView(v);
  };
  const human = withAttestation(O1);
  assert.equal(human.ok, true, JSON.stringify(human.failures));
  assert.equal(human.from.authenticated, "HEAD_ATTESTATION");
});

test("A-101.2 / A-111.4 export: a from attestation by an AGENT key, and one under M_eff(STATE_CHECKPOINT) = 2, are refused", async (t) => {
  for (const [options, signer, pattern] of [
    [{ coOwnerKeys: [pub(A1)], ownerPolicy: { threshold: 1, keyClasses: { "agent:1": "AGENT" } } }, A1, /A-101\.0 \(a\)/],
    [{ coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 1, byType: { STATE_CHECKPOINT: 2 } } }, O1, /A-111\.1 \(c\)/],
  ]) {
    const { handle } = await owner(t, options);
    await handle.createAgent({ id: "bea" });
    await handle.createAgent({ id: "cal" });
    await handle.createAgent({ id: "dee" });
    const view = JSON.parse(JSON.stringify(handle.exportView({ fromPosition: 3, toPosition: 4, include: { fromRecords: true, referencedEvents: true, keyEvents: true, attestations: true } })));
    view.attestations.from = attestHeadSync(signerFromKeyPair(signer), view.domain, view.from.head, "sha256", { stateRoot: view.from.stateRoot, projectionHead: view.from.projectionHead });
    view.fromAuthenticated = true;
    const report = core.verifyExportView(view);
    assert.equal(report.ok, false);
    assert.equal(report.from.authenticated, null);
    assert.match(report.failures.join("\n"), pattern);
  }
});

test("A-131.1: under an ATTESTED epoch the exporter's closure carries e_{q-1} of every key event at q <= from, so the verifier can judge T2", async (t) => {
  const domain = createLocalDomain();
  const ownerPolicy = { threshold: 1, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations: [statement(domain, O1, AT1, 0, 1_000_000), statement(domain, O2, AT2, 0, 1_000_000)] };
  const { handle } = await owner(t, { domain, coOwnerKeys: [pub(O2)], ownerPolicy });
  await handle.createAgent({ id: "bea" });
  const rotated = await handle.rotateOwnerPolicy({ ownerPolicy: { ...ownerPolicy, labels: { "owner:2": "phone" } } });
  await handle.createAgent({ id: "cal" });
  await handle.createAgent({ id: "dee" });
  const q = rotated.head.position;
  const view = JSON.parse(JSON.stringify(handle.exportView({ fromPosition: q + 1, toPosition: q + 2, include: { fromRecords: true, referencedEvents: true, keyEvents: true, attestations: true } })));
  assert.ok(view.referencedEvents.some((e) => e.position === q - 1), "the body before the key event is carried");
  const report = core.verifyExportView(view);
  assert.equal(report.ok, true, JSON.stringify(report.failures));
  assert.equal(report.notes.some((note) => /T2 not judged/.test(note)), false);
});

test("A-75.2 / A-185.4: the exporter sets fromAuthenticated only when the view carries verified evidence of from", async (t) => {
  const { handle } = await owner(t);
  await handle.createAgent({ id: "bea" });
  await handle.createAgent({ id: "cal" });
  await handle.createAgent({ id: "dee" });
  const state = core.replay(handle.exportHistory()).state;
  const at = (from, to, include = {}, headAttestations = []) => core.exportViewState(state, { fromPosition: from, toPosition: to, include: { fromRecords: true, referencedEvents: true, keyEvents: true, ...include } }, { headAttestations });
  const bare = at(3, 4);
  const attestation = (signer) => attestHeadSync(signerFromKeyPair(signer), bare.domain, bare.from.head, "sha256", { stateRoot: bare.from.stateRoot, projectionHead: bare.from.projectionHead });
  assert.equal(bare.fromAuthenticated, false, "nothing authenticates from = 3");
  // A held, valid attestation of from.head that the view does not carry does not set it (it did before A-185.4).
  assert.equal(at(3, 4, {}, [attestation(O1)]).fromAuthenticated, false);
  // Carried (attestations selected) and verified: true, and the verifier agrees.
  const carried = at(3, 4, { attestations: true }, [attestation(O1)]);
  assert.equal(carried.fromAuthenticated, true);
  const report = core.verifyExportView(JSON.parse(JSON.stringify(carried)));
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.from.authenticated, "HEAD_ATTESTATION");
  // Carried but not verified (not an owner key): false; the verifier finds no authentication either, so the view is consistent.
  const unverified = at(3, 4, { attestations: true }, [attestation(A1)]);
  assert.equal(unverified.fromAuthenticated, false);
  assert.equal(core.verifyExportView(JSON.parse(JSON.stringify(unverified))).from.authenticated, null);
  // The checkpoint at from + 1 outside the range: only through attestations.fromCheckpoint; inside the range it is in events.
  await handle.checkpoint();
  const withCheckpoint = core.replay(handle.exportHistory()).state;
  const end = withCheckpoint.head.position - 1;
  const view = (from, to, include) => core.exportViewState(withCheckpoint, { fromPosition: from, toPosition: to, include: { fromRecords: true, referencedEvents: true, keyEvents: true, ...include } });
  assert.equal(view(end, end, {}).fromAuthenticated, false, "an identity range without attestations is false");
  const identity = view(end, end, { attestations: true });
  assert.equal(identity.fromAuthenticated, true);
  assert.equal(core.verifyExportView(JSON.parse(JSON.stringify(identity))).from.authenticated, "STATE_CHECKPOINT");
  const inRange = view(end, end + 1, {});
  assert.equal(inRange.fromAuthenticated, true, "the checkpoint at from + 1 is carried in events");
  assert.equal(core.verifyExportView(JSON.parse(JSON.stringify(inRange))).from.authenticated, "STATE_CHECKPOINT");
});
