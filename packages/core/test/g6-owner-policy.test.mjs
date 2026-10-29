// G6 round 1 (ADDENDA-G6 A-91/A-92, ADDENDA-G6.1 A-96/A-99/A-102): owner approval policies and co-signatures.
// Engine rules the vectors of conformance/v2-owner-policy pin are spot-checked here; the rest is the writer contract of
// A-92.4 and A-96.4 and the builder-pinned cases: prepare/submit (HISTORY_CONFLICT, a short submit with {required, present}),
// the automatic checkpoint under M_eff(35) = 2 (NO_SIGNER), the snapshot resume and the export verifier under a policy
// (A-101), the witness path reading the epoch's policy (A-100), POLICY_RESET, commitNextKey restating the
// policy, the policyRotations counter, a co-signed key rotation, and the maximum sizes (63 co-signatures, 64 proofs).
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, openLocalOwner, replay, controlAuthorizationHash, controlEffectHash, ownerKeyDigest, canonicalEncode } = core;
const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");
const { FORMAT2_VERSIONS } = await import("../src/events.ts");
const { ADAPTER_POLICY_HASH } = await import("../src/adapter-editions.ts");
const { openHistoryStore, createHistoryStore, storeCounters, resetStoreCountersForTests } = await import("../src/store.ts");
const { stateRecordsOf } = await import("../src/state-records.ts");

const code = (value, reason) => (e) => e.code === value && (reason === undefined || e.detail?.reason === reason);
const seed = (n) => `0x${n.toString(16).padStart(64, "0")}`;
const pair = (keyId, n) => keyPairFromPrivateKey("ed25519", keyId, seed(n));
const pub = (p) => ({ keyId: p.keyId, scheme: "ed25519", credential: p.credential });
const O1 = pair("owner:1", 0x6001), O2 = pair("owner:2", 0x6002), O3 = pair("owner:3", 0x6003), A1 = pair("agent:1", 0x6101), N1 = pair("next:1", 0x6201);

// ---------------------------------------------------------------- engine-level histories

const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "2", deploymentId: "g6-tests" });
const genesis = (keys, extra = {}) => ({
  id: "event:genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 100,
  data: {
    adapterPolicyHash: ADAPTER_POLICY_HASH, canonicalLineageId: "lineage:g6", domain: DOMAIN, finality: "LOCAL_ONLY", globalPolicySourceId: "policy:g6", ownerKeys: keys.map(pub),
    policyVersion: "irontrellis-local-owner/2", rootRecognitionPolicy: "declared-principal-root/0.2", timeSource: "EVENT_TIMESTAMP", versions: { ...FORMAT2_VERSIONS, signatureScheme: "ed25519" }, ...extra,
  },
});
const headOf = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED", r.reason); return r.head; };
/** `event` (unsigned) signed at the end of `events`: the first key signs controlAuthorization, the others co-sign; `proofs` sign nextKeyAuthorizations. */
const sign = (events, event, [first, ...rest], proofs = []) => {
  const head = headOf(events);
  const hash = controlAuthorizationHash({ domain: DOMAIN, eventId: event.id, eventType: event.type, timestamp: event.timestamp, previousHead: { hash: head.hash, position: head.position }, effectHash: controlEffectHash(event, "sha256") }, "sha256");
  const entry = (p) => ({ keyId: p.keyId, signature: signerFromKeyPair(p).signHashSync(hash) });
  return { ...event, data: { ...event.data, controlAuthorization: entry(first), ...(rest.length === 0 ? {} : { additionalControlAuthorizations: rest.map(entry) }), ...(proofs.length === 0 ? {} : { nextKeyAuthorizations: proofs.map((p) => ({ ...entry(p), scheme: "ed25519" })) }) } };
};
const principal = { id: "event:principal", type: "PRINCIPAL_CREATED", timestamp: 101, data: { principalId: "operations" } };
const role = (id, t = 102) => ({ id: `event:role:${id}`, type: "ROLE_CREATED", timestamp: t, data: { roleId: id, principalId: "operations", exclusive: true } });
const rejected = (events) => { const r = replay(events); return r.status === "REJECTED" ? `${r.code}@${r.position}` : `ACCEPTED@${r.head.position}`; };

test("A-91/A-92 engine: 2-of-3 genesis, presence, quorum, distinctness, agent floor, and nothing changes without a policy", () => {
  const g = genesis([O1, O2, O3], { ownerPolicy: { threshold: 2 } });
  assert.equal(rejected([g, sign([g], principal, [O1, O2])]), "ACCEPTED@1");
  assert.equal(rejected([g, sign([g], principal, [O1])]), "CONTROL_AUTHORIZATION_INVALID@1");          // step 2: the array is missing
  assert.equal(rejected([g, sign([g], principal, [O1, O1])]), "CONTROL_AUTHORIZATION_INVALID@1");      // step 4
  assert.equal(rejected([g, sign([g], principal, [O1, O2, O3])]), "ACCEPTED@1");                       // surplus verifies
  const plain = genesis([O1, O2]);
  assert.equal(rejected([plain, sign([plain], principal, [O1, O2])]), "CONTROL_AUTHORIZATION_INVALID@1"); // a stray array under the default policy
  const agents = genesis([O1, O2, A1], { ownerPolicy: { threshold: 1, keyClasses: { "agent:1": "AGENT" } } });
  assert.equal(rejected([agents, sign([agents], principal, [A1])]), "CONTROL_AUTHORIZATION_INVALID@1"); // step 6: an agent never alone
  // The epoch record carries the policy as written; the genesis record does not (A-91.3).
  const state = replay([g]).state;
  const records = stateRecordsOf(state);
  assert.deepEqual(records.find((r) => r.kind === "ownerKeyEpoch" && r.key === "0").record.policy, { threshold: 2 });
  assert.equal(Object.hasOwn(records.find((r) => r.kind === "genesis").record, "ownerPolicy"), false);
  assert.equal(Object.hasOwn(replay([plain]).state.ownerKeyEpochs[0], "policy"), false);
});

test("A-96: policy rotations out of a committed epoch carry the commitment; HF1 still refuses everything else; the witness path stays HF1-literal (A-100 held)", () => {
  const g = genesis([O1, O2], { nextKeyDigests: [ownerKeyDigest(N1)], ownerPolicy: { threshold: 2 } });
  const base = [g, sign([g], principal, [O1, O2])];
  const rotation = (data) => ({ id: "event:rotation", type: "OWNER_KEYS_ROTATED", timestamp: 103, data: { ownerKeys: [pub(O1), pub(O2)], ...data } });
  const ok = sign(base, rotation({ nextKeyDigests: [ownerKeyDigest(N1)], ownerPolicy: { threshold: 1 } }), [O1, O2]);
  assert.equal(rejected([...base, ok]), "ACCEPTED@2");
  assert.equal(rejected([...base, sign(base, rotation({ ownerPolicy: { threshold: 1 } }), [O1, O2])]), "TRANSITION_INVALID@2");                 // dropping
  assert.equal(rejected([...base, sign(base, rotation({ nextKeyDigests: [ownerKeyDigest(O3)], ownerPolicy: { threshold: 1 } }), [O1, O2])]), "TRANSITION_INVALID@2"); // replacing
  assert.equal(rejected([...base, sign(base, rotation({ nextKeyDigests: [ownerKeyDigest(N1)], ownerPolicy: { threshold: 2 } }), [O1, O2])]), "TRANSITION_INVALID@2"); // same keys, same policy
  const counts = core.ownerKeyRotationCounts(replay([...base, ok]).state);
  assert.deepEqual(counts, { keyRotations: 0, commitmentRotations: 0, policyRotations: 1 });
  // A-100.1 / A-120.1: the witness verifier reads the epoch's policy and judges the same rotation as replay (a policy rotation).
  const epochs = [{ fromPosition: 0, keys: [pub(O1), pub(O2)], nextKeyDigests: [ownerKeyDigest(N1)], policy: { threshold: 2 } }];
  const verdict = core.verifyRotationEvent(ok, { domain: DOMAIN, previousHead: { hash: headOf(base).hash, position: 1 }, epochs });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.policyRotation, true);
  assert.equal(verdict.stateChecked, false);
  assert.deepEqual(verdict.epochs.at(-1).policy, { threshold: 1 });
  // An older witness's epochs without the policy (the default {threshold: 1}): the co-signed rotation is refused at step 2.
  const older = core.verifyRotationEvent(ok, { domain: DOMAIN, previousHead: { hash: headOf(base).hash, position: 1 }, epochs: [{ ...epochs[0], policy: undefined }] });
  assert.equal(older.ok, false);
  assert.equal(older.code, "CONTROL_AUTHORIZATION_INVALID");
});

test("A-91.2 / A-99 / A-102 validity at the genesis and on a rotation (EVENT_DATA_INVALID), and the formerly held fields", () => {
  const at0 = (policy, keys = [O1, O2, O3]) => rejected([genesis(keys, { ownerPolicy: policy })]);
  assert.equal(at0({ threshold: 4 }), "EVENT_DATA_INVALID@0");
  assert.equal(at0({ threshold: 1, byType: { TRANSACTION_INTENT_DECLARED: 1 } }), "EVENT_DATA_INVALID@0");
  assert.equal(at0({ threshold: 1, acknowledged: "SINGLE_SIGNER", byType: { ROLE_CREATED: 1 } }), "EVENT_DATA_INVALID@0");
  assert.equal(at0({ threshold: 1, humanFloor: "DECLARED" }), "ACCEPTED@0");                    // A-93 (hold lifted)
  assert.equal(at0({ threshold: 1, humanFloor: "ATTESTED" }), "EVENT_DATA_INVALID@0");          // A-93.2 rule 1: needs attesters and statements
  assert.equal(at0({ threshold: 1, recovery: "COMMITTED_NEXT_KEYS" }), "ACCEPTED@0");            // A-97 (hold lifted): in the schema
  assert.equal(at0({ threshold: 1, recovery: "ANY_NEXT_KEY" }), "EVENT_DATA_INVALID@0");          // a closed literal
  assert.equal(at0({ threshold: 1 }, [O1, { ...pub(O2), keyId: "owner:1b", credential: O1.credential }]), "EVENT_DATA_INVALID@0"); // A-99
  // Without a policy the alias is today's behaviour.
  const alias = genesis([O1, { ...pub(O2), keyId: "owner:1b", credential: O1.credential }]);
  assert.equal(rejected([alias, sign([alias], principal, [O1])]), "ACCEPTED@1");
  // On a rotation the validity follows control authorization and the key test.
  const g = genesis([O1, O2], { ownerPolicy: { threshold: 1 } });
  const base = [g, sign([g], principal, [O1])];
  const bad = { id: "event:rotation", type: "OWNER_KEYS_ROTATED", timestamp: 103, data: { ownerKeys: [pub(O1), pub(O2)], nextKeyDigests: [ownerKeyDigest(N1)], ownerPolicy: { threshold: 3 } } };
  assert.equal(rejected([...base, sign(base, bad, [O1])]), "EVENT_DATA_INVALID@2");
  assert.equal(rejected([...base, { ...sign(base, bad, [O1]), data: { ...sign(base, bad, [O1]).data, controlAuthorization: { keyId: "owner:1", signature: `0x${"00".repeat(64)}` } } }]), "CONTROL_AUTHORIZATION_INVALID@2");
});

test("maximum sizes (A-95.7, MAILBOX-G6.1 item 12): a rotation with 63 co-signatures and 64 nextKeyAuthorizations, and its epoch record", (t) => {
  const current = Array.from({ length: 64 }, (_, i) => pair(`owner:${i + 1}`, 0x7000 + i));
  const next = Array.from({ length: 64 }, (_, i) => pair(`next:${i + 1}`, 0x7100 + i));
  const after = Array.from({ length: 64 }, (_, i) => pair(`after:${i + 1}`, 0x7200 + i));
  const labels = Object.fromEntries(next.map((p) => [p.keyId, "L".repeat(64)]));
  const g = genesis(current, { nextKeyDigests: next.map(ownerKeyDigest), ownerPolicy: { threshold: 1, byType: { OWNER_KEYS_ROTATED: 64 } } });
  const base = [g, sign([g], principal, [current[0]])];
  const rotation = sign(base, { id: "event:rotation", type: "OWNER_KEYS_ROTATED", timestamp: 103, data: { ownerKeys: next.map(pub), nextKeyDigests: after.map(ownerKeyDigest), ownerPolicy: { threshold: 1, byType: { OWNER_KEYS_ROTATED: 64 }, labels } } }, current, next);
  assert.equal(rotation.data.additionalControlAuthorizations.length, 63);
  const result = replay([...base, rotation]);
  assert.equal(result.status, "ACCEPTED", result.reason);
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g6-size-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "history.jsonl");
  createHistoryStore(path, [...base, rotation], { witness: false, readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true }).close?.();
  const line = readFileSync(path, "utf8").split("\n")[2];
  const epoch = stateRecordsOf(result.state).find((r) => r.kind === "ownerKeyEpoch" && r.key === "1").record;
  const sizes = { rotationLineBytes: Buffer.byteLength(line, "utf8"), epochRecordBytes: Buffer.byteLength(canonicalEncode(epoch), "utf8") };
  t.diagnostic(`maximum sizes: ${JSON.stringify(sizes)}`);
  assert.ok(sizes.rotationLineBytes < 1_048_576);
});

// ---------------------------------------------------------------- the writer (A-92.4, A-96.4)

async function owner(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g6-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 1000;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, signer: signerFromKeyPair(O1), witness: false, ...options };
  const handle = await createLocalOwner(config);
  return { handle, config, dir, advance: () => (tick += 1) };
}
const cosign = async (prepared, ...pairs) => Promise.all(pairs.map((p) => core.authorizeControlEvent(signerFromKeyPair(p), prepared)));

test("A-92.4: prepare, collect and submit; a short submit (CONTROL_AUTHORIZATION_INVALID {required, present}); a moved head (HISTORY_CONFLICT); single-signer writes refused under M ≥ 2", async (t) => {
  const { handle } = await owner(t, { coOwnerKeys: [pub(O2), pub(O3)], ownerPolicy: { threshold: 1, byType: { ROLE_CREATED: 2 } } });
  await handle.createAgent({ id: "bea" }); // M = 1
  await assert.rejects(handle.createRole({ id: "reviewer" }), (e) => e.code === "CONTROL_AUTHORIZATION_INVALID" && e.detail.required === 2 && e.detail.present === 1);
  const prepared = await handle.prepareControlEvent({ type: "ROLE_CREATED", data: { roleId: "reviewer", principalId: "operations", exclusive: true } });
  assert.equal(prepared.required, 2);
  assert.deepEqual(prepared.signers.map((s) => [s.keyId, s.class, s.counts]), [["owner:1", "HUMAN", true], ["owner:2", "HUMAN", true], ["owner:3", "HUMAN", true]]);
  await assert.rejects(handle.submitControlEvent(prepared, await cosign(prepared, O1)), (e) => e.code === "CONTROL_AUTHORIZATION_INVALID" && e.detail.required === 2 && e.detail.present === 1);
  const result = await handle.submitControlEvent(prepared, await cosign(prepared, O1, O3));
  assert.equal(handle.exportHistory().at(-1).data.additionalControlAuthorizations.length, 1);
  assert.equal(result.head.position, 3);
  // A consent is never re-signed onto a new head.
  const stale = await handle.prepareControlEvent({ type: "ROLE_CREATED", data: { roleId: "auditor", principalId: "operations", exclusive: true } });
  const entries = await cosign(stale, O1, O2);
  await handle.createAgent({ id: "cal" });
  await assert.rejects(handle.submitControlEvent(stale, entries), code("HISTORY_CONFLICT"));
  assert.equal(handle.verify().ok, true);
});

test("A-96: rotateOwnerPolicy (committed epoch, commitment carried), policyRotations, a 2-of-3 policy then co-signed writes and a co-signed reset", async (t) => {
  const { handle } = await owner(t, { coOwnerKeys: [pub(O2), pub(O3)] });
  await handle.createAgent({ id: "bea" });
  const before = handle.ownerKeyStatus();
  assert.equal(before.commitment.source, "GENESIS");
  await handle.rotateOwnerPolicy({ ownerPolicy: { threshold: 2, labels: { "owner:1": "laptop" } } });
  const status = handle.ownerKeyStatus();
  assert.deepEqual(status.ownerPolicy, { threshold: 2, labels: { "owner:1": "laptop" } });
  assert.deepEqual([status.keyRotations, status.commitmentRotations, status.policyRotations], [0, 0, 1]);
  assert.deepEqual(status.commitment.nextKeyDigests, before.commitment.nextKeyDigests);
  assert.equal(status.commitment.source, "GENESIS"); // carried over, not re-committed
  await assert.rejects(handle.createAgent({ id: "cal" }), code("CONTROL_AUTHORIZATION_INVALID"));
  await assert.rejects(handle.rotateOwnerPolicy({ resetPolicy: true }), (e) => e.code === "CONTROL_AUTHORIZATION_INVALID" && e.detail.required === 2);
  await assert.rejects(handle.rotateOwnerPolicy({ ownerPolicy: { threshold: 2, labels: { "owner:1": "laptop" } } }), code("INVALID_INPUT"));
  const reset = await handle.prepareOwnerPolicyRotation({ resetPolicy: true });
  await handle.submitControlEvent(reset, await cosign(reset, O2, O3));
  assert.equal(handle.ownerKeyStatus().ownerPolicy, null);
  assert.equal(handle.ownerKeyStatus().policyRotations, 2);
  await handle.createAgent({ id: "cal" });
  assert.equal(handle.verify().ok, true);
});

test("A-96.4: POLICY_RESET for a key rotation without ownerPolicy; commitNextKey restates the policy; co-signed key rotation under M_rot = 2", async (t) => {
  const { handle } = await owner(t, { nextKey: false, ownerPolicy: { threshold: 1, labels: { "owner:1": "laptop" } }, coOwnerKeys: [pub(O2)] });
  await assert.rejects(handle.rotateOwnerKey({ retire: ["owner:1"], newSigner: signerFromKeyPair(O3) }), code("INVALID_INPUT", "POLICY_RESET"));
  const committed = await handle.commitNextKey({ nextPublicKey: N1.credential });
  assert.equal(committed.nextKeyDigests.length, 1);
  let status = handle.ownerKeyStatus();
  assert.deepEqual(status.ownerPolicy, { threshold: 1, labels: { "owner:1": "laptop" } });
  assert.deepEqual([status.commitmentRotations, status.policyRotations], [1, 0]);
  // Raise M_rot to 2; then a key rotation needs a co-signature (prepare, co-sign, commit).
  await handle.rotateOwnerPolicy({ ownerPolicy: { threshold: 2 } });
  await assert.rejects(handle.rotateOwnerKey({ nextSigner: signerFromKeyPair(N1), retire: ["owner:1"], ownerPolicy: { threshold: 2 } }), (e) => e.code === "CONTROL_AUTHORIZATION_INVALID" && e.detail.required === 2);
  const prepared = await handle.prepareOwnerKeyRotation({ nextSigner: signerFromKeyPair(N1), retire: ["owner:1"], ownerPolicy: { threshold: 2 }, newNextPublicKey: pair("next:2", 0x6202).credential });
  assert.equal(prepared.required, 2);
  const [entry] = await cosign(prepared, O2);
  const rotated = await handle.commitOwnerKeyRotation(prepared, { additionalAuthorizations: [entry] });
  assert.equal(rotated.preRotated, true);
  status = handle.ownerKeyStatus();
  assert.deepEqual(status.ownerKeys.map((k) => k.keyId), ["owner:2", "next:1"]);
  assert.deepEqual(status.ownerPolicy, { threshold: 2 });
  assert.equal(handle.verify().ok, true);
});

test("A-92.3(b): an automatic checkpoint the handle cannot sign to M_eff(STATE_CHECKPOINT) = 2 is CHECKPOINT_SUPPRESSED {reason: NO_SIGNER}, never written short", async (t) => {
  const { handle } = await owner(t, { coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 1, byType: { STATE_CHECKPOINT: 2 } }, checkpointPolicy: { everyEvents: 1 } });
  const result = await handle.createAgent({ id: "bea" });
  assert.equal(result.checkpoint?.code, "CHECKPOINT_SUPPRESSED");
  assert.equal(result.checkpoint?.reason, "NO_SIGNER");
  assert.equal(handle.exportHistory().some((e) => e.type === "STATE_CHECKPOINT"), false);
});

test("A-174.2: under M_eff(STATE_CHECKPOINT) = 2 with one local signer, succeed() completes without its seal and reports CHECKPOINT_SUPPRESSED {NO_SIGNER}; a single-phase checkpoint() is CONTROL_AUTHORIZATION_INVALID {required, present}", async (t) => {
  const { handle } = await owner(t, { coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 1, byType: { STATE_CHECKPOINT: 2 } } });
  await handle.createAgent({ id: "bea" });
  await handle.createAgent({ id: "cal" });
  await handle.createRole({ id: "desk" });
  await handle.declareSuccession({ id: "rule:1", from: "bea", to: "cal", role: "desk" });
  await handle.appoint({ agent: "bea", role: "desk", tenure: "shift:1", number: 1, succession: "rule:1" });
  const result = await handle.succeed({ id: "h:1", rule: "rule:1", fromAgent: "bea", fromTenure: "shift:1", toAgent: "cal", toTenure: "shift:2", role: "desk", number: 2 });
  assert.equal(result.status, "HANDOVER_RECORDED");
  assert.equal(result.checkpoint?.code, "CHECKPOINT_SUPPRESSED");
  assert.equal(result.checkpoint?.reason, "NO_SIGNER");
  const history = handle.exportHistory();
  assert.equal(history.some((e) => e.type === "STATE_CHECKPOINT"), false, "never written short");
  assert.deepEqual(result.eventIds, history.slice(-2).map((e) => e.id), "eventIds names the two handover steps only");
  assert.deepEqual(history.slice(-2).map((e) => e.type), ["AGENT_TERMINATED", "ROLE_TRANSFERRED"]);
  await assert.rejects(handle.checkpoint(), (e) => e.code === "CONTROL_AUTHORIZATION_INVALID" && e.detail?.required === 2 && e.detail?.present === 1);
  assert.equal(handle.verify().ok, true);
});

test("A-101.2 resume-root-human-both-policies: a pin by a HUMAN key under the policy seeds a resume, and the policy history's export view verifies (A-101.1)", async (t) => {
  const { handle, config } = await owner(t, { coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 1, labels: { "owner:2": "phone" } } });
  await handle.createAgent({ id: "bea" });
  await handle.checkpoint();
  await handle.createAgent({ id: "cal" });
  handle.close();
  resetStoreCountersForTests();
  const store = openHistoryStore(config.historyFile, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(store.loadedBy(), "CHECKPOINT_RESUME");
  assert.equal(storeCounters.resumes, 1);
  const report = store.verify();
  assert.equal(report.ok, true);
  assert.equal(report.snapshot, "USED");
  assert.equal(report.notes.some((note) => note.startsWith("FULL_REPLAY")), false);
  store.close?.();
  const reopened = openLocalOwner(config);
  const view = reopened.exportView({ fromPosition: 2, toPosition: 4, include: { fromRecords: true, referencedEvents: true, keyEvents: true, attestations: true } });
  const verified = core.verifyExportView(JSON.parse(JSON.stringify(view)));
  assert.equal(verified.ok, true, JSON.stringify(verified.failures));
  assert.deepEqual(verified.ownerKeyEpochs[0].policy, { threshold: 1, labels: { "owner:2": "phone" } });
});

test("creation: a genesis policy the creation's own events cannot satisfy is refused before any file exists; coOwnerKeys need format 2", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g6-create-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const base = { historyFile: join(dir, "h.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => 1000, signer: signerFromKeyPair(O1), witness: false };
  await assert.rejects(createLocalOwner({ ...base, coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 2 } }), code("INVALID_INPUT", "POLICY_UNSATISFIABLE_AT_CREATION"));
  await assert.rejects(createLocalOwner({ ...base, coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 3 } }), code("INVALID_INPUT"));
  await assert.rejects(createLocalOwner({ ...base, format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, domain: { ...createLocalDomain(), version: "1" }, coOwnerKeys: [pub(O2)] }), code("INVALID_INPUT"));
});

test("A-197.1 (SHOULD): writing a policy that carries recovery warns OWNER_POLICY_RECOVERY_NO_WRITER, and ownerKeyStatus warns while it is in force; a policy without recovery does not", async (t) => {
  const { handle } = await owner(t, { coOwnerKeys: [pub(O2), pub(O3)] });
  const plain = await handle.rotateOwnerPolicy({ ownerPolicy: { threshold: 1 } });
  assert.equal(plain.warning, undefined);
  assert.equal(handle.ownerKeyStatus().warnings.some((w) => w.code === "OWNER_POLICY_RECOVERY_NO_WRITER"), false);
  const withRecovery = await handle.rotateOwnerPolicy({ ownerPolicy: { threshold: 1, recovery: "COMMITTED_NEXT_KEYS" } });
  assert.equal(withRecovery.warning, core.OWNER_POLICY_RECOVERY_NO_WRITER);
  assert.match(withRecovery.warning, /^OWNER_POLICY_RECOVERY_NO_WRITER: .*\(known issue 24, A-197\)$/);
  // The number points at the published entry for it (LAUNCH-TEXT-01, A-003): KNOWN-ISSUES 24 is the missing recovery writer.
  const knownIssues = readFileSync(new URL("../../../docs/records/KNOWN-ISSUES-r2.5.md", import.meta.url), "utf8");
  assert.match(knownIssues, /^24\. \*\*No writer path for a recovery rotation \(A-197\.1/m);
  const warned = handle.ownerKeyStatus().warnings.find((w) => w.code === "OWNER_POLICY_RECOVERY_NO_WRITER");
  assert.ok(warned && /no writer/.test(warned.message), JSON.stringify(handle.ownerKeyStatus().warnings));
  // JOB75-08: the two-phase path warns on both halves; a policy without recovery does not.
  const prepared = await handle.prepareOwnerPolicyRotation({ ownerPolicy: { threshold: 1, recovery: "COMMITTED_NEXT_KEYS", labels: { "owner:1": "two-phase" } } });
  assert.equal(prepared.warning, core.OWNER_POLICY_RECOVERY_NO_WRITER);
  const signature = await signerFromKeyPair(O1).signHash(prepared.challengeHash);
  assert.equal((await handle.submitControlEvent(prepared, [{ keyId: "owner:1", signature }])).warning, core.OWNER_POLICY_RECOVERY_NO_WRITER);
  assert.equal((await handle.prepareOwnerPolicyRotation({ ownerPolicy: { threshold: 1 } })).warning, undefined);
});

test("JOB75-08 / A-197.1: a genesis policy carrying recovery is warned by ownerKeyStatus from the first open (no write result carries it)", async (t) => {
  const { handle } = await owner(t, { coOwnerKeys: [pub(O2), pub(O3)], ownerPolicy: { threshold: 1, recovery: "COMMITTED_NEXT_KEYS" } });
  assert.ok(handle.ownerKeyStatus().warnings.some((w) => w.code === "OWNER_POLICY_RECOVERY_NO_WRITER"));
});
