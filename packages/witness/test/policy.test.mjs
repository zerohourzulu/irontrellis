// Owner approval policies at the witness (A-100, A-111.3, A-120; the G6.x holds were lifted on 2026-10-12): the
// rotation verifier reads the policy of the epoch a rotation leaves (quorum, recovery, policy rotations), epoch 0's
// policy comes from the registered genesis, a head statement's signer must be qualified under the epoch's policy
// (WITNESS_SIGNER_UNQUALIFIED), an older witness without the policy is behind (WITNESS_POLICY_UNKNOWN), and the
// verifier's result says it did not check the replayed state (stateChecked: false). Real format-2 events.
import { test } from "node:test";
import assert from "node:assert/strict";
import { core, keyPair, ownerKeyOf, signerOf, t, witnessLib, wire } from "./helpers.mjs";

const { emptyState, decideRegister, decideHead, decideKeyEvent, applyEntry, ERROR_CODES } = witnessLib;

const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "2", deploymentId: "witness-policy" });
const pub = ownerKeyOf;
const O1 = keyPair("owner:1", 0x9001), O2 = keyPair("owner:2", 0x9002), O3 = keyPair("owner:3", 0x9003), O4 = keyPair("owner:4", 0x9004);
const A1 = keyPair("agent:1", 0x9101), N1 = keyPair("next:1", 0x9201), N2 = keyPair("next:2", 0x9202);
const AT1 = keyPair("attester:1", 0x9301), AT2 = keyPair("attester:2", 0x9302);

const genesis = (keys, extra = {}) => ({
  id: "event:genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 100,
  data: {
    adapterPolicyHash: core.ADAPTER_POLICY_HASH, canonicalLineageId: "lineage:witness-policy", domain: DOMAIN, finality: "LOCAL_ONLY", globalPolicySourceId: "policy:witness-policy",
    ownerKeys: keys.map(pub), policyVersion: "irontrellis-local-owner/2", rootRecognitionPolicy: "declared-principal-root/0.2", timeSource: "EVENT_TIMESTAMP",
    versions: { ...core.FORMAT2_VERSIONS, signatureScheme: "ed25519" }, ...extra,
  },
});
const statementBody = async (domain, subject, attester, notBefore, expiresAt, historyId) => {
  const body = { version: core.HUMAN_ATTESTATION_VERSION, audience: domain, subject: pub(subject), profile: "phl:ceremony/1", attesterKeyId: attester.keyId, evidenceDigest: `0x${"cd".repeat(32)}`, notBefore, expiresAt, ...(historyId === undefined ? {} : { historyId }) };
  return { ...body, signature: await core.signHashWith(attester)(core.humanAttestationHash({ ...body, signature: "" })) };
};

/** A format-2 history built event by event (every prefix replayed), with signing and head statements. */
function history(g) {
  const events = [g];
  const replayed = () => { const r = core.replay(events); assert.equal(r.status, "ACCEPTED", r.reason); return r.head; };
  const heads = [replayed()];
  const historyId = heads[0].hash;
  const sign = async (event, [first, ...rest], proofs = []) => {
    const head = heads.at(-1);
    const hash = core.controlAuthorizationHash({ domain: DOMAIN, eventId: event.id, eventType: event.type, timestamp: event.timestamp, previousHead: { hash: head.hash, position: head.position }, effectHash: core.controlEffectHash(event, "sha256") }, "sha256");
    const entry = async (p) => ({ keyId: p.keyId, signature: await core.signHashWith(p)(hash) });
    return {
      ...event, data: {
        ...event.data, controlAuthorization: await entry(first), ...(rest.length === 0 ? {} : { additionalControlAuthorizations: await Promise.all(rest.map(entry)) }),
        ...(proofs.length === 0 ? {} : { nextKeyAuthorizations: await Promise.all(proofs.map(async (p) => ({ ...(await entry(p)), scheme: "ed25519" }))) }),
      },
    };
  };
  const push = (event) => { events.push(event); heads.push(replayed()); return heads.length - 1; };
  const at = (p) => ({ hash: heads[p].hash, position: p });
  const statement = (p, q, pair, head = heads[p]) => t.signHeadStatement(signerOf(pair), { version: t.HEAD_STATEMENT_VERSION, historyId, domain: DOMAIN, head, previous: q === null ? null : at(q) });
  return { events, heads, historyId, sign, push, at, statement, next: () => 100 + events.length };
}

function pureWitness() {
  const state = emptyState();
  const entries = [];
  const lookup = (index) => entries[index];
  const context = () => ({ now: 1_000, lookup });
  const run = (decision) => {
    for (const entry of decision.append?.entries ?? []) {
      const index = entries.length;
      entries.push(entry);
      assert.equal(applyEntry(state, entry, index, { lookup, verify: true }), null);
    }
    return decision;
  };
  return {
    state, entries,
    register: (body) => run(decideRegister(state, wire(body), context())),
    head: (id, body) => run(decideHead(state, id, wire(body), context())),
    keyEvent: (id, body) => run(decideKeyEvent(state, id, wire(body), context())),
  };
}
const code = (decision) => decision.error?.code;
const principal = (h) => ({ id: "event:principal", type: "PRINCIPAL_CREATED", timestamp: h.next(), data: { principalId: "operations" } });
const rotation = (h, data, id = "event:rotation") => ({ id, type: "OWNER_KEYS_ROTATED", timestamp: h.next(), data });

test("A-100.2: under M_rot = 2 a 2-of-3 rotation is accepted and a 1-of-3 refused; epoch 0's policy from the genesis; the new epoch's policy as written; stateChecked: false", async () => {
  const policy = { threshold: 1, byType: { OWNER_KEYS_ROTATED: 2 } };
  const h = history(genesis([O1, O2, O3], { ownerPolicy: policy }));
  h.push(await h.sign(principal(h), [O1]));
  const w = pureWitness();
  assert.equal(w.register({ genesis: h.events[0] }).status, 201);
  assert.deepEqual(w.state.histories.get(h.historyId).epochs[0].policy, policy, "Register {genesis} seeds epoch 0's policy");
  assert.equal(w.head(h.historyId, await h.statement(0, null, O1)).status, 201);
  assert.equal(w.head(h.historyId, await h.statement(1, 0, O1)).status, 201);
  const data = { ownerKeys: [pub(O1), pub(O2), pub(O4)], ownerPolicy: policy, reason: "replace owner:3" };
  const single = await h.sign(rotation(h, data), [O1]);
  const refused = w.keyEvent(h.historyId, { event: single, previousHead: h.at(1), eventHead: { hash: h.heads[1].hash, position: 2 } });
  assert.equal(code(refused), "KEY_EVENT_INVALID");
  assert.match(refused.error.message, /needs 2 owner signatures/);
  const pair = await h.sign(rotation(h, data), [O1, O2]);
  const position = h.push(pair);
  const accepted = w.keyEvent(h.historyId, { event: pair, previousHead: h.at(position - 1), eventHead: h.at(position), statement: await h.statement(position, position - 1, O1) });
  assert.equal(accepted.status, 201, accepted.error?.message);
  const epochs = w.state.histories.get(h.historyId).epochs;
  assert.deepEqual(epochs.map((e) => [e.fromPosition, e.keys.map((k) => k.keyId), e.policy]), [[0, ["owner:1", "owner:2", "owner:3"], policy], [3, ["owner:1", "owner:2", "owner:4"], policy]]);
  assert.deepEqual(w.state.histories.get(h.historyId).epochFacts.map((f) => f.policyKnown), [true, true], "the policyKnown marker (A-111.3)");
  // A-120.1 / A-120.3: the verifier the witness uses says it did not check the replayed state.
  const verdict = core.verifyRotationEvent(pair, { domain: DOMAIN, previousHead: { ...h.at(position - 1), canonicalTime: h.heads[position - 1].canonicalTime }, epochs: [{ fromPosition: 0, keys: [pub(O1), pub(O2), pub(O3)], policy }], openedAt: [100], historyId: h.historyId });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.stateChecked, false);
  assert.deepEqual([verdict.quorum.required, verdict.quorum.signers.map((s) => s.keyId)], [2, ["owner:1", "owner:2"]]);
});

test("A-100.2: a recovery rotation is refused under a policy without recovery and accepted under COMMITTED_NEXT_KEYS; a policy rotation out of a committed epoch is accepted", async () => {
  for (const [policy, expected] of [[{ threshold: 1 }, "KEY_EVENT_INVALID"], [{ threshold: 1, recovery: "COMMITTED_NEXT_KEYS" }, undefined]]) {
    const h = history(genesis([O1], { nextKeyDigests: [core.ownerKeyDigest(N1)], ownerPolicy: policy }));
    h.push(await h.sign(principal(h), [O1]));
    const w = pureWitness();
    w.register({ genesis: h.events[0] });
    w.head(h.historyId, await h.statement(0, null, O1));
    w.head(h.historyId, await h.statement(1, 0, O1));
    const recover = await h.sign(rotation(h, { ownerKeys: [pub(N1)], nextKeyDigests: [core.ownerKeyDigest(N2)], ownerPolicy: policy }), [N1], [N1]);
    if (expected !== undefined) {
      const refused = w.keyEvent(h.historyId, { event: recover, previousHead: h.at(1), eventHead: { hash: h.heads[1].hash, position: 2 } });
      assert.equal(code(refused), expected);
      assert.match(refused.error.message, /not an owner key in force/);
      continue;
    }
    const position = h.push(recover);
    const accepted = w.keyEvent(h.historyId, { event: recover, previousHead: h.at(1), eventHead: h.at(position), statement: await h.statement(position, 1, O1) });
    assert.equal(accepted.status, 201, accepted.error?.message);
    assert.deepEqual(w.state.histories.get(h.historyId).epochs.at(-1).keys.map((k) => k.keyId), ["next:1"]);
  }
  // A policy rotation out of a committed epoch: every key kept, the commitment restated, no proof.
  const h = history(genesis([O1, O2], { nextKeyDigests: [core.ownerKeyDigest(N1)], ownerPolicy: { threshold: 2 } }));
  h.push(await h.sign(principal(h), [O1, O2]));
  const w = pureWitness();
  w.register({ genesis: h.events[0] });
  w.head(h.historyId, await h.statement(0, null, O1));
  w.head(h.historyId, await h.statement(1, 0, O1));
  const relax = await h.sign(rotation(h, { ownerKeys: [pub(O1), pub(O2)], nextKeyDigests: [core.ownerKeyDigest(N1)], ownerPolicy: { threshold: 1 } }), [O1, O2]);
  const position = h.push(relax);
  const accepted = w.keyEvent(h.historyId, { event: relax, previousHead: h.at(1), eventHead: h.at(position), statement: await h.statement(position, 1, O2) });
  assert.equal(accepted.status, 201, accepted.error?.message);
  assert.deepEqual(w.state.histories.get(h.historyId).epochs.at(-1).policy, { threshold: 1 });
  assert.equal(w.entries.at(-1).kind, "ROTATED");
});

test("A-111.3 / A-111.4: an AGENT-signed head statement under DECLARED and a LAPSED-signed one under ATTESTED are WITNESS_SIGNER_UNQUALIFIED and not recorded", async () => {
  assert.ok(ERROR_CODES.includes("WITNESS_SIGNER_UNQUALIFIED") && ERROR_CODES.includes("WITNESS_POLICY_UNKNOWN"));
  const declared = history(genesis([O1, A1], { ownerPolicy: { threshold: 1, keyClasses: { "agent:1": "AGENT" } } }));
  declared.push(await declared.sign(principal(declared), [O1]));
  const w = pureWitness();
  w.register({ genesis: declared.events[0] });
  const agent = w.head(declared.historyId, await declared.statement(0, null, A1));
  assert.equal(code(agent), "WITNESS_SIGNER_UNQUALIFIED");
  assert.match(agent.error.message, /AGENT/);
  assert.equal(w.entries.length, 1, "nothing recorded");
  assert.equal(w.head(declared.historyId, await declared.statement(0, null, O1)).status, 201);
  // ATTESTED: owner:1's statement covers [0, 150); a head statement at canonicalTime 150 or later is by a LAPSED key.
  const domain = DOMAIN;
  const attestations = [await statementBody(domain, O1, AT1, 0, 150), await statementBody(domain, O2, AT2, 0, 10_000)];
  const attested = history(genesis([O1, O2], { ownerPolicy: { threshold: 1, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations } }));
  attested.push(await attested.sign(principal(attested), [O1]));
  const v = pureWitness();
  v.register({ genesis: attested.events[0] });
  assert.equal(v.head(attested.historyId, await attested.statement(0, null, O1)).status, 201, "HUMAN at 100");
  const late = { ...attested.heads[1], canonicalTime: 200 };
  const lapsed = v.head(attested.historyId, await attested.statement(1, 0, O1, late));
  assert.equal(code(lapsed), "WITNESS_SIGNER_UNQUALIFIED");
  assert.match(lapsed.error.message, /LAPSED/);
  assert.equal(v.head(attested.historyId, await attested.statement(1, 0, O2, late)).status, 201, "owner:2 is HUMAN at 200");
});

test("A-100.1: a witness that does not know the policy of the epoch in force is behind: WITNESS_POLICY_UNKNOWN for a rotation and for a head statement", async () => {
  const h = history(genesis([O1], { ownerPolicy: { threshold: 1 } }));
  h.push(await h.sign(principal(h), [O1]));
  const w = pureWitness();
  w.register({ genesis: h.events[0] });
  w.head(h.historyId, await h.statement(0, null, O1));
  // An older witness's epoch record (no policy carried over): simulated by marking the epoch unknown.
  const record = w.state.histories.get(h.historyId);
  record.epochFacts = [{ ...record.epochFacts[0], policyKnown: false }];
  assert.equal(code(w.head(h.historyId, await h.statement(1, 0, O1))), "WITNESS_POLICY_UNKNOWN");
  const event = await h.sign(rotation(h, { ownerKeys: [pub(O1), pub(O2)], ownerPolicy: { threshold: 1 } }), [O1]);
  assert.equal(code(w.keyEvent(h.historyId, { event, previousHead: h.at(1), eventHead: { hash: h.heads[1].hash, position: 2 } })), "WITNESS_POLICY_UNKNOWN");
});

test("G63-X-4 at the witness: T2 needs the canonicalTime of the head before a rotation; without that head the rotation is not judged (KEY_EVENT_HEAD_UNKNOWN), with it a lone LAPSED restorer past the horizon is refused", async () => {
  const domain = DOMAIN;
  const attestations = [await statementBody(domain, O1, AT1, 0, 1_000), await statementBody(domain, O2, AT2, 0, 1_000)];
  const policy = { threshold: 1, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations };
  const h = history(genesis([O1, O2], { ownerPolicy: policy }));
  h.push(await h.sign(principal(h), [O1]));
  const w = pureWitness();
  w.register({ genesis: h.events[0] });
  w.head(h.historyId, await h.statement(0, null, O1));
  // At 2000 every statement has expired (H = 1000). A restoration renews both; LAPSED owner:1 counts alone (A-107.2), so
  // T2 applies (hc = 1): the timestamp must be the head's (τ = 102) or at most H.
  const renewed = [await statementBody(domain, O1, AT1, 1_500, 5_000, h.historyId), await statementBody(domain, O2, AT2, 1_500, 5_000, h.historyId)];
  const event = await h.sign({ ...rotation(h, { ownerKeys: [pub(O1), pub(O2)], ownerPolicy: { ...policy, attestations: renewed } }), timestamp: 2_000 }, [O1]);
  const unheld = w.keyEvent(h.historyId, { event, previousHead: h.at(1), eventHead: { hash: h.heads[1].hash, position: 2 } });
  assert.equal(code(unheld), "KEY_EVENT_HEAD_UNKNOWN");
  assert.match(unheld.error.message, /not judged/);
  w.head(h.historyId, await h.statement(1, 0, O1));
  const judged = w.keyEvent(h.historyId, { event, previousHead: h.at(1), eventHead: { hash: h.heads[1].hash, position: 2 } });
  assert.equal(code(judged), "KEY_EVENT_INVALID");
  assert.match(judged.error.message, /attestation horizon/);
  // Replay agrees: TRANSITION_INVALID at 2 (T2, after control authorization).
  const r = core.replay([...h.events, event]);
  assert.deepEqual([r.status, r.code, r.position], ["REJECTED", "TRANSITION_INVALID", 2]);
});

test("A-131.2 (ce34): the attester clause of A-117.3 stays in acceptSF: the witness refuses a rotation that commits to an attester of the policy in force", async () => {
  const domain = DOMAIN;
  const attestations = [await statementBody(domain, O1, AT1, 0, 10_000), await statementBody(domain, O2, AT2, 0, 10_000)];
  const h = history(genesis([O1, O2], { ownerPolicy: { threshold: 1, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations } }));
  h.push(await h.sign(principal(h), [O1]));
  const w = pureWitness();
  w.register({ genesis: h.events[0] });
  w.head(h.historyId, await h.statement(0, null, O1));
  w.head(h.historyId, await h.statement(1, 0, O1));
  const event = await h.sign(rotation(h, { ownerKeys: [pub(O1), pub(O2)], nextKeyDigests: [core.ownerKeyDigest(AT1)], ownerPolicy: { threshold: 1 } }), [O1]);
  const refused = w.keyEvent(h.historyId, { event, previousHead: h.at(1), eventHead: { hash: h.heads[1].hash, position: 2 } });
  assert.equal(code(refused), "KEY_EVENT_INVALID");
  assert.match(refused.error.message, /names attester attester:1/);
  const r = core.replay([...h.events, event]);
  assert.deepEqual([r.status, r.code, r.position], ["REJECTED", "TRANSITION_INVALID", 2]);
});
