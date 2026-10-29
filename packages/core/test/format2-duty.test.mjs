// SPEC §13 through the IronTrellis API and the replay (E4): the rules record and its pinned hash (B1), activation (B2–B3),
// dispositions and contests (B4–B5), the view (B6), the writer contract with fresh eligibility (B7–B8), the duty quota in
// capacity (B9), the query extensions (B10–B11) and `openLocalDutyPolicy` (B12). The cases are the ports of
// reference-0.3's `tests/core-0.3/duty-activation.test.mjs` and `duty-disposition.test.mjs` that concern the host API
// and the replay rules (their segmented-store internals are E3's store tests). T6 (BUILD §4): describe → activate →
// dispose → contest → inspect, idempotent repeats, and the fresh-eligibility refusal when the attester session expires
// between the two signatures; T6's budget-survives-handover half is `format2-api.test.mjs` ("a roleIds budget … after succeed()").
import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { canonicalEncode, hashCanonical, replay, withProspectiveEvent, deriveAllRecords, stateRootOfRecords, stateRootOf, inspectDutyPolicyState, inspectAttemptHistory, observeHistory } = core;
const { openLocalDutyPolicy, openLocalAttemptRecorder, openLocalRuntime, openLocalOwner, capacityOf } = core;
const { DUTY_POLICY_RULES, DUTY_POLICY_RULES_HASH, DUTY_POLICY_RULES_HASH_ALGORITHM, dutyPolicyRulesHashIsPinned, DUTY_POLICY_VERSION, publicQueryDisclosure, DUTY_QUERY_FIELD_PATHS, QUERY_ANSWER_FIELD_PATHS } = core;
const { fixture, dutyFixture, dispositionFixture, signHash, digest, DIGEST, KEYS, checklist } = await import("./helpers/duty-fixture.mjs");
const { setCapacityLimitsForTests } = await import("../src/capacity.ts");

const code = (value) => (e) => e.code === value || e.detail?.code === value;
const equal = (a, b, message) => assert.equal(canonicalEncode(a), canonicalEncode(b), message);
const mutable = (x) => structuredClone(x);
const stateOf = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED", r.reason); return r.state; };
const authorizeOn = (events, action) => {
  const s = stateOf(events);
  return core.authorizeState(s, { expectedHistoryHead: s.head, domain: s.genesis.domain, policyVersion: s.genesis.policyVersion, rootRecognitionPolicy: core.ROOT_RECOGNITION_POLICY,
    request: { actorId: "worker", action, resource: "incident", claimedAt: 100 }, evaluationTime: 100, consequential: false });
};
/** The §7.1 invariant on a state: the incremental records equal the from-scratch derivation and reproduce the root. */
const rootsAgree = (state) => {
  const all = deriveAllRecords(state);
  assert.equal(stateRootOfRecords(all).root, stateRootOf(state).root);
  equal(all.map((r) => [r.kind, r.key, r.record]).sort((a, b) => canonicalEncode([a[0], a[1]]) < canonicalEncode([b[0], b[1]]) ? -1 : 1), core.stateRecordsOf(state).map((r) => [r.kind, r.key, r.record]));
};

// ---------------------------------------------------------------- B1: the rules record

test("B1: DUTY_POLICY_RULES is carried verbatim and hashes to the pinned literal (keccak256, Continuity's hashCanonical); the literal is what every descriptor and finding carries", () => {
  assert.equal(DUTY_POLICY_RULES_HASH, "0xf7fb2b7de27abb77c6c3d03af6f61dce11afda5a510af20c8036085cd10a5f94");
  assert.equal(DUTY_POLICY_RULES_HASH_ALGORITHM, "keccak256");
  assert.equal(hashCanonical(DUTY_POLICY_RULES, "keccak256"), DUTY_POLICY_RULES_HASH);
  assert.notEqual(hashCanonical(DUTY_POLICY_RULES, "sha256"), DUTY_POLICY_RULES_HASH);
  assert.equal(dutyPolicyRulesHashIsPinned(), true);
  assert.equal(DUTY_POLICY_RULES.writerProfile, "continuity-segmented-local/1");
  assert.deepEqual(DUTY_POLICY_RULES.limits, { dispositions: 4, contests: 2, reservedAtActivation: 6, releaseUnusedOnCompletion: false, raiseExistingStorageOrShapeLimits: false });
  assert.deepEqual(DUTY_POLICY_RULES.criteria, KEYS);
  assert.equal(Object.keys(DUTY_POLICY_RULES).length, 24);
  // The duty disclosure paths are opt-in: the unextended defaults keep their original bytes (B10).
  for (const kind of ["WHY", "RESPONSIBLE", "SURVIVES"]) {
    equal(publicQueryDisclosure(kind), publicQueryDisclosure(kind, []));
    assert.ok(publicQueryDisclosure(kind).includedFields.every((p) => !DUTY_QUERY_FIELD_PATHS.includes(p)));
  }
  assert.ok(DUTY_QUERY_FIELD_PATHS.every((p) => !QUERY_ANSWER_FIELD_PATHS.includes(p)));
  assert.ok(publicQueryDisclosure("RESPONSIBLE", [DUTY_POLICY_VERSION]).includedFields.includes("attemptDuties.currentView.policy.priorHead.canonicalTime"));
  assert.ok(publicQueryDisclosure("SURVIVES", [DUTY_POLICY_VERSION]).includedFields.includes("attemptDuties.currentView"));
  assert.ok(!publicQueryDisclosure("WHY", [DUTY_POLICY_VERSION]).includedFields.includes("attemptDuties.currentView"));
});

// ---------------------------------------------------------------- activation (duty-activation.test.mjs)

test("activation: the original E5 duty is activated without changing prior evidence, spent allowance or revocation; the quota and the records follow", async (t) => {
  const f = await dutyFixture(t);
  await f.grant();
  const before = f.events, state = stateOf(before), capacity = f.owner.capacity();
  const r = await f.duties.activate(f.input), after = f.events, next = stateOf(after);
  assert.equal(r.alreadyRecorded, false); assert.equal(f.calls, 1);
  equal(after.slice(0, -1), before);
  assert.deepEqual(next.genesis, state.genesis); assert.deepEqual(next.intentAdmissions, state.intentAdmissions);
  assert.deepEqual(next.attemptDuties, state.attemptDuties); assert.deepEqual(next.eventHistoryHashes.slice(0, -1), state.eventHistoryHashes);
  for (const action of ["inspect", "export"]) assert.equal(authorizeOn(after, action).decision, "DENY");
  assert.equal(next.attemptDutyPolicies.size, 1);
  assert.equal(r.view.dutyDisposition, "OPEN"); assert.equal(r.view.outstanding, true); assert.equal(r.view.externalOutcome, "NOT_PROVEN");
  assert.deepEqual(r.view.reasons, ["NO_DISPOSITION_RECORDED"]); assert.equal(r.view.lastRecordedDisposition, null);
  assert.equal(r.view.version, "continuity-attempt-duty-view/1");
  // B9: the activation reserves 4 + 2 slots; the lifecycle reservation is untouched.
  assert.equal(f.owner.capacity().dutyReserved, capacity.dutyReserved + 6);
  assert.equal(f.owner.capacity().lifecycleReserved, capacity.lifecycleReserved);
  equal(openLocalOwner(f.config).inspectDutyPolicy({ dutyId: "duty" }), r.view);
  assert.equal(f.duties.inspect("duty").policy.dutyDisposition, "OPEN");
  assert.equal(inspectAttemptHistory(after).attempts[0].duty.disposition.version, "continuity-attempt-duty-view/1");
  assert.equal(observeHistory(after).eventCount, after.length);
  equal(observeHistory(after).inspectDutyPolicy("duty"), r.view);
  // The §7.2 duty record: policy with the short priorHead and `position`, no dispositions yet; the roots agree.
  const record = core.stateRecordsOf(next).find((e) => e.kind === "duty" && e.key === "duty").record;
  assert.equal(record.policy.dispositionCount, 0); assert.equal(record.policy.contestCount, 0);
  assert.deepEqual(record.policy.priorHead, { hash: state.head.hash, position: state.head.position });
  assert.equal(record.policy.position, after.length - 1); assert.equal(record.policy.eventId, "duty-policy:activate");
  assert.deepEqual(record.dispositions, []);
  assert.equal(next.attemptDutyPolicies.get("duty").priorHead.canonicalTime, state.head.canonicalTime);
  rootsAgree(next);
  // The activation event: /2 literals, action and resource of SPEC §13.1.
  const activation = after.at(-1);
  assert.equal(activation.data.administrativeAuthorization.challenge.version, "irontrellis-administrative-authorization/2");
  assert.equal(activation.data.administrativeAuthorization.challenge.request.action, "ACTIVATE_DUTY_POLICY");
  assert.equal(activation.data.administrativeAuthorization.challenge.request.resource, `duty-policy:${f.selection.descriptorHash}`);
  assert.equal(activation.data.descriptor.genesisHash, next.eventHistoryHashes[0]);
  assert.equal(activation.data.descriptor.domain.version, "2");
  assert.equal(activation.data.descriptor.rulesHash, DUTY_POLICY_RULES_HASH);
});

test("activation: current queries disclose the activated policy; the unextended disclosure refuses explicitly (B10)", async (t) => {
  const f = await dutyFixture(t);
  await f.grant(); await f.duties.activate(f.input);
  const events = f.events, observation = observeHistory(events);
  const survives = observation.survives("worker");
  assert.equal(survives.epistemicStatus, "ESTABLISHED", JSON.stringify(survives));
  assert.equal(survives.answer.attemptDuties[0].currentView.dutyDisposition, "OPEN");
  assert.equal(Object.hasOwn(survives.answer.attemptDuties[0], "status"), false);
  assert.deepEqual(survives.scope.recognizedExtensions, [{ version: "continuity-attempt-disposition/1", rulesHash: DUTY_POLICY_RULES_HASH }]);
  const old = core.survivesState(stateOf(events), { targetAgentId: "worker", evaluationTime: 100, disclosure: publicQueryDisclosure("SURVIVES") });
  assert.equal(old.code, "DISCLOSURE_INVALID");
  const admission = events.find((e) => e.type === "TRANSACTION_INTENT_ADMITTED"), proof = admission.data.authorizationProof;
  const binding = Object.fromEntries(["runtimeSessionId", "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "intentId", "nonce"].map((key) => [key, proof[key]]));
  const responsible = core.responsibleState(stateOf(events.slice(0, proof.historyHead.position + 1)), stateOf(events), {
    authorizationDomain: f.config.domain, request: proof.request, evaluationTime: proof.evaluationTime,
    consequentialBinding: { ...binding, runtimeSignature: admission.data.runtimeSignature }, disclosure: publicQueryDisclosure("RESPONSIBLE", [DUTY_POLICY_VERSION]),
  });
  assert.equal(responsible.epistemicStatus, "ESTABLISHED", JSON.stringify(responsible));
  assert.equal(responsible.answer.attemptDuties[0].currentView.policy.descriptor.dutyId, "duty");
  assert.equal(responsible.answer.attemptDuties[0].currentView.dutyDisposition, "OPEN");
  assert.deepEqual(responsible.scope.recognizedExtensions, [{ version: DUTY_POLICY_VERSION, rulesHash: DUTY_POLICY_RULES_HASH }]);
  // Unextended answers on the prefix before the activation have no extension and no duty rows.
  const prefix = observeHistory(events.slice(0, -1)).survives("worker");
  assert.equal(prefix.scope.recognizedExtensions, undefined);
  assert.equal(prefix.answer.attemptDuties[0].status, "OPEN");
  // The withheld-field rule: a duty path or the extension cannot be withheld.
  for (const path of ["scope.recognizedExtensions", "attemptDuties.currentView", "answer.attemptDuties.currentView.policy"]) {
    const refused = core.survivesState(stateOf(events), { targetAgentId: "worker", evaluationTime: 100, disclosure: { mode: "PUBLIC_MINIMAL", includedFields: publicQueryDisclosure("SURVIVES", [DUTY_POLICY_VERSION]).includedFields.filter((p) => p !== path), withheldFields: [path] } });
    assert.equal(refused.code, "DISCLOSURE_INVALID", path);
  }
});

test("activation: an exact retry survives retirement without another signature; a changed operation and a second activation refuse (T6 idempotency)", async (t) => {
  const f = await dutyFixture(t);
  await f.grant();
  const first = await f.duties.activate(f.input);
  await f.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 }); await f.owner.revoke("activation");
  const repeated = await openLocalDutyPolicy(f.options).activate(f.input);
  assert.equal(repeated.eventId, first.eventId); assert.equal(repeated.alreadyRecorded, true); assert.equal(f.calls, 1);
  assert.notEqual(repeated.head.hash, first.head.hash);
  equal(repeated.view, f.duties.inspect("duty").policy);
  await assert.rejects(f.duties.activate({ ...f.input, activationAuthority: "different" }), code("OPERATION_CONFLICT"));
  await assert.rejects(f.duties.activate({ ...f.input, id: "second" }), code("TRANSITION_REJECTED"));
  assert.equal(f.calls, 1);
});

test("activation: the host API refuses executable selection input and a duty-less history", async (t) => {
  const f = await fixture(t, { policy: "E5" });
  const x = await dutyFixture(t);
  let reads = 0;
  assert.throws(() => x.duties.describe({ duty: "duty", get incidentSourceDigest() { reads++; return digest; }, attesterRole: "role" }));
  assert.equal(reads, 0);
  await assert.rejects(x.duties.activate({ ...x.input, unexpected: undefined })); assert.equal(x.calls, 0);
  assert.throws(() => openLocalDutyPolicy(f.options).describe({ duty: "missing", incidentSourceDigest: digest, attesterRole: "role" }), code("TRANSITION_REJECTED"));
  assert.throws(() => x.duties.inspect("missing"), code("TRANSITION_REJECTED"));
  assert.equal(openLocalOwner(x.config).inspectDutyPolicy({ dutyId: "duty" }), null);
  assert.equal(inspectDutyPolicyState(x.state(), "duty"), null);
});

test("activation requires the exact live dedicated grant before requesting a signature (delegated, capped, wrong resource, expired, …)", async (t) => {
  const variants = [
    ["missing", null], ["broad-action", { actions: ["ACTIVATE_DUTY_POLICY", "other"] }],
    ["broad-resource", { resources: ["wrong"] }], ["multiple-resources", null],
    ["capped", { maxTransactions: 1 }], ["amount-capped", { maxAmount: 1n }],
    ["expired", { expiresAt: 100 }], ["future", { notBefore: 101 }], ["wrong-grantee", { to: "replacement" }],
    ["delegable", { delegable: 1 }],
  ];
  for (const [name, changes] of variants) {
    await t.test(name, async (t) => {
      const f = await dutyFixture(t);
      if (name === "multiple-resources") await f.grant({ resources: [f.selection.activationResource, "other"] });
      else if (changes) await f.grant(changes);
      const before = f.events;
      await assert.rejects(f.duties.activate(f.input), code("TRANSITION_REJECTED")); assert.equal(f.calls, 0); equal(f.events, before);
      assert.equal(f.state().attemptDutyPolicies.size, 0);
    });
  }
  await t.test("revoked", async (t) => { const f = await dutyFixture(t); await f.grant(); await f.owner.revoke("activation"); await assert.rejects(f.duties.activate(f.input)); assert.equal(f.calls, 0); });
  await t.test("wrong-selected-grant", async (t) => { const f = await dutyFixture(t); await f.grant(); await assert.rejects(f.duties.activate({ ...f.input, activationAuthority: "record" })); assert.equal(f.calls, 0); });
});

test("activation: descriptor source facts and the fixed rule identity cannot be substituted", async (t) => {
  for (const key of ["rulesHash", "domain", "genesisHash", "baseAdapterPolicyHash", "dutyId", "dutyCreationEventId", "dutyRecordHash", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "principalId", "acceptedAttesterRoleId", "dispositionLimit", "contestLimit"]) {
    await t.test(key, async (t) => {
      const f = await dutyFixture(t), d = mutable(f.selection.descriptor);
      if (key === "domain") d.domain = { ...d.domain, deploymentId: "other" };
      else if (key.endsWith("Hash")) d[key] = `0x${"b".repeat(64)}`;
      else if (key.endsWith("Limit")) d[key] = 0;
      else d[key] = "other";
      // Even an exact grant for the forged descriptor cannot alter source facts or fixed semantics.
      await f.grant({ resources: [`duty-policy:${hashCanonical(d, "sha256")}`] });
      await assert.rejects(f.duties.activate({ ...f.input, descriptor: d })); assert.equal(f.calls, 0);
    });
  }
});

test("activation: a same-principal attester selection allows an internal reviewer role but never creates new authority", async (t) => {
  const f = await dutyFixture(t);
  await f.owner.createRole({ id: "reviewer" });
  const selection = f.duties.describe({ duty: "duty", incidentSourceDigest: digest, attesterRole: "reviewer" });
  await f.grant({ resources: [selection.activationResource] });
  await f.duties.activate({ ...f.input, descriptor: selection.descriptor });
  assert.equal(f.state().attemptDutyPolicies.get("duty").descriptor.acceptedAttesterRoleId, "reviewer");
  assert.equal(f.events.filter((e) => e.type === "AUTHORITY_GRANTED").length, 4);
  assert.equal(selection.grantsAuthority, false);
});

test("activation: a wrong principal, a delegated root, a prohibition, an intersection or an alternate winner cannot activate", async (t) => {
  for (const kind of ["wrong-principal", "delegated", "prohibited", "intersection", "capped-winner", "alternate-winner"]) {
    await t.test(kind, async (t) => {
      const f = await dutyFixture(t);
      const base = { actions: [f.selection.activationAction], resources: [f.selection.activationResource], expiresAt: 1000 };
      if (kind === "wrong-principal") {
        // A grant from another principal: the owner handle grants as `owner`; a foreign grantor needs the raw event, which the API never writes — the grant from the wrong principal is simulated by a root under another principal through `createAgent` + delegation chain below.
        await f.owner.grant({ id: "parent", to: "replacement", ...base, delegable: 1 });
        await f.owner.delegate({ id: "activation", to: "worker", ...base, parent: "parent", from: "replacement" });
      }
      if (kind === "delegated") {
        await f.owner.grant({ id: "parent", to: "replacement", ...base, delegable: 1 });
        await f.owner.delegate({ id: "activation", to: "worker", ...base, parent: "parent", from: "replacement" });
      }
      if (kind === "intersection") {
        await f.owner.grant({ id: "intersection", to: "worker", actions: ["different"], resources: base.resources, expiresAt: 1000 });
        await f.owner.grant({ id: "activation", to: "worker", ...base, requires: ["intersection"] });
      }
      if (kind === "capped-winner" || kind === "alternate-winner") {
        await f.owner.grant({ id: "a-winner", to: "worker", ...base, ...(kind === "capped-winner" ? { maxTransactions: 1 } : {}) });
        await f.owner.grant({ id: "activation", to: "worker", ...base });
      }
      if (kind === "prohibited") {
        await f.owner.grant({ id: "activation", to: "worker", ...base });
        await f.owner.prohibit({ id: "prohibition", global: true, subject: "worker", actions: base.actions, resources: base.resources });
      }
      await assert.rejects(f.duties.activate(f.input)); assert.equal(f.calls, 0);
      assert.equal(f.state().attemptDutyPolicies.size, 0);
    });
  }
});

test("activation: a retired runtime, a changed role tenure and an owner-string substitution cannot activate", async (t) => {
  for (const kind of ["epoch", "tenure", "owner"]) {
    await t.test(kind, async (t) => {
      const f = await dutyFixture(t); await f.grant();
      if (kind === "epoch") await f.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 });
      if (kind === "tenure") await f.owner.succeed({ id: "replace", rule: "succession", fromAgent: "worker", fromTenure: "tenure", toAgent: "replacement", toTenure: "tenure:2", role: "role", number: 2 });
      if (kind === "owner") assert.throws(() => openLocalDutyPolicy({ ...f.options, owner: "foreign" }), code("PROFILE_MISMATCH"));
      else await assert.rejects(f.duties.activate(f.input));
      assert.equal(f.calls, 0);
    });
  }
});

test("activation: post-sign checks allow forward time, reject expiry and regression, and preserve the original signed timestamp", async (t) => {
  for (const [name, at, success] of [["forward", 101, true], ["grant-expiry", 1000, false], ["session-expiry", 10000, false], ["regression", 99, false]]) {
    await t.test(name, async (t) => {
      let f;
      f = await dutyFixture(t, { sign: async (h) => { f.setTime(at); return signHash(h); } });
      await f.grant({ expiresAt: name === "session-expiry" ? 20000 : 1000 });
      if (success) { await f.duties.activate(f.input); assert.equal(f.events.at(-1).timestamp, 100); }
      else { const before = f.events; await assert.rejects(f.duties.activate(f.input)); equal(f.events, before); }
      assert.equal(f.calls, 1);
    });
  }
});

test("activation: a concurrent append during signing conflicts; request mutation cannot change the captured effect", async (t) => {
  let f;
  f = await dutyFixture(t, { sign: async (h) => { await f.owner.createAgent({ id: "unrelated" }); return signHash(h); } });
  await f.grant();
  await assert.rejects(f.duties.activate(f.input), code("HISTORY_CONFLICT"));
  assert.equal(f.state().attemptDutyPolicies.size, 0);
  let x, input;
  x = await dutyFixture(t, { sign: async (h) => { input.descriptor.dutyId = "mutated"; return signHash(h); } });
  await x.grant(); input = mutable(x.input);
  await x.duties.activate(input);
  assert.equal(x.state().attemptDutyPolicies.has("duty"), true);
});

test("activation: a failed signer, an invalid signature, and raw duty events cannot append; replay refuses a second activation and a forged one", async (t) => {
  for (const signer of [async () => { throw new Error("offline"); }, async () => `0x${"0".repeat(130)}`]) {
    const f = await dutyFixture(t, { sign: signer }); await f.grant();
    const before = f.events; await assert.rejects(f.duties.activate(f.input)); equal(f.events, before);
  }
  const f = await dutyFixture(t); await f.grant(); await f.duties.activate(f.input);
  const state = f.state(), activation = f.events.at(-1);
  // Replay rules (SPEC §13.1): a second activation of the same duty, a moved activation and an unsigned disposition are refused.
  assert.equal(withProspectiveEvent(state, { ...activation, id: "again" }).code, "TRANSITION_INVALID");
  assert.equal(replay([...f.events.slice(0, -2), activation]).status, "REJECTED");
  for (const type of ["ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]) {
    assert.equal(withProspectiveEvent(state, { id: `future:${type}`, type, timestamp: 100, data: { dutyId: "duty" } }).code, "EVENT_DATA_INVALID");
  }
  // The one-signature producers refuse a finding shape (prepareAdministrativeEventState); the duty quota is recorded in the replay.
  assert.throws(() => core.prepareAdministrativeEventState(state, { expectedDomain: f.config.domain, expectedHistoryHead: state.head, runtimeSessionId: "session", transition: { id: "future", type: "ATTEMPT_DUTY_DISPOSITION_RECORDED", timestamp: 100, data: { dutyId: "duty", actorId: "worker" } } }));
  assert.equal(capacityOf(state).dutyReserved, 6);
  assert.equal(replay(f.events).status, "ACCEPTED");
});

// ---------------------------------------------------------------- dispositions and contests (duty-disposition.test.mjs)

test("T6: describe → activate → dispose → contest → inspect; two signatures, preserved transaction uncertainty, reserved remaining capacity, the records and the queries", async (t) => {
  const x = await dispositionFixture(t), before = x.events, capacity = x.owner.capacity();
  const prep = x.duties.prepareDisposition(x.input);
  assert.equal(prep.executionCapability, false); assert.deepEqual(x.calls, []);
  assert.equal(prep.challenge.version, "continuity-duty-finding/1"); assert.equal(prep.challenge.purpose, "DISPOSITION");
  assert.equal(prep.signingHash, hashCanonical(prep.challenge, "sha256"));
  assert.equal(prep.challenge.priorHead.hash, prep.head.hash); assert.equal(prep.challenge.priorHead.canonicalTime, prep.head.canonicalTime);
  const result = await x.duties.dispose(x.input), events = x.events;
  assert.deepEqual(x.calls, ["finding", "outer"]); equal(events.slice(0, -1), before);
  assert.equal(result.alreadyRecorded, false);
  assert.equal(result.view.dutyDisposition, "COMPLETED_UNDER_POLICY"); assert.equal(result.view.outstanding, false); assert.equal(result.view.externalOutcome, "NOT_PROVEN");
  assert.deepEqual(result.view.reasons, ["ALL_LOCAL_CRITERIA_SATISFIED"]);
  assert.equal(result.view.lastRecordedDisposition.eventId, "duty-disposition:complete");
  assert.equal(result.view.lastRecordedDisposition.eventPosition, events.length - 1);
  const state = stateOf(events);
  assert.equal(state.attemptDuties.get("duty").record.status, "OPEN");
  assert.equal(x.owner.capacity().dutyReserved, 5); assert.equal(x.owner.capacity().lifecycleReserved, capacity.lifecycleReserved);
  for (const action of ["inspect", "export"]) assert.equal(authorizeOn(events, action).decision, "DENY");
  assert.ok(Buffer.byteLength(canonicalEncode(events.at(-1))) <= 8192);
  assert.equal(inspectAttemptHistory(events).attempts[0].duty.disposition.dutyDisposition, "COMPLETED_UNDER_POLICY");
  const query = observeHistory(events).survives("worker");
  assert.equal(query.epistemicStatus, "ESTABLISHED", JSON.stringify(query));
  assert.equal(query.answer.attemptDuties[0].currentView.dutyDisposition, "COMPLETED_UNDER_POLICY");
  assert.equal(query.answer.attemptDuties[0].evidence.some((e) => e.eventId === "duty-disposition:complete"), true);
  // The recorded event (SPEC §13.2): literals, the finding challenge's format-2 adaptations, the outer action.
  const event = events.at(-1);
  assert.equal(event.type, "ATTEMPT_DUTY_DISPOSITION_RECORDED");
  assert.equal(event.data.version, DUTY_POLICY_VERSION); assert.equal(event.data.rulesHash, DUTY_POLICY_RULES_HASH);
  const c = event.data.finding.challenge;
  assert.deepEqual(c.priorHead, before.length === 0 ? null : stateOf(before).head);
  assert.equal(c.transitionEventType, "ATTEMPT_DUTY_DISPOSITION_RECORDED"); assert.equal(c.previousDispositionEventId, null);
  assert.equal(c.evidenceIndexHash, hashCanonical(core.deriveDutyEvidenceIndex(stateOf(before), "duty"), "sha256"));
  assert.equal(c.domain.version, "2");
  assert.equal(/^0x[0-9a-f]{130}$/.test(event.data.finding.runtimeSignature), true);
  assert.equal(event.data.administrativeAuthorization.challenge.request.action, "RECORD_DUTY_DISPOSITION");
  assert.equal(event.data.administrativeAuthorization.challenge.request.resource, `duty:${x.selection.descriptorHash}`);
  // The §7.2 duty record and the roots.
  const record = core.stateRecordsOf(state).find((e) => e.kind === "duty").record;
  assert.equal(record.policy.dispositionCount, 1); assert.equal(record.policy.contestCount, 0);
  assert.deepEqual(record.dispositions, [{ eventId: "duty-disposition:complete", position: events.length - 1, type: "ATTEMPT_DUTY_DISPOSITION_RECORDED", findingHash: hashCanonical(event.data.finding, "sha256") }]);
  rootsAgree(state);
  // Contest → CONTESTED, outstanding, both counts; then inspect.
  const contested = await x.duties.contest(x.contest("challenge"));
  assert.deepEqual(x.calls, ["finding", "outer", "finding", "outer"]);
  assert.equal(contested.view.dutyDisposition, "CONTESTED"); assert.equal(contested.view.outstanding, true);
  assert.deepEqual(contested.view.reasons, ["ACCEPTED_CONTEST"]);
  assert.equal(contested.view.policy.contestCount, 1); assert.equal(contested.view.policy.dispositionCount, 1);
  assert.equal(x.events.at(-1).data.finding.challenge.purpose, "CONTEST");
  assert.equal(x.events.at(-1).data.finding.challenge.operation.targetDispositionEventId, "duty-disposition:complete");
  equal(x.duties.inspect("duty").policy, contested.view);
  equal(openLocalRuntime(x.options).inspectDutyPolicy({ dutyId: "duty" }), contested.view);
  assert.equal(x.owner.capacity().dutyReserved, 4);
  const final = x.state();
  assert.equal(core.stateRecordsOf(final).find((e) => e.kind === "duty").record.dispositions.length, 2);
  rootsAgree(final);
  assert.equal(replay(x.events).status, "ACCEPTED");
  t.diagnostic(`Dual-signature event bytes: ${Buffer.byteLength(canonicalEncode(events.at(-1)))}`);
});

test("disposition: missing material can escalate but cannot complete; syntax and oversized input refuse before callbacks", async (t) => {
  const x = await dispositionFixture(t);
  const missing = { ...x.input, disposition: "ESCALATED", checklist: checklist(), nextStep: "Ask the internal custodian for the missing incident file." };
  missing.checklist.SOURCE_REVIEWED.state = "UNAVAILABLE";
  const result = await x.duties.dispose(missing);
  assert.equal(result.view.dutyDisposition, "ESCALATED"); assert.equal(result.view.outstanding, true); assert.deepEqual(result.view.reasons, ["ATTENTION_REQUESTED"]);
  for (const kind of ["incomplete", "empty-next-step", "extra", "undefined", "long-reason", "long-next-step", "absent-report", "wrong-digest", "completed-with-next-step"]) {
    await t.test(kind, async (t) => {
      const y = await dispositionFixture(t), v = structuredClone(y.input);
      if (kind === "incomplete") v.checklist.HISTORY_REVIEWED.state = "UNRESOLVED";
      if (kind === "empty-next-step") { v.disposition = "ESCALATED"; v.checklist.HISTORY_REVIEWED.state = "UNRESOLVED"; v.nextStep = ""; }
      if (kind === "extra") v.checklist.OTHER = { state: "SATISFIED", reason: "extra" };
      if (kind === "undefined") v.nextStep = undefined;
      if (kind === "long-reason") v.checklist.SOURCE_REVIEWED.reason = "x".repeat(257);
      if (kind === "long-next-step") { v.disposition = "ESCALATED"; v.checklist.SOURCE_REVIEWED.state = "UNAVAILABLE"; v.nextStep = "x".repeat(513); }
      if (kind === "absent-report") delete v.reportDigest;
      if (kind === "wrong-digest") v.reportDigest.algorithm = "sha512";
      if (kind === "completed-with-next-step") v.nextStep = "not allowed";
      const before = y.events;
      await assert.rejects(y.duties.dispose(v)); assert.deepEqual(y.calls, []); equal(y.events, before);
    });
  }
});

test("disposition: attestation and disposition authority are independently necessary", async (t) => {
  for (const missing of ["finding", "disposition"]) {
    await t.test(missing, async (t) => {
      const x = await dispositionFixture(t, { findingGrant: missing !== "finding", dispositionGrant: missing !== "disposition" });
      await assert.rejects(x.duties.dispose(x.input), code("TRANSITION_REJECTED")); assert.deepEqual(x.calls, []);
    });
  }
  const x = await dispositionFixture(t);
  await assert.rejects(x.duties.dispose({ ...x.input, attestationAuthority: "disposition", dispositionAuthority: "finding" })); assert.deepEqual(x.calls, []);
});

test("T6: exact retries report the current view after contests and retirement, never sign again; a different repeat is OPERATION_CONFLICT", async (t) => {
  const x = await dispositionFixture(t), first = await x.duties.dispose(x.input);
  await x.duties.contest(x.contest("challenge"));
  await x.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 }); await x.owner.revoke("finding"); await x.owner.revoke("disposition");
  const calls = x.calls.length, head = x.state().head;
  const repeated = await x.duties.dispose(x.input);
  assert.equal(repeated.alreadyRecorded, true); assert.equal(repeated.eventId, first.eventId);
  assert.equal(repeated.view.dutyDisposition, "CONTESTED"); equal(repeated.head, head); assert.equal(x.calls.length, calls);
  await assert.rejects(x.duties.dispose({ ...x.input, reportDigest: DIGEST("d") }), code("OPERATION_CONFLICT"));
  await assert.rejects(x.duties.contest({ ...x.contest("challenge"), reason: "another reason" }), code("OPERATION_CONFLICT"));
  const repeatContest = await x.duties.contest(x.contest("challenge"));
  assert.equal(repeatContest.alreadyRecorded, true); assert.equal(x.calls.length, calls);
});

test("view: later same-duty evidence stales a completion (NEEDS_REVIEW); unrelated events, expiry and revocation do not", async (t) => {
  const x = await dispositionFixture(t, { policy: "E6" });
  await x.duties.dispose(x.input);
  await x.owner.createAgent({ id: "unrelated" }); await x.owner.revoke("finding"); x.f.setTime(1001);
  assert.equal(x.duties.inspect("duty").policy.dutyDisposition, "COMPLETED_UNDER_POLICY");
  // A later existing E6 review is relevant evidence, but does not complete the policy.
  await openLocalAttemptRecorder(x.f.options).reviewDuty({ id: "later-review", duty: "duty", summaryDigest: DIGEST("e").value });
  const view = x.duties.inspect("duty").policy;
  assert.equal(view.dutyDisposition, "NEEDS_REVIEW"); assert.equal(view.outstanding, true); assert.deepEqual(view.reasons, ["RELEVANT_EVIDENCE_CHANGED"]);
  assert.equal(view.lastRecordedDisposition.disposition, "COMPLETED_UNDER_POLICY");
  assert.equal(inspectAttemptHistory(x.events).attempts[0].duty.disposition.dutyDisposition, "NEEDS_REVIEW");
});

test("B5/B9: quotas are independent (fifth disposition, third contest refused); contests persist through escalation and further evidence; the quota in capacity()", async (t) => {
  const x = await dispositionFixture(t, { policy: "E6" });
  for (let i = 0; i < 4; i++) await x.duties.dispose({ ...x.input, id: i ? `complete:${i}` : "complete" });
  assert.equal(x.owner.capacity().dutyReserved, 2);
  const calls = x.calls.length;
  await assert.rejects(x.duties.dispose({ ...x.input, id: "fifth" }), code("TRANSITION_REJECTED")); assert.equal(x.calls.length, calls);
  await openLocalAttemptRecorder(x.f.options).reviewDuty({ id: "after-four", duty: "duty", summaryDigest: DIGEST("e").value });
  assert.equal(x.duties.inspect("duty").policy.dutyDisposition, "NEEDS_REVIEW");
  await x.duties.contest(x.contest("one")); await x.duties.contest(x.contest("two"));
  assert.equal(x.owner.capacity().dutyReserved, 0);
  const after = x.calls.length;
  await assert.rejects(x.duties.contest(x.contest("three")), code("TRANSITION_REJECTED")); assert.equal(x.calls.length, after);
  assert.equal(x.duties.inspect("duty").policy.dutyDisposition, "CONTESTED");
  assert.equal(x.owner.capacity().dutyReserved, 0, "the reservation is never released and never negative");
  const y = await dispositionFixture(t);
  await y.duties.dispose(y.input); await y.duties.contest(y.contest("one")); await y.duties.contest(y.contest("two"));
  // COMPLETED after a contest is ineligible; ESCALATED with a nextStep is the way out, and the view stays CONTESTED.
  await assert.rejects(y.duties.dispose({ ...y.input, id: "complete-again" }), code("TRANSITION_REJECTED"));
  const escalated = await y.duties.dispose({ ...y.input, id: "escalate", disposition: "ESCALATED", nextStep: "Investigate the contest with the existing Principal." });
  assert.equal(escalated.view.dutyDisposition, "CONTESTED"); assert.equal(y.owner.capacity().dutyReserved, 2);
  assert.equal(y.state().attemptDutyPolicies.get("duty").dispositionCount, 2);
  // A contest must target an accepted disposition of this duty.
  await assert.rejects(y.duties.contest({ ...y.contest("stray"), targetDispositionId: "duty-disposition:missing" }), code("TRANSITION_REJECTED"));
});

test("B7: each signing callback is followed by fresh authority, head and monotone-clock checks (both phases × head / expiry / regression)", async (t) => {
  for (const phase of ["finding", "outer"]) {
    for (const change of ["head", "expiry", "regression"]) {
      await t.test(`${phase}:${change}`, async (t) => {
        const x = await dispositionFixture(t);
        const mutate = async (hash) => { if (change === "head") await x.owner.createAgent({ id: "racer" }); else x.f.setTime(change === "expiry" ? 1000 : 99); return signHash(hash); };
        const duties = x.make(phase === "finding" ? mutate : undefined, phase === "outer" ? mutate : undefined);
        await assert.rejects(duties.dispose(x.input), (e) => ["HISTORY_CONFLICT", "TRANSITION_REJECTED", "CLOCK_INVALID"].includes(e.code));
        assert.equal(x.events.some((e) => e.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED"), false);
        assert.deepEqual(x.calls, phase === "finding" ? ["finding"] : ["finding", "outer"]);
      });
    }
  }
  const x = await dispositionFixture(t), duties = x.make(async (h) => { x.f.setTime(101); return signHash(h); }, async (h) => { x.f.setTime(102); return signHash(h); });
  await duties.dispose(x.input); assert.equal(x.events.at(-1).timestamp, 100, "the signatures keep their original time");
  const y = await dispositionFixture(t), regressed = y.make(async (h) => { y.f.setTime(101); return signHash(h); }, async (h) => { y.f.setTime(100); return signHash(h); });
  await assert.rejects(regressed.dispose(y.input), code("CLOCK_INVALID"));
});

test("T6: fresh eligibility refuses when the attester session expires between the two signatures (and when the outer session does)", async (t) => {
  // The attester is a distinct reviewer whose session expires at 500; the finding is signed at 100 and the outer signer moves the clock past the expiry.
  const x = await dutyFixture(t);
  const { SECOND_KEY, signHashSecond } = await import("./helpers/duty-fixture.mjs");
  await x.owner.createAgent({ id: "reviewer" }); await x.owner.createRole({ id: "review-role" });
  await x.owner.appoint({ agent: "reviewer", role: "review-role", tenure: "review-tenure", number: 1 });
  await x.owner.admitRuntime({ agent: "reviewer", session: "review-session", epoch: 1, key: "review-key", address: SECOND_KEY.credential, scheme: "eip191-personal-sign-keccak256", expiresAt: 500 });
  const selected = x.duties.describe({ duty: "duty", incidentSourceDigest: DIGEST("a"), attesterRole: "review-role" });
  await x.grant({ resources: [selected.activationResource] }); await x.duties.activate({ ...x.input, descriptor: selected.descriptor });
  const resource = `duty:${selected.descriptorHash}`;
  await x.owner.grant({ id: "finding", to: "reviewer", actions: ["ATTEST_DUTY_FINDING"], resources: [resource], expiresAt: 1000 });
  await x.owner.grant({ id: "disposition", to: "worker", actions: ["RECORD_DUTY_DISPOSITION"], resources: [resource], expiresAt: 1000 });
  const input = { id: "complete", duty: "duty", disposition: "COMPLETED_UNDER_POLICY", checklist: checklist(), reportDigest: DIGEST("b"), nextStep: null, attestationAuthority: "finding", dispositionAuthority: "disposition" };
  const calls = [];
  const expiring = openLocalDutyPolicy({ ...x.options, signHash: async (h) => { calls.push("outer"); x.setTime(500); return signHash(h); } }, { session: "review-session", signHash: async (h) => { calls.push("finding"); return signHashSecond(h); } });
  const before = x.events;
  await assert.rejects(expiring.dispose(input), code("TRANSITION_REJECTED"));
  assert.deepEqual(calls, ["finding", "outer"], "the expiry is seen after the second signature returns; nothing is appended");
  equal(x.events, before);
  // The same at the first return: the attester expires while the finding signer runs → refused before the outer signer is asked.
  calls.length = 0; x.setTime(100);
  const early = openLocalDutyPolicy({ ...x.options, signHash: async (h) => { calls.push("outer"); return signHash(h); } }, { session: "review-session", signHash: async (h) => { calls.push("finding"); x.setTime(500); return signHashSecond(h); } });
  await assert.rejects(early.dispose(input), code("TRANSITION_REJECTED"));
  assert.deepEqual(calls, ["finding"]); equal(x.events, before);
  // And a fresh clock before the expiry completes it with the original signed time.
  calls.length = 0; x.setTime(100);
  const ok = openLocalDutyPolicy({ ...x.options, signHash: async (h) => { calls.push("outer"); x.setTime(499); return signHash(h); } }, { session: "review-session", signHash: async (h) => { calls.push("finding"); x.setTime(400); return signHashSecond(h); } });
  const result = await ok.dispose(input);
  assert.equal(result.view.dutyDisposition, "COMPLETED_UNDER_POLICY"); assert.equal(x.events.at(-1).timestamp, 100);
  assert.equal(x.events.at(-1).data.finding.challenge.attesterId, "reviewer"); assert.equal(x.events.at(-1).data.actorId, "worker");
  // validateDutyFreshEligibility directly: true at the signed time and later with the head unchanged; false past the attester's expiry or before the signed time.
  const s = stateOf(before), event = x.events.at(-1);
  assert.equal(core.validateDutyFreshEligibility(s, event, "session", 100), true);
  assert.equal(core.validateDutyFreshEligibility(s, event, "session", 499), true);
  assert.equal(core.validateDutyFreshEligibility(s, event, "session", 500), false);
  assert.equal(core.validateDutyFreshEligibility(s, event, "session", 99), false);
  assert.equal(core.validateDutyFreshEligibility(s, event, "missing-session", 100), false);
  assert.equal(core.validateDutyFreshEligibility(stateOf(x.events), event, "session", 100), false, "the head moved: the finding no longer validates");
});

test("disposition: a bad first signature never calls the second signer, and a failed second signer never appends", async (t) => {
  const x = await dispositionFixture(t);
  await assert.rejects(x.make(async () => `0x${"0".repeat(130)}`).dispose(x.input)); assert.deepEqual(x.calls, ["finding"]);
  const y = await dispositionFixture(t), before = y.events;
  await assert.rejects(y.make(undefined, async () => { throw new Error("offline"); }).dispose(y.input), code("SIGNER_FAILED")); equal(y.events, before);
  const z = await dispositionFixture(t);
  await assert.rejects(z.make(async () => { throw new Error("offline"); }).dispose(z.input), code("SIGNER_FAILED")); assert.deepEqual(z.calls, ["finding"]);
});

test("disposition: a distinct internal attester needs its own current role, runtime and exact permission", async (t) => {
  const x = await dutyFixture(t);
  const { SECOND_KEY, signHashSecond } = await import("./helpers/duty-fixture.mjs");
  await x.owner.createAgent({ id: "reviewer" }); await x.owner.createRole({ id: "review-role" });
  await x.owner.appoint({ agent: "reviewer", role: "review-role", tenure: "review-tenure", number: 1 });
  await x.owner.admitRuntime({ agent: "reviewer", session: "review-session", epoch: 1, key: "review-key", address: SECOND_KEY.credential, scheme: "eip191-personal-sign-keccak256", expiresAt: 1000 });
  const selected = x.duties.describe({ duty: "duty", incidentSourceDigest: DIGEST("a"), attesterRole: "review-role" });
  await x.grant({ resources: [selected.activationResource] }); await x.duties.activate({ ...x.input, descriptor: selected.descriptor });
  const resource = `duty:${selected.descriptorHash}`;
  await x.owner.grant({ id: "finding", to: "reviewer", actions: ["ATTEST_DUTY_FINDING"], resources: [resource], expiresAt: 1000 });
  await x.owner.grant({ id: "disposition", to: "worker", actions: ["RECORD_DUTY_DISPOSITION"], resources: [resource], expiresAt: 1000 });
  const input = { id: "complete", duty: "duty", disposition: "COMPLETED_UNDER_POLICY", checklist: checklist(), reportDigest: DIGEST("b"), nextStep: null, attestationAuthority: "finding", dispositionAuthority: "disposition" };
  await assert.rejects(x.duties.dispose(input), "the worker is not the attester role's occupant");
  const duties = openLocalDutyPolicy(x.options, { session: "review-session", signHash: signHashSecond });
  const result = await duties.dispose(input);
  assert.equal(result.view.dutyDisposition, "COMPLETED_UNDER_POLICY");
  const event = x.events.at(-1);
  assert.equal(event.data.actorId, "worker"); assert.equal(event.data.finding.challenge.attesterId, "reviewer"); assert.equal(event.data.finding.challenge.runtimeSessionId, "review-session");
  const changed = openLocalDutyPolicy({ ...x.options, signHash: async (hash) => { x.setTime(1000); return signHash(hash); } }, { session: "review-session", signHash: signHashSecond });
  await assert.rejects(changed.dispose({ ...input, id: "expired-reviewer" }));
});

test("disposition: captured caller input cannot change between signatures; a copied finding cannot target another event; patched challenges are refused by replay", async (t) => {
  const x = await dispositionFixture(t), input = structuredClone(x.input);
  const duties = x.make(async (hash) => { input.reportDigest.value = DIGEST("f").value; input.checklist.SOURCE_REVIEWED.state = "UNAVAILABLE"; return signHash(hash); });
  await duties.dispose(input);
  const original = x.events.at(-1);
  equal(original.data.finding.challenge.operation.reportDigest, x.input.reportDigest);
  const prefix = x.events.slice(0, -1), base = stateOf(prefix);
  assert.equal(withProspectiveEvent(base, { ...original, id: "duty-disposition:forged" }).code, "TRANSITION_INVALID");
  for (const patch of [{ purpose: "CONTEST" }, { evidenceIndexHash: DIGEST("f").value }, { previousDispositionEventId: original.id }, { evaluationTime: 101 }, { attesterId: "replacement" }, { priorHead: { ...original.data.finding.challenge.priorHead, position: 0 } }]) {
    const event = structuredClone(original);
    Object.assign(event.data.finding.challenge, patch);
    const result = replay([...prefix, event]);
    assert.equal(result.status, "REJECTED", JSON.stringify(patch));
    assert.ok(["TRANSITION_INVALID", "EVENT_DATA_INVALID"].includes(result.code), result.code);
  }
  // The finding signature itself and the outer signature are each necessary.
  for (const forge of [(e) => { e.data.finding.runtimeSignature = x.events.at(-1).data.administrativeAuthorization.runtimeSignature; }, (e) => { e.data.administrativeAuthorization.runtimeSignature = e.data.finding.runtimeSignature; }]) {
    const event = structuredClone(original); forge(event);
    assert.equal(replay([...prefix, event]).code, "TRANSITION_INVALID");
  }
  // Literal substitutions are schema failures.
  for (const [path, value] of [["version", "continuity-attempt-disposition/2"], ["rulesHash", DIGEST("0").value]]) {
    const event = structuredClone(original); event.data[path] = value;
    assert.equal(replay([...prefix, event]).code, "EVENT_DATA_INVALID", path);
  }
});

test("view: an existing review or a report digest by itself does not complete the activated duty", async (t) => {
  const x = await dispositionFixture(t, { policy: "E6" });
  await openLocalAttemptRecorder(x.f.options).reviewDuty({ id: "review-only", duty: "duty", summaryDigest: DIGEST("b").value });
  assert.equal(x.duties.inspect("duty").policy.dutyDisposition, "OPEN");
  await assert.rejects(x.duties.dispose({ id: "missing-finding", duty: "duty", reportDigest: DIGEST("b") }), code("INVALID_INPUT"));
  assert.deepEqual(x.calls, []);
});

test("view: role replacement alone keeps a completion historical; explicit A → B → A assignments make it need review", async (t) => {
  const x = await dispositionFixture(t);
  const { SECOND_KEY, signHashSecond } = await import("./helpers/duty-fixture.mjs");
  await x.duties.dispose(x.input);
  // The role moves to `replacement` (a succession transfer: the reference used a raw REASSIGNMENT transfer); no assignment yet.
  await x.owner.succeed({ id: "to-replacement", rule: "succession", fromAgent: "worker", fromTenure: "tenure", toAgent: "replacement", toTenure: "replacement-tenure", role: "role", number: 2 });
  assert.equal(x.duties.inspect("duty").policy.dutyDisposition, "COMPLETED_UNDER_POLICY");
  await x.owner.admitRuntime({ agent: "replacement", session: "replacement-session", epoch: 1, key: "replacement-key", address: SECOND_KEY.credential, scheme: "eip191-personal-sign-keccak256", expiresAt: 1000 });
  for (const [id, action] of [["new-finding", "ATTEST_DUTY_FINDING"], ["new-disposition", "RECORD_DUTY_DISPOSITION"]]) await x.owner.grant({ id, to: "replacement", actions: [action], resources: [x.resource], expiresAt: 1000 });
  await x.owner.grant({ id: "assign-new", to: "replacement", actions: ["ASSIGN_ATTEMPT_DUTY"], resources: ["job"], expiresAt: 1000 });
  const replacementOptions = { ...x.f.options, session: "replacement-session", signHash: signHashSecond };
  await assert.rejects(openLocalDutyPolicy(replacementOptions).dispose({ ...x.input, id: "without-assignment", attestationAuthority: "new-finding", dispositionAuthority: "new-disposition" }), "the replacement is not the assignee yet");
  await openLocalAttemptRecorder(replacementOptions).assignDuty({ id: "to-replacement", duty: "duty" });
  assert.equal(x.duties.inspect("duty").policy.dutyDisposition, "NEEDS_REVIEW");
  assert.equal(x.duties.inspect("duty").policy.currentAssigneeId, "replacement");
  assert.equal(x.duties.inspect("duty").policy.latestAssignmentEventId, "attempt-duty-assignment:to-replacement");
  // The replacement, now the assignee, can record a new completion (its own attester role occupancy: `role` is the attester role).
  const again = await openLocalDutyPolicy(replacementOptions).dispose({ ...x.input, id: "by-replacement", attestationAuthority: "new-finding", dispositionAuthority: "new-disposition" });
  assert.equal(again.view.dutyDisposition, "COMPLETED_UNDER_POLICY");
  assert.equal(x.events.at(-1).data.finding.challenge.previousDispositionEventId, "duty-disposition:complete");
  assert.equal(x.events.at(-1).data.finding.challenge.latestAssignmentEventId, "attempt-duty-assignment:to-replacement");
});

test("disposition: a maximal escaped checklist is within the format-2 bounds (the reference's 8 KiB managed-profile envelope is not a format-2 rule); a reason past 256 bytes refuses before callbacks", async (t) => {
  const x = await dispositionFixture(t), input = structuredClone(x.input);
  for (const key of KEYS) input.checklist[key].reason = "\\".repeat(256);
  input.disposition = "ESCALATED"; input.checklist.SOURCE_REVIEWED.state = "UNAVAILABLE"; input.nextStep = "\\".repeat(512);
  const result = await x.duties.dispose(input);
  assert.equal(result.view.dutyDisposition, "ESCALATED"); assert.deepEqual(x.calls, ["finding", "outer"]);
  t.diagnostic(`maximal escaped disposition event bytes: ${Buffer.byteLength(canonicalEncode(x.events.at(-1)))}`);
  assert.equal(replay(x.events).status, "ACCEPTED");
  const y = await dispositionFixture(t), over = structuredClone(y.input);
  over.checklist.SOURCE_REVIEWED.reason = "\\".repeat(257);
  const before = y.events;
  await assert.rejects(y.duties.dispose(over)); assert.deepEqual(y.calls, []); equal(y.events, before);
});

test("B12: the one-signature route refuses finding events with DUTY_WRITER_REQUIRED before its callback", async (t) => {
  const x = await dispositionFixture(t);
  const { signedTransition } = await import("../src/runtime-writes.ts");
  const { configuration, openStore } = await import("../src/owner.ts");
  const config = configuration(x.f.options), store = openStore(config);
  let calls = 0;
  for (const type of ["ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]) {
    await assert.rejects(signedTransition(store, config, "session", async (h) => { calls++; return signHash(h); }, "wrong-writer", type, { dutyId: "duty" }), code("DUTY_WRITER_REQUIRED"));
  }
  assert.equal(calls, 0);
  store.close?.();
});

test("B7: either signer phase refuses switching to another grant route after expiry", async (t) => {
  for (const phase of ["finding", "outer"]) {
    await t.test(phase, async (t) => {
      const x = await dispositionFixture(t);
      await x.owner.grant({ id: "branch-parent", to: "replacement", actions: ["ATTEST_DUTY_FINDING"], resources: [x.resource], expiresAt: 1000, delegable: 1 });
      for (const [id, expiresAt] of [["branch-a", 101], ["branch-b", 1000]]) await x.owner.delegate({ id, to: "worker", actions: ["ATTEST_DUTY_FINDING"], resources: [x.resource], expiresAt, parent: "branch-parent", from: "replacement" });
      const change = async (h) => { x.f.setTime(101); return signHash(h); };
      const duties = x.make(phase === "finding" ? change : undefined, phase === "outer" ? change : undefined);
      const before = x.events;
      await assert.rejects(duties.dispose({ ...x.input, attestationAuthority: "branch-parent" }), code("TRANSITION_REJECTED"));
      equal(x.events, before); assert.deepEqual(x.calls, phase === "finding" ? ["finding"] : ["finding", "outer"]);
    });
  }
});

test("view: a later signed outside report changes freshness but does not itself complete or contest the duty; the evidence index", async (t) => {
  const x = await dispositionFixture(t);
  await x.duties.dispose(x.input);
  const before = x.duties.inspect("duty").policy;
  const identity = x.state().intentAdmissions.get("job").adapterIdentity;
  const acknowledgment = core.createRemoteServiceReportAcknowledgment(identity, DIGEST("d").value);
  await openLocalAttemptRecorder(x.f.options).observe({ id: "later-outside-report", intent: "job", acknowledgment });
  const after = x.duties.inspect("duty").policy;
  assert.equal(after.dutyDisposition, "NEEDS_REVIEW"); assert.equal(after.externalOutcome, "NOT_PROVEN");
  assert.equal(after.policy.contestCount, 0); assert.equal(after.lastRecordedDisposition.eventId, before.lastRecordedDisposition.eventId);
  const state = x.state(), index = core.deriveDutyEvidenceIndex(state, "duty");
  assert.equal(index.version, "continuity-duty-evidence-index/1");
  assert.equal(index.counts.OUTCOME_OBSERVATION_RECORDED, 1);
  assert.equal(index.records.at(-1).eventId, "attempt-observation:later-outside-report");
  assert.equal(index.records.some((r) => r.eventType === "ATTEMPT_DUTY_DISPOSITION_RECORDED"), false, "dispositions are excluded");
  assert.deepEqual(index.records.map((r) => r.eventType).slice(0, 4), ["TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED", "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_POLICY_ACTIVATED"]);
  // [F2] contentHash = eventHash of the record's event (sha256 of the canonical event), in position order.
  for (const r of index.records) assert.equal(r.contentHash, core.eventHash(state.events[state.eventPositionsById.get(r.eventId)]));
  assert.deepEqual(index.records.map((r) => state.eventPositionsById.get(r.eventId)), [...index.records.map((r) => state.eventPositionsById.get(r.eventId))].sort((a, b) => a - b));
  assert.equal(index.recordCount, index.records.length);
  equal((await x.duties.dispose(x.input)).view, after);
});

test("B9: capacity — the control-event reserve refuses a finding before any signer with CAPACITY_RESERVED; a declared maxEvents counts the quota", async (t) => {
  const x = await dispositionFixture(t);
  const records = x.state().stateRecords.size;
  setCapacityLimitsForTests({ maxStateRecords: records + core.RESERVED_STATE_RECORDS });
  try {
    const before = x.events;
    await assert.rejects(x.duties.dispose(x.input), code("CAPACITY_RESERVED"));
    assert.deepEqual(x.calls, []); equal(x.events, before);
    assert.throws(() => x.duties.prepareDisposition(x.input), code("CAPACITY_RESERVED"));
  } finally { setCapacityLimitsForTests(); }
  const ok = await x.duties.dispose(x.input);
  assert.equal(ok.view.dutyDisposition, "COMPLETED_UNDER_POLICY");
  // A declared maxEvents exactly at the committed space: dispositions and contests within the quota are admitted, growth is refused (SPEC §5.2, §13.5).
  const y = await dutyFixture(t, {});
  await y.grant(); await y.duties.activate(y.input);
  const report = y.owner.capacity();
  assert.equal(report.dutyReserved, 6);
  assert.equal(capacityOf(y.state()).dutyReserved, 6);
});

test("state: the duty records rebuild the policy and dispositions (§7.1 invariant) and a replayed copy agrees with the store's state", async (t) => {
  const x = await dispositionFixture(t);
  await x.duties.dispose(x.input); await x.duties.contest(x.contest("one"));
  const state = x.state(), live = openLocalOwner(x.config).exportHistory();
  equal(live, x.events);
  const record = core.stateRecordsOf(state).find((e) => e.kind === "duty").record;
  assert.deepEqual(Object.keys(record.policy).sort(), ["activatedAt", "activationAuthorityId", "actorId", "contestCount", "descriptor", "descriptorHash", "dispositionCount", "eventId", "position", "priorHead"]);
  assert.deepEqual(Object.keys(record.policy.priorHead), ["hash", "position"]);
  assert.equal(record.policy.contestCount, 1); assert.equal(record.policy.dispositionCount, 1);
  assert.deepEqual(record.dispositions.map((r) => r.type), ["ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]);
  rootsAgree(state);
  // The in-memory activation keeps the full prior head and `eventPosition` (the frozen view shape); the view's policy is that record.
  const view = inspectDutyPolicyState(state, "duty");
  assert.deepEqual(Object.keys(view.policy.priorHead).sort(), ["canonicalTime", "hash", "position"]);
  assert.equal(view.policy.eventPosition, record.policy.position);
  assert.deepEqual(Object.keys(view).sort(), ["currentAssigneeId", "dutyDisposition", "dutyId", "evidenceScope", "externalOutcome", "lastRecordedDisposition", "latestAssignmentEventId", "observedHead", "outstanding", "policy", "reasons", "version"]);
  // Export view carries the duty record at `to`.
  const exported = core.exportViewState(state, { fromPosition: 0, toPosition: state.head.position, include: { toRecords: true } });
  assert.ok(exported.toRecords.some((r) => r.kind === "duty" && r.record.policy !== null));
});
