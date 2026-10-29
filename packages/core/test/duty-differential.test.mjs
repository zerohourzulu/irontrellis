// T5 (BUILD §4; SPEC §13.7; LEFT-OUT-SWEEP B15): the duty-policy differential. Every scenario of reference-0.3's
// `tests/core-0.3/duty-activation.test.mjs`, `duty-disposition.test.mjs`, `duty-workflow.test.mjs`, `duty-capacity.test.mjs`
// and `duty-disposition-capacity.test.mjs` (52 top-level cases; the two `duty-store` cases are E3's store parity) is run
// on the frozen reference-0.3 engine over a legacy history (`node --experimental-strip-types`, in process), the legacy
// history is transcribed into a format-2 twin by the IronTrellis producers (`helpers/duty-twin.mjs`), and every answer the
// reference gave at a checkpoint (the duty view, SURVIVES, RESPONSIBLE and WHY with the admission binding,
// `inspectAttemptHistory`, the duty quota) is recomputed by the IronTrellis engine on the twin's prefix and compared under
// the BUILD §4 comparison projection; every refusal the reference host API gave is re-attempted through
// `openLocalDutyPolicy` on a format-2 store holding the twin's prefix, which must refuse too without signing or appending.
// A divergence that comes from a SPEC rule is a stop-rule finding (STOP-E4.md); none was found (see E4-NOTES §3).
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const R = new URL("../../reference-0.3/", import.meta.url);
const refPath = (rel) => new URL(rel, R).href;
const ref = await import(refPath("packages/core-0.2/src/core/index.ts"));
const { inspectPortableDutyPolicy } = await import(refPath("packages/core-0.2/src/core/duty-policy.ts"));
const { derivePortableDutyEvidenceIndex } = await import(refPath("packages/core-0.2/src/core/duty-disposition.ts"));
const { stateOf: refStateOf } = await import(refPath("packages/core-0.3/src/local-store.ts"));
const { inspectAttemptHistory: refInspectAttempts, openLocalAttemptRecorder: refRecorder } = await import(refPath("packages/core-0.3/src/attempts.ts"));
const { capacityOf: refCapacityOf, dutyReservationOf } = await import(refPath("packages/core-0.3/src/capacity.ts"));
const { openLocalDutyPolicy: refOpenDuties } = await import(refPath("packages/core-0.3/src/duties.ts"));
const { commitHistoryAdministration: refCommit } = await import(refPath("packages/core-0.3/src/history-store/index.ts"));
const { dutyFixture: refDutyFixture } = await import(refPath("tests/core-0.3/fixtures/duty-fixture.mjs"));
const { signHash: refSign, account } = await import(refPath("tests/core-0.3/fixtures/history-fixture.mjs"));
const { investigateDuty: refInvestigate, readDocumentDigest } = await import(refPath("examples/protected-evidence/investigation.mjs"));

const core = await import("../src/index.ts");
const { canonicalEncode, replay, withProspectiveEvent, createHistoryStore, openLocalDutyPolicy, inspectDutyPolicyState, inspectAttemptHistory, capacityOf, newCapacityLedger, accountCapacity } = core;
const { transcribeLegacyToFormat2, positionTokens, projected, twinOwner } = await import("./helpers/duty-twin.mjs");
const { signHash: mySign, checklist, DIGEST, KEYS } = await import("./helpers/duty-fixture.mjs");

const plain = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x)));
const mutable = (x) => structuredClone(plain(x));
const digest = (n) => ({ algorithm: "sha256", value: `0x${n.repeat(64)}` });
let compared = 0, refusalsCompared = 0;

// ---------------------------------------------------------------- answers on each engine

const hasPolicy = (events) => events.some((e) => e.type === "ATTEMPT_DUTY_POLICY_ACTIVATED");
const admissionBinding = (events) => {
  const admission = events.find((e) => e.type === "TRANSACTION_INTENT_ADMITTED");
  if (admission === undefined) return undefined;
  const proof = plain(admission.data.authorizationProof);
  const binding = Object.fromEntries(["runtimeSessionId", "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "intentId", "nonce"].map((key) => [key, proof[key]]));
  return { proof, binding: { ...binding, runtimeSignature: admission.data.runtimeSignature }, prefix: proof.historyHead.position + 1 };
};
/** The reference's answers on a legacy prefix at `now`. */
function referenceAnswers(events, now, dutyId = "duty") {
  const state = refStateOf(events), ext = hasPolicy(events) ? [ref.DUTY_POLICY_VERSION] : [];
  const at = Math.max(now, state.head.canonicalTime);
  const a = admissionBinding(events);
  const query = (kind, extra) => ref[`${kind.toLowerCase()}Portable`]({ operationVersion: ref.PORTABLE_QUERY_VERSION, ...extra, disclosure: ref.portablePublicQueryDisclosure(kind, ext) });
  return {
    view: inspectPortableDutyPolicy(state, dutyId) ?? null,
    attempts: refInspectAttempts(events).attempts,
    survives: query("SURVIVES", { observedEvents: events, targetAgentId: "worker", evaluationTime: at }),
    ...(a === undefined ? {} : {
      responsible: query("RESPONSIBLE", { evaluationEvents: events.slice(0, a.prefix), observedEvents: events, authorizationDomain: events[0].data.domain, request: a.proof.request, evaluationTime: a.proof.evaluationTime, consequentialBinding: a.binding }),
      why: query("WHY", { evaluationEvents: events.slice(0, a.prefix), observedEvents: events, authorizationDomain: events[0].data.domain, request: a.proof.request, evaluationTime: a.proof.evaluationTime, consequentialBinding: a.binding }),
    }),
    dutyReserved: refCapacityOf(events).dutyReserved ?? 0,
    evidenceIndex: state.attemptDutyPolicies.has(dutyId) ? derivePortableDutyEvidenceIndex(state, dutyId) : null,
  };
}
/** The IronTrellis answers on a format-2 prefix at `now`. */
function trellisAnswers(events, now, dutyId = "duty") {
  const replayed = replay(events);
  assert.equal(replayed.status, "ACCEPTED", `twin prefix (${events.length}) rejected: ${replayed.code} ${replayed.reason}`);
  const state = replayed.state, ext = hasPolicy(events) ? [core.DUTY_POLICY_VERSION] : [];
  const at = Math.max(now, state.head.canonicalTime);
  const a = admissionBinding(events);
  const evaluation = a === undefined ? state : replay(events.slice(0, a.prefix)).state;
  return {
    view: inspectDutyPolicyState(state, dutyId),
    attempts: inspectAttemptHistory(events).attempts,
    survives: core.survivesState(state, { targetAgentId: "worker", evaluationTime: at, disclosure: core.publicQueryDisclosure("SURVIVES", ext) }),
    ...(a === undefined ? {} : {
      responsible: core.responsibleState(evaluation, state, { authorizationDomain: state.genesis.domain, request: a.proof.request, evaluationTime: a.proof.evaluationTime, consequentialBinding: a.binding, disclosure: core.publicQueryDisclosure("RESPONSIBLE", ext) }),
      why: core.whyState(evaluation, state, { authorizationDomain: state.genesis.domain, request: a.proof.request, evaluationTime: a.proof.evaluationTime, consequentialBinding: a.binding, disclosure: core.publicQueryDisclosure("WHY", ext) }),
    }),
    dutyReserved: capacityOf(state).dutyReserved,
    evidenceIndex: state.attemptDutyPolicies.has(dutyId) ? core.deriveDutyEvidenceIndex(state, dutyId) : null,
  };
}
const firstDifference = (a, b) => { let i = 0; while (i < a.length && a[i] === b[i]) i += 1; return `…${a.slice(Math.max(0, i - 120), i + 200)}\n   vs …${b.slice(Math.max(0, i - 120), i + 200)}`; };
function compareAnswers(label, legacyEvents, twinEvents, now) {
  const L = referenceAnswers(legacyEvents, now), T = trellisAnswers(twinEvents, now);
  const lt = positionTokens(legacyEvents, { legacy: ref }), tt = positionTokens(twinEvents, { legacy: false });
  for (const key of Object.keys(L)) {
    const a = projected(L[key], lt), b = projected(T[key], tt);
    assert.equal(b, a, `${label}: ${key} differs:\n${firstDifference(a, b)}`);
    compared += 1;
  }
  assert.deepEqual(Object.keys(T).sort(), Object.keys(L).sort());
  return { L, T };
}

// ---------------------------------------------------------------- the scenario driver over the reference engine

/** A reference duty fixture with the scenario log: checkpoints (prefix lengths + answers) and refusals (prefix + the refused operation). */
async function legacyScenario(t, { policy = "E5" } = {}) {
  const f = await refDutyFixture(t, { policy });
  let clock = 100;
  const setTime = (at) => { clock = at; f.setTime(at); };
  const log = { checkpoints: [], refusals: [] };
  log.calls = []; log.selections = [{ ...f.selection.descriptor, legacyHash: f.selection.descriptorHash }];
  /** A signer from a descriptor (`{setTime, append, result}`: what happens while the signer runs) or a closure; both drivers build theirs from the same descriptor. */
  const driverHooks = { setTime, appendAgent: (id) => { f.owner.createAgent({ id }); } };
  const counted = (label, descriptor) => { const sign = signerFrom(descriptor, driverHooks, refSign); return async (h) => { log.calls.push(label); return sign(h); }; };
  /** The reference duty handle with counted signers; `attester` names a distinct attester session. */
  const handle = ({ attester, finding, outer, options = {} } = {}) => refOpenDuties({ ...f.options, ...options, signHash: counted("outer", outer) }, attester === undefined ? undefined : { session: attester, signHash: counted("finding", finding) });
  const d = {
    f, owner: f.owner, selection: f.selection, input: f.input, grant: f.grant, append: f.append, setTime, now: () => clock, handle, log, policy,
    /** A second selection the scenario describes (its legacy descriptor hash lets the twin rewrite the grants naming it). */
    describe(selection) { const s = d.handle().describe(selection); log.selections.push({ ...s.descriptor, legacyHash: s.descriptorHash }); return s; },
    get events() { return f.owner.exportHistory(); },
    recorder: (options = {}) => refRecorder({ ...f.options, ...options }),
    /** Records the reference's answers at the current prefix. */
    checkpoint(label) { const events = d.events; log.checkpoints.push({ label, length: events.length, now: clock }); return events; },
    /** The reference refuses `op`; the twin store must refuse it too (same signer calls before the refusal). */
    async refuse(label, op) {
      const events = d.events, before = log.calls.length, now = clock;
      await assert.rejects(runOp(handle(op), op), `reference: ${label} should refuse`);
      // A signer that appends a racer event changes the history by that one event and never by a duty event.
      const appended = [op.finding, op.outer].some((x) => x?.append !== undefined) ? 1 : 0;
      assert.equal(d.events.length, events.length + appended, `reference: ${label} appended`);
      assert.equal(canonicalEncode(d.events.slice(0, events.length)), canonicalEncode(events), `reference: ${label} changed the prefix`);
      log.refusals.push({ label, length: events.length, now, op, calls: log.calls.slice(before), appended });
    },
  };
  return d;
}
const runOp = (duties, op) => duties[op.method](op.input);
/** A format-2 store holding `events`, pinned and attested by `owner` (the attestation is awaited before the handle is released). */
async function twinStore(path, events, owner) {
  const store = createHistoryStore(path, events, { signer: owner });
  await store.flush();
  store.close();
  return path;
}
const signerFrom = (descriptor, hooks, baseSign) => {
  if (typeof descriptor === "function") return descriptor;
  return async (h) => {
    if (descriptor?.append !== undefined) await hooks.appendAgent(descriptor.append);
    if (descriptor?.setTime !== undefined) hooks.setTime(descriptor.setTime);
    if (descriptor?.result === "throw") throw new Error("offline");
    if (descriptor?.result === "zero") return `0x${"0".repeat(130)}`;
    return baseSign(h);
  };
};

/** The twin of a legacy history (cached per events array) and the IronTrellis API refusal check on a store holding its prefix. */
async function twinOf(legacyEvents, owner, selections = []) {
  return transcribeLegacyToFormat2(legacyEvents, { sign: mySign, owner, selections });
}
/** The op's legacy descriptor becomes the twin's (the same selection re-derived on the twin prefix; a forgery is re-applied on top). */
const translateInput = (op, prefixState) => {
  const input = op.input;
  if (input?.descriptor === undefined) return input;
  const legacy = input.descriptor;
  const derived = core.deriveDutyPolicyDescriptor(prefixState, { dutyId: legacy.dutyId, incidentSourceDigest: legacy.incidentSourceDigest, acceptedAttesterRoleId: legacy.acceptedAttesterRoleId });
  const descriptor = op.forge === undefined ? derived : op.forge(mutable(derived ?? legacy));
  return { ...input, descriptor: descriptor ?? legacy };
};
async function trellisRefusal(t, twin, refusal, workspace) {
  const dir = mkdtempSync(join(workspace, "prefix-"));
  const path = join(dir, "history.jsonl");
  const prefix = twin.events.slice(0, refusal.length);
  await twinStore(path, prefix, twin.owner);
  const calls = [];
  const domain = prefix[0].data.domain;
  let now = refusal.now;
  const base = { historyFile: path, domain, owner: "owner", controller: "controller", now: () => now, signer: twin.owner, session: "session" };
  const hooks = { setTime: (at) => { now = at; }, appendAgent: async (id) => { await core.openLocalOwner(base).createAgent({ id }); } };
  const op = { ...refusal.op, input: translateInput(refusal.op, replay(prefix).state) };
  const attester = op.attester === undefined ? undefined : { session: op.attester, signHash: (() => { const sign = signerFrom(op.finding, hooks, mySign); return async (h) => { calls.push("finding"); return sign(h); }; })() };
  const outer = signerFrom(op.outer, hooks, mySign);
  const handle = openLocalDutyPolicy({ ...base, ...(op.options ?? {}), signHash: async (h) => { calls.push("outer"); return outer(h); } }, attester);
  await assert.rejects(runOp(handle, op), `IronTrellis: ${refusal.label} should refuse`);
  assert.deepEqual(calls, refusal.calls, `${refusal.label}: signer calls before the refusal`);
  const after = core.openHistoryStore(path, { signer: twin.owner }).readAll();
  assert.equal(after.length, refusal.length + refusal.appended, `${refusal.label}: the twin store appended`);
  assert.equal(canonicalEncode(after.slice(0, refusal.length)), canonicalEncode(prefix), `${refusal.label}: the twin prefix changed`);
  refusalsCompared += 1;
}
/** Runs the reference scenario, builds the twin, compares every checkpoint and re-attempts every refusal. */
async function differential(t, name, scenario, options = {}) {
  await t.test(name, async (t) => {
    const d = await legacyScenario(t, options);
    await scenario(d);
    const legacy = d.events;
    const owner = twinOwner();
    const twin = await twinOf(legacy, owner, d.log.selections);
    assert.equal(twin.events.length, legacy.length);
    for (const checkpoint of d.log.checkpoints) compareAnswers(`${name} / ${checkpoint.label}`, legacy.slice(0, checkpoint.length), twin.events.slice(0, checkpoint.length), checkpoint.now);
    if (d.log.checkpoints.at(-1)?.length !== legacy.length) compareAnswers(`${name} / final`, legacy, twin.events, d.now());
    if (d.log.refusals.length > 0) {
      const workspace = mkdtempSync(join(tmpdir(), "irontrellis-t5-"));
      t.after(() => rmSync(workspace, { recursive: true, force: true }));
      for (const refusal of d.log.refusals) await trellisRefusal(t, twin, refusal, workspace);
    }
    return { d, legacy, twin };
  });
}

const activationOp = (d, input = d.input, extra = {}) => ({ method: "activate", input, ...extra });
const disposeOp = (input, extra = {}) => ({ method: "dispose", input, ...extra });
const contestOp = (input, extra = {}) => ({ method: "contest", input, ...extra });
const completed = { id: "complete", duty: "duty", disposition: "COMPLETED_UNDER_POLICY", checklist: checklist(), reportDigest: digest("b"), nextStep: null, attestationAuthority: "finding", dispositionAuthority: "disposition" };
const contestInput = (id) => ({ id, duty: "duty", targetDispositionId: "duty-disposition:complete", reason: "Incident material may have been incomplete.", reportDigest: digest("c"), attestationAuthority: "finding", dispositionAuthority: "disposition" });
/** The reference disposition setup (`duty-disposition.test.mjs setup`). */
async function activated(d, { findingGrant = true, dispositionGrant = true } = {}) {
  d.grant(); await d.handle().activate(d.input);
  const resource = `duty:${d.selection.descriptorHash}`;
  if (findingGrant) d.owner.grant({ id: "finding", to: "worker", actions: ["ATTEST_DUTY_FINDING"], resources: [resource], expiresAt: 1000 });
  if (dispositionGrant) d.owner.grant({ id: "disposition", to: "worker", actions: ["RECORD_DUTY_DISPOSITION"], resources: [resource], expiresAt: 1000 });
  return resource;
}

// ---------------------------------------------------------------- duty-activation.test.mjs (13 cases)

test("T5: duty-activation (reference-0.3 duty-activation.test.mjs) — activation, queries, retries, grant variants, descriptor substitution, principals, lifecycle, post-sign checks", async (t) => {
  await differential(t, "A1 activates the original E5 duty without changing prior evidence, spent allowance or revocation", async (d) => {
    d.grant(); d.checkpoint("granted");
    const r = await d.handle().activate(d.input);
    assert.equal(r.alreadyRecorded, false); assert.equal(r.view.dutyDisposition, "OPEN");
    assert.deepEqual(d.log.calls, ["outer"]);
    d.checkpoint("activated");
  });
  await differential(t, "A2 E6 remains E6: the activation on a review deployment", async (d) => {
    d.grant(); await d.handle().activate(d.input); d.checkpoint("activated-e6");
    await d.recorder().reviewDuty({ id: "review", duty: "duty", summaryDigest: digest("e").value }); d.checkpoint("reviewed");
  }, { policy: "E6" });
  await differential(t, "A3 current queries disclose the activated policy; the unextended disclosure refuses on both engines", async (d) => {
    d.grant(); await d.handle().activate(d.input); d.checkpoint("activated");
    const events = d.events;
    const old = ref.survivesPortable({ operationVersion: ref.PORTABLE_QUERY_VERSION, observedEvents: events, targetAgentId: "worker", evaluationTime: 100, disclosure: ref.portablePublicQueryDisclosure("SURVIVES") });
    assert.equal(old.code, "DISCLOSURE_INVALID");
    const twin = await twinOf(events, twinOwner());
    const mine = core.survivesState(twin.state, { targetAgentId: "worker", evaluationTime: 100, disclosure: core.publicQueryDisclosure("SURVIVES") });
    assert.equal(mine.code, "DISCLOSURE_INVALID");
    assert.deepEqual([...core.publicQueryDisclosure("SURVIVES", [core.DUTY_POLICY_VERSION]).includedFields], [...ref.portablePublicQueryDisclosure("SURVIVES", [ref.DUTY_POLICY_VERSION]).includedFields]);
    assert.deepEqual([...core.publicQueryDisclosure("RESPONSIBLE", [core.DUTY_POLICY_VERSION]).includedFields], [...ref.portablePublicQueryDisclosure("RESPONSIBLE", [ref.DUTY_POLICY_VERSION]).includedFields]);
    assert.deepEqual([...core.publicQueryDisclosure("WHY", [core.DUTY_POLICY_VERSION]).includedFields], [...ref.portablePublicQueryDisclosure("WHY", [ref.DUTY_POLICY_VERSION]).includedFields]);
  });
  await differential(t, "A4 exact activation retry survives retirement without another signature; changed operation and second activation refuse", async (d) => {
    d.grant(); const first = await d.handle().activate(d.input);
    d.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 }); d.owner.revoke("activation");
    const repeated = await d.handle().activate(d.input);
    assert.equal(repeated.alreadyRecorded, true); assert.equal(repeated.eventId, first.eventId); assert.deepEqual(d.log.calls, ["outer"]);
    d.checkpoint("retired");
    await d.refuse("different-authority", activationOp(d, { ...d.input, activationAuthority: "different" }));
    await d.refuse("second-activation", activationOp(d, { ...d.input, id: "second" }));
    // The twin store answers the identical repeat as already recorded, without a signature.
    const twin = await twinOf(d.events, twinOwner());
    const dir = mkdtempSync(join(tmpdir(), "irontrellis-t5-repeat-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "history.jsonl"); await twinStore(path, twin.events, twin.owner);
    let calls = 0;
    const again = await openLocalDutyPolicy({ historyFile: path, domain: twin.events[0].data.domain, owner: "owner", controller: "controller", now: () => 100, signer: twin.owner, session: "session", signHash: async (h) => { calls++; return mySign(h); } }).activate({ ...d.input, descriptor: twin.state.attemptDutyPolicies.get("duty").descriptor });
    assert.equal(again.alreadyRecorded, true); assert.equal(calls, 0);
  });
  await t.test("A5 the host API refuses executable selection input (host input shape, both engines; no history to compare)", async (t) => {
    const d = await legacyScenario(t);
    let reads = 0;
    assert.throws(() => d.handle().describe({ duty: "duty", get incidentSourceDigest() { reads++; return digest("a"); }, attesterRole: "role" })); assert.equal(reads, 0);
    await assert.rejects(d.handle().activate({ ...d.input, unexpected: undefined })); assert.deepEqual(d.log.calls, []);
    const { dutyFixture } = await import("./helpers/duty-fixture.mjs");
    const x = await dutyFixture(t);
    assert.throws(() => x.duties.describe({ duty: "duty", get incidentSourceDigest() { reads++; return digest("a"); }, attesterRole: "role" })); assert.equal(reads, 0);
    await assert.rejects(x.duties.activate({ ...x.input, unexpected: undefined })); assert.equal(x.calls, 0);
  });
  await differential(t, "A6 activation requires the exact live dedicated grant (missing, broad action/resource, multiple resources, capped, amount-capped, expired, future, wrong grantee, revoked, wrong selected grant)", async (d) => {
    const variants = [["missing", null], ["broad-action", { actions: ["ACTIVATE_DUTY_POLICY", "other"] }], ["broad-resource", { resources: ["wrong"] }], ["multiple-resources", { resources: [d.selection.activationResource, "other"] }], ["capped", { maxTransactions: 1 }], ["amount-capped", { maxAmount: 1n }], ["expired", { expiresAt: 100 }], ["future", { notBefore: 101 }], ["wrong-grantee", { to: "replacement" }]];
    for (const [name, changes] of variants) {
      if (changes !== null) d.grant({ id: `activation:${name}`, ...changes });
      await d.refuse(name, activationOp(d, { ...d.input, activationAuthority: changes === null ? "activation" : `activation:${name}` }));
    }
    d.grant(); d.owner.revoke("activation");
    await d.refuse("revoked", activationOp(d));
    await d.refuse("wrong-selected-grant", activationOp(d, { ...d.input, activationAuthority: "record" }));
    d.checkpoint("no-policy");
  });
  await differential(t, "A7 descriptor source facts and the fixed rule identity cannot be substituted (14 fields)", async (d) => {
    for (const key of ["rulesHash", "domain", "genesisHash", "baseAdapterPolicyHash", "dutyId", "dutyCreationEventId", "dutyRecordHash", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "principalId", "acceptedAttesterRoleId", "dispositionLimit", "contestLimit"]) {
      const forged = mutable(d.selection.descriptor);
      if (key === "domain") forged.domain = { ...forged.domain, deploymentId: "other" };
      else if (key.endsWith("Hash")) forged[key] = `0x${"b".repeat(64)}`;
      else if (key.endsWith("Limit")) forged[key] = 0;
      else forged[key] = "other";
      const forge = (descriptor) => { if (key === "domain") descriptor.domain = { ...descriptor.domain, deploymentId: "other" }; else if (key.endsWith("Hash")) descriptor[key] = `0x${"b".repeat(64)}`; else if (key.endsWith("Limit")) descriptor[key] = 0; else descriptor[key] = "other"; return descriptor; };
      // Even an exact grant for the forged descriptor cannot alter source facts (the twin's grant keeps the legacy hash: the refusal is the descriptor's on both engines).
      d.grant({ id: `activation:${key}`, resources: [`duty-policy:${ref.hashCanonical(forged)}`] });
      await d.refuse(key, { method: "activate", input: { ...d.input, descriptor: forged, activationAuthority: `activation:${key}` }, forge });
    }
  });
  await differential(t, "A8 a same-principal attester selection allows an internal reviewer role but never creates new authority", async (d) => {
    d.owner.createRole({ id: "reviewer" });
    const selection = d.describe({ duty: "duty", incidentSourceDigest: digest("a"), attesterRole: "reviewer" });
    d.grant({ resources: [selection.activationResource] });
    await d.handle().activate({ ...d.input, descriptor: selection.descriptor });
    assert.equal(refStateOf(d.events).attemptDutyPolicies.get("duty").descriptor.acceptedAttesterRoleId, "reviewer");
    d.checkpoint("reviewer-attester");
  });
  for (const kind of ["wrong-principal", "delegable", "delegated", "prohibited", "intersection", "capped-winner", "alternate-winner"]) {
    await differential(t, `A9 ${kind}: a wrong principal, delegable or delegated roots, prohibitions, intersections and alternate winners cannot activate`, async (d) => {
      const base = mutable(d.events.find((e) => e.type === "AUTHORITY_GRANTED").data.grant);
      const grant = { ...base, authorityId: "activation", rootAuthorityId: "activation", constraints: { ...base.constraints, actions: [d.selection.activationAction], resources: [d.selection.activationResource], maxDelegationDepth: 0 } };
      delete grant.constraints.maxTransactions;
      if (kind === "wrong-principal") { d.append("foreign", "PRINCIPAL_CREATED", { principalId: "foreign" }); grant.grantorId = "foreign"; }
      if (kind === "delegable") grant.constraints.maxDelegationDepth = 1;
      if (kind === "delegated") {
        d.append("parent", "AUTHORITY_GRANTED", { grant: { ...grant, authorityId: "parent", rootAuthorityId: "parent", granteeId: "replacement", constraints: { ...grant.constraints, maxDelegationDepth: 1 } } });
        grant.grantorId = "replacement"; grant.parentAuthorityId = "parent"; grant.rootAuthorityId = "parent";
      }
      if (kind === "intersection") {
        d.append("intersection", "AUTHORITY_GRANTED", { grant: { ...grant, authorityId: "intersection", rootAuthorityId: "intersection", constraints: { ...grant.constraints, actions: ["different"] } } });
        grant.constraints.requiredIntersectionIds = ["intersection"];
      }
      if (kind === "capped-winner" || kind === "alternate-winner") d.append("a-winner", "AUTHORITY_GRANTED", { grant: { ...grant, authorityId: "a-winner", rootAuthorityId: "a-winner", constraints: { ...grant.constraints, ...(kind === "capped-winner" ? { maxTransactions: 1 } : {}) } } });
      d.append("activation-grant", "AUTHORITY_GRANTED", { grant });
      if (kind === "prohibited") d.append("prohibition", "AUTHORITY_GRANTED", { grant: { kind: "PROHIBITION", scope: "GLOBAL", authorityId: "prohibition", grantorId: d.events[0].data.globalPolicySourceId, subjectActorId: "worker", constraints: grant.constraints } });
      await d.refuse(kind, activationOp(d));
      assert.equal(refStateOf(d.events).attemptDutyPolicies.size, 0);
      d.checkpoint("no-policy");
    });
  }
  await differential(t, "A10 epoch: a retired runtime cannot activate", async (d) => {
    d.grant();
    d.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 });
    await d.refuse("epoch", activationOp(d));
    d.checkpoint("retired");
  });
  await differential(t, "A10 tenure: a changed role tenure cannot activate; an owner-string substitution is PROFILE_MISMATCH on both", async (d) => {
    d.grant();
    d.owner.succeed({ id: "replace", rule: "succession", fromAgent: "worker", fromTenure: "tenure", toAgent: "replacement", toTenure: "tenure:2", role: "role", number: 2 });
    await d.refuse("tenure", activationOp(d));
    assert.throws(() => d.handle({ options: { owner: "foreign" } }), (e) => e.code === "PROFILE_MISMATCH");
    const twin = await twinOf(d.events, twinOwner());
    const dir = mkdtempSync(join(tmpdir(), "irontrellis-t5-owner-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "history.jsonl"); await twinStore(path, twin.events, twin.owner);
    assert.throws(() => openLocalDutyPolicy({ historyFile: path, domain: twin.events[0].data.domain, owner: "foreign", controller: "controller", now: () => 100, signer: twin.owner, session: "session", signHash: mySign }), (e) => e.code === "PROFILE_MISMATCH");
    d.checkpoint("succeeded");
  });
  await differential(t, "A11 post-sign checks allow forward time, reject grant expiry, session expiry and regression, and preserve the signed timestamp", async (d) => {
    d.grant({ expiresAt: 1000 });
    for (const [name, at] of [["grant-expiry", 1000], ["regression", 99]]) {
      await d.refuse(name, activationOp(d, d.input, { outer: { setTime: at } }));
      d.setTime(100);
    }
    d.owner.revoke("activation"); d.grant({ id: "activation:late", expiresAt: 20000 });
    await d.refuse("session-expiry", activationOp(d, { ...d.input, activationAuthority: "activation:late" }, { outer: { setTime: 10000 } }));
    d.setTime(100);
    const forward = await d.handle({ outer: async (h) => { d.setTime(101); return refSign(h); } }).activate({ ...d.input, activationAuthority: "activation:late" });
    assert.equal(forward.alreadyRecorded, false); assert.equal(d.events.at(-1).timestamp, 100);
    d.checkpoint("forward");
  });
  await differential(t, "A12 a concurrent append during signing conflicts; request mutation cannot change the captured effect", async (d) => {
    d.grant();
    await d.refuse("concurrent-append", activationOp(d, d.input, { outer: { append: "racer" } }));
    assert.equal(refStateOf(d.events).attemptDutyPolicies.size, 0);
    const input = mutable(d.input);
    await d.handle({ outer: async (h) => { input.descriptor.dutyId = "mutated"; return refSign(h); } }).activate(input);
    assert.equal(refStateOf(d.events).attemptDutyPolicies.has("duty"), true);
    d.checkpoint("activated-after-race");
  });
  await differential(t, "A13 a failed signer, an invalid signature and unsupported raw duty events cannot append; replay refuses them on both", async (d) => {
    d.grant();
    await d.refuse("signer-throws", activationOp(d, d.input, { outer: { result: "throw" } }));
    await d.refuse("signature-zero", activationOp(d, d.input, { outer: { result: "zero" } }));
    await d.handle().activate(d.input);
    for (const type of ["ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]) assert.throws(() => d.append(`future:${type}`, type, { dutyId: "duty" }));
    const twin = await twinOf(d.events, twinOwner());
    for (const type of ["ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]) assert.equal(withProspectiveEvent(twin.state, { id: `future:${type}`, type, timestamp: 100, data: { dutyId: "duty" } }).ok, false);
    // A second activation of the same duty (a copy under another id) is refused by both replays.
    const activation = d.events.at(-1);
    assert.equal(ref.replayPortable({ operationVersion: ref.PORTABLE_REPLAY_VERSION, events: [...d.events, { ...activation, id: "again" }] }).status, "REJECTED");
    assert.equal(withProspectiveEvent(twin.state, { ...twin.events.at(-1), id: "again" }).ok, false);
    d.checkpoint("activated");
  });
  t.diagnostic(`answers compared: ${compared}, refusals re-attempted: ${refusalsCompared}`);
});

// ---------------------------------------------------------------- duty-disposition.test.mjs (17 cases)

test("T5: duty-disposition (reference-0.3 duty-disposition.test.mjs) — findings, eligibility, retries, views, fresh checks, attesters, forgeries", async (t) => {
  await differential(t, "D1 a complete local investigation has two signatures, preserved transaction uncertainty and reserved remaining capacity", async (d) => {
    await activated(d); d.checkpoint("activated");
    const prep = d.handle({ attester: "session" }).prepareDisposition(completed);
    assert.equal(prep.executionCapability, false);
    const result = await d.handle({ attester: "session" }).dispose(completed);
    assert.deepEqual(d.log.calls.slice(-2), ["finding", "outer"]); assert.equal(result.view.dutyDisposition, "COMPLETED_UNDER_POLICY");
    assert.equal(refCapacityOf(d.events).dutyReserved, 5);
    d.checkpoint("completed");
  });
  await differential(t, "D2 missing material can escalate but cannot complete; syntax and oversized input refuse before callbacks", async (d) => {
    await activated(d);
    const missing = { ...completed, disposition: "ESCALATED", checklist: checklist(), nextStep: "Ask the internal custodian for the missing incident file." };
    missing.checklist.SOURCE_REVIEWED.state = "UNAVAILABLE";
    const result = await d.handle({ attester: "session" }).dispose(missing);
    assert.equal(result.view.dutyDisposition, "ESCALATED"); d.checkpoint("escalated");
    for (const kind of ["incomplete", "empty-next-step", "extra", "undefined", "long-reason", "long-next-step", "absent-report", "wrong-digest"]) {
      const v = mutable({ ...completed, id: `complete:${kind}` });
      if (kind === "incomplete") v.checklist.HISTORY_REVIEWED.state = "UNRESOLVED";
      if (kind === "empty-next-step") { v.disposition = "ESCALATED"; v.checklist.HISTORY_REVIEWED.state = "UNRESOLVED"; v.nextStep = ""; }
      if (kind === "extra") v.checklist.OTHER = { state: "SATISFIED", reason: "extra" };
      if (kind === "undefined") v.nextStep = undefined;
      if (kind === "long-reason") v.checklist.SOURCE_REVIEWED.reason = "x".repeat(257);
      if (kind === "long-next-step") { v.disposition = "ESCALATED"; v.checklist.SOURCE_REVIEWED.state = "UNAVAILABLE"; v.nextStep = "x".repeat(513); }
      if (kind === "absent-report") delete v.reportDigest;
      if (kind === "wrong-digest") v.reportDigest.algorithm = "sha512";
      await d.refuse(kind, disposeOp(v, { attester: "session" }));
    }
  });
  await differential(t, "D3 attestation and disposition authority are independently necessary", async (d) => {
    await activated(d, { findingGrant: false });
    await d.refuse("no-finding-grant", disposeOp(completed, { attester: "session" }));
    d.owner.grant({ id: "finding", to: "worker", actions: ["ATTEST_DUTY_FINDING"], resources: [`duty:${d.selection.descriptorHash}`], expiresAt: 1000 });
    await d.refuse("swapped-authorities", disposeOp({ ...completed, attestationAuthority: "disposition", dispositionAuthority: "finding" }, { attester: "session" }));
    d.owner.revoke("disposition");
    await d.refuse("no-disposition-grant", disposeOp(completed, { attester: "session" }));
  });
  await differential(t, "D4 exact retries report the current view after contests and retirement, never sign again; a different repeat conflicts", async (d) => {
    await activated(d);
    const first = await d.handle({ attester: "session" }).dispose(completed);
    await d.handle({ attester: "session" }).contest(contestInput("challenge"));
    d.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 }); d.owner.revoke("finding"); d.owner.revoke("disposition");
    const calls = d.log.calls.length;
    const repeated = await d.handle({ attester: "session" }).dispose(completed);
    assert.equal(repeated.alreadyRecorded, true); assert.equal(repeated.eventId, first.eventId); assert.equal(repeated.view.dutyDisposition, "CONTESTED"); assert.equal(d.log.calls.length, calls);
    await d.refuse("different-digest", disposeOp({ ...completed, reportDigest: digest("d") }, { attester: "session" }));
    const repeatContest = await d.handle({ attester: "session" }).contest(contestInput("challenge"));
    assert.equal(repeatContest.alreadyRecorded, true); assert.equal(d.log.calls.length, calls);
    d.checkpoint("retired-contested");
    // The twin store repeats both without a signature.
    const twin = await twinOf(d.events, twinOwner());
    const dir = mkdtempSync(join(tmpdir(), "irontrellis-t5-repeat-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "history.jsonl"); await twinStore(path, twin.events, twin.owner);
    const count = []; const sign = async (h) => { count.push(1); return mySign(h); };
    const handle = openLocalDutyPolicy({ historyFile: path, domain: twin.events[0].data.domain, owner: "owner", controller: "controller", now: () => 100, signer: twin.owner, session: "session", signHash: sign }, { session: "session", signHash: sign });
    assert.equal((await handle.dispose(completed)).alreadyRecorded, true); assert.equal((await handle.contest(contestInput("challenge"))).alreadyRecorded, true); assert.equal(count.length, 0);
  });
  await differential(t, "D5 later same-duty evidence stales a completion; unrelated events, expiry and revocation do not", async (d) => {
    await activated(d); await d.handle({ attester: "session" }).dispose(completed);
    d.owner.createAgent({ id: "unrelated" }); d.owner.revoke("finding"); d.setTime(1001);
    assert.equal(d.handle({ attester: "session" }).inspect("duty").policy.dutyDisposition, "COMPLETED_UNDER_POLICY"); d.checkpoint("still-completed");
    await d.recorder().reviewDuty({ id: "later-review", duty: "duty", summaryDigest: digest("e").value });
    assert.equal(d.handle({ attester: "session" }).inspect("duty").policy.dutyDisposition, "NEEDS_REVIEW"); d.checkpoint("needs-review");
  }, { policy: "E6" });
  await differential(t, "D6 quotas are independent (fifth disposition, third contest); contests persist through escalation and further evidence", async (d) => {
    await activated(d);
    for (let i = 0; i < 4; i++) await d.handle({ attester: "session" }).dispose({ ...completed, id: i ? `complete:${i}` : "complete" });
    assert.equal(refCapacityOf(d.events).dutyReserved, 2); d.checkpoint("four");
    await d.refuse("fifth-disposition", disposeOp({ ...completed, id: "fifth" }, { attester: "session" }));
    await d.recorder().reviewDuty({ id: "after-four", duty: "duty", summaryDigest: digest("e").value });
    d.checkpoint("needs-review");
    await d.handle({ attester: "session" }).contest(contestInput("one")); await d.handle({ attester: "session" }).contest(contestInput("two"));
    assert.equal(refCapacityOf(d.events).dutyReserved, 0); d.checkpoint("two-contests");
    await d.refuse("third-contest", contestOp(contestInput("three"), { attester: "session" }));
    await d.refuse("completed-after-contest", disposeOp({ ...completed, id: "complete-again" }, { attester: "session" }));
    await d.refuse("escalated-without-next-step", disposeOp({ ...completed, id: "escalate-blank", disposition: "ESCALATED" }, { attester: "session" }));
  }, { policy: "E6" });
  await differential(t, "D6b an escalation after two contests stays CONTESTED and keeps its reservation; a contest must target an accepted disposition", async (d) => {
    await activated(d);
    await d.handle({ attester: "session" }).dispose(completed); await d.handle({ attester: "session" }).contest(contestInput("one")); await d.handle({ attester: "session" }).contest(contestInput("two"));
    await d.refuse("stray-target", contestOp({ ...contestInput("stray"), targetDispositionId: "duty-disposition:missing" }, { attester: "session" }));
    const escalated = await d.handle({ attester: "session" }).dispose({ ...completed, id: "escalate", disposition: "ESCALATED", nextStep: "Investigate the contest with the existing Principal." });
    assert.equal(escalated.view.dutyDisposition, "CONTESTED"); assert.equal(refCapacityOf(d.events).dutyReserved, 2);
    d.checkpoint("escalated-contested");
  });
  await differential(t, "D7 each signing callback is followed by fresh authority, head and monotone-clock checks", async (d) => {
    await activated(d);
    for (const phase of ["finding", "outer"]) {
      for (const change of ["head", "expiry", "regression"]) {
        const mutate = change === "head" ? { append: `racer:${phase}` } : { setTime: change === "expiry" ? 1000 : 99 };
        await d.refuse(`${phase}:${change}`, disposeOp(completed, { attester: "session", ...(phase === "finding" ? { finding: mutate } : { outer: mutate }) }));
        d.setTime(100);
      }
    }
    await d.refuse("regression-between-signatures", disposeOp(completed, { attester: "session", finding: { setTime: 101 }, outer: { setTime: 100 } }));
    d.setTime(100);
    const forward = await d.handle({ attester: "session", finding: async (h) => { d.setTime(101); return refSign(h); }, outer: async (h) => { d.setTime(102); return refSign(h); } }).dispose(completed);
    assert.equal(forward.view.dutyDisposition, "COMPLETED_UNDER_POLICY"); assert.equal(d.events.at(-1).timestamp, 100);
    d.checkpoint("forward");
  });
  await differential(t, "D8 a bad first signature never calls the second signer; a failed second signer never appends", async (d) => {
    await activated(d);
    await d.refuse("bad-finding-signature", disposeOp(completed, { attester: "session", finding: { result: "zero" } }));
    await d.refuse("outer-signer-offline", disposeOp(completed, { attester: "session", outer: { result: "throw" } }));
  });
  await differential(t, "D9 a distinct internal attester needs its own current role, runtime and exact permission", async (d) => {
    d.owner.createAgent({ id: "reviewer" }); d.owner.createRole({ id: "review-role" });
    d.owner.appoint({ agent: "reviewer", role: "review-role", tenure: "review-tenure", number: 1 });
    d.owner.admitRuntime({ agent: "reviewer", session: "review-session", epoch: 1, key: "review-key", address: account.address, expiresAt: 1000 });
    const selected = d.describe({ duty: "duty", incidentSourceDigest: digest("a"), attesterRole: "review-role" });
    d.grant({ resources: [selected.activationResource] }); await d.handle().activate({ ...d.input, descriptor: selected.descriptor });
    const resource = `duty:${selected.descriptorHash}`;
    d.owner.grant({ id: "finding", to: "reviewer", actions: ["ATTEST_DUTY_FINDING"], resources: [resource], expiresAt: 1000 });
    d.owner.grant({ id: "disposition", to: "worker", actions: ["RECORD_DUTY_DISPOSITION"], resources: [resource], expiresAt: 1000 });
    await d.refuse("worker-is-not-the-attester", disposeOp(completed, { attester: "session" }));
    const result = await d.handle({ attester: "review-session" }).dispose(completed);
    assert.equal(result.view.dutyDisposition, "COMPLETED_UNDER_POLICY");
    assert.equal(d.events.at(-1).data.finding.challenge.attesterId, "reviewer");
    d.checkpoint("reviewer-attested");
    await d.refuse("reviewer-expired", disposeOp({ ...completed, id: "expired-reviewer" }, { attester: "review-session", outer: { setTime: 1000 } }));
  });
  await differential(t, "D10 captured caller input cannot change between signatures; copied and patched findings are refused by both replays", async (d) => {
    await activated(d);
    const input = mutable(completed);
    await d.handle({ attester: "session", finding: async (h) => { input.reportDigest.value = digest("f").value; input.checklist.SOURCE_REVIEWED.state = "UNAVAILABLE"; return refSign(h); } }).dispose(input);
    assert.equal(canonicalEncode(d.events.at(-1).data.finding.challenge.operation.reportDigest), canonicalEncode(completed.reportDigest));
    d.checkpoint("captured");
    const legacy = d.events, original = legacy.at(-1), twin = await twinOf(legacy, twinOwner()), twinOriginal = twin.events.at(-1);
    const refRejects = (event) => ref.replayPortable({ operationVersion: ref.PORTABLE_REPLAY_VERSION, events: [...legacy.slice(0, -1), event] }).status === "REJECTED";
    const mineRejects = (event) => replay([...twin.events.slice(0, -1), event]).status === "REJECTED";
    assert.equal(refRejects({ ...original, id: "duty-disposition:forged" }), true); assert.equal(mineRejects({ ...twinOriginal, id: "duty-disposition:forged" }), true);
    for (const patch of [{ purpose: "CONTEST" }, { evidenceIndexHash: digest("f").value }, { previousDispositionEventId: original.id }, { evaluationTime: 101 }, { attesterId: "replacement" }]) {
      const l = structuredClone(plain(original)); Object.assign(l.data.finding.challenge, patch);
      const m = structuredClone(plain(twinOriginal)); Object.assign(m.data.finding.challenge, patch);
      assert.equal(refRejects(l), true, `reference accepts ${JSON.stringify(patch)}`); assert.equal(mineRejects(m), true, `IronTrellis accepts ${JSON.stringify(patch)}`);
    }
  });
  await differential(t, "D11 an existing review or a report digest by itself does not complete the activated duty", async (d) => {
    await activated(d);
    await d.recorder().reviewDuty({ id: "review-only", duty: "duty", summaryDigest: digest("b").value });
    assert.equal(d.handle({ attester: "session" }).inspect("duty").policy.dutyDisposition, "OPEN"); d.checkpoint("review-only");
    await d.refuse("missing-finding-fields", disposeOp({ id: "missing-finding", duty: "duty", reportDigest: digest("b") }, { attester: "session" }));
  }, { policy: "E6" });
  await differential(t, "D12 role replacement alone keeps a completion historical; explicit A → B → A assignments make it need review", async (d) => {
    await activated(d); await d.handle({ attester: "session" }).dispose(completed);
    d.append("role-to-replacement", "ROLE_TRANSFERRED", { roleId: "role", fromAgentId: "worker", fromRoleTenureId: "tenure", toAgentId: "replacement", toRoleTenureId: "replacement-tenure", toTenureNumber: 2, principalId: "owner", transferKind: "REASSIGNMENT" });
    d.checkpoint("transferred");
    d.owner.admitRuntime({ agent: "replacement", session: "replacement-session", epoch: 1, key: "replacement-key", address: account.address, expiresAt: 1000 });
    const resource = `duty:${d.selection.descriptorHash}`;
    for (const [id, action] of [["new-finding", "ATTEST_DUTY_FINDING"], ["new-disposition", "RECORD_DUTY_DISPOSITION"]]) d.owner.grant({ id, to: "replacement", actions: [action], resources: [resource], expiresAt: 1000 });
    d.owner.grant({ id: "assign-new", to: "replacement", actions: ["ASSIGN_ATTEMPT_DUTY"], resources: ["job"], expiresAt: 1000 });
    await d.refuse("without-assignment", disposeOp({ ...completed, id: "without-assignment", attestationAuthority: "new-finding", dispositionAuthority: "new-disposition" }, { attester: "replacement-session", options: { session: "replacement-session" } }));
    await d.recorder({ session: "replacement-session" }).assignDuty({ id: "to-replacement", duty: "duty" });
    d.checkpoint("assigned-to-replacement");
    d.append("role-back-to-worker", "ROLE_TRANSFERRED", { roleId: "role", fromAgentId: "replacement", fromRoleTenureId: "replacement-tenure", toAgentId: "worker", toRoleTenureId: "return-tenure", toTenureNumber: 3, principalId: "owner", transferKind: "REASSIGNMENT" });
    await d.recorder().assignDuty({ id: "back-to-worker", duty: "duty" });
    d.checkpoint("assigned-back");
    const again = await d.handle({ attester: "session" }).dispose(completed);
    assert.equal(again.alreadyRecorded, true); assert.equal(again.view.dutyDisposition, "NEEDS_REVIEW");
  });
  await t.test("D13 a large escaped checklist: the reference's 8 KiB managed-profile envelope refuses it, format 2 (no fixed per-event envelope, SPEC C10) accepts it — a documented profile difference, not a rule divergence", async (t) => {
    const d = await legacyScenario(t); await activated(d);
    const input = mutable(completed);
    for (const key of KEYS) input.checklist[key].reason = "\\".repeat(256);
    input.disposition = "ESCALATED"; input.checklist.SOURCE_REVIEWED.state = "UNAVAILABLE"; input.nextStep = "\\".repeat(512);
    const before = d.log.calls.length;
    await assert.rejects(d.handle({ attester: "session" }).dispose(input)); assert.equal(d.log.calls.length, before, "the reference refuses before any callback");
    const twin = await twinOf(d.events, twinOwner());
    const dir = mkdtempSync(join(tmpdir(), "irontrellis-t5-large-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "history.jsonl"); await twinStore(path, twin.events, twin.owner);
    const handle = openLocalDutyPolicy({ historyFile: path, domain: twin.events[0].data.domain, owner: "owner", controller: "controller", now: () => 100, signer: twin.owner, session: "session", signHash: mySign }, { session: "session", signHash: mySign });
    const result = await handle.dispose(input);
    assert.equal(result.view.dutyDisposition, "ESCALATED");
  });
  await t.test("D14 the single-signature route refuses finding events before its callback on both engines (DUTY_WRITER_REQUIRED)", async (t) => {
    const d = await legacyScenario(t); await activated(d);
    let calls = 0;
    await assert.rejects(refCommit(d.f.store, { expectedDomain: d.f.options.domain, runtimeSessionId: "session", transition: { id: "wrong-writer", type: "ATTEMPT_DUTY_DISPOSITION_RECORDED", timestamp: 100, data: { dutyId: "duty" } } }, { signHash: async (h) => { calls++; return refSign(h); }, now: () => 100 }), (e) => e.code === "DUTY_WRITER_REQUIRED");
    const twin = await twinOf(d.events, twinOwner());
    const dir = mkdtempSync(join(tmpdir(), "irontrellis-t5-writer-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "history.jsonl"); await twinStore(path, twin.events, twin.owner);
    const { signedTransition } = await import("../src/runtime-writes.ts");
    const { configuration, openStore } = await import("../src/owner.ts");
    const config = configuration({ historyFile: path, domain: twin.events[0].data.domain, owner: "owner", controller: "controller", now: () => 100, signer: twin.owner });
    const store = openStore(config);
    await assert.rejects(signedTransition(store, config, "session", async (h) => { calls++; return mySign(h); }, "wrong-writer", "ATTEMPT_DUTY_DISPOSITION_RECORDED", { dutyId: "duty" }), (e) => e.code === "DUTY_WRITER_REQUIRED");
    store.close?.();
    assert.equal(calls, 0);
  });
  await differential(t, "D15 either signer phase refuses switching to another grant route after expiry", async (d) => {
    const resource = await activated(d);
    const template = d.events.find((e) => e.type === "AUTHORITY_GRANTED" && e.data.grant.authorityId === "finding").data.grant;
    d.append("branch-parent", "AUTHORITY_GRANTED", { grant: { ...template, authorityId: "branch-parent", rootAuthorityId: "branch-parent", granteeId: "replacement", constraints: { ...template.constraints, maxDelegationDepth: 1 } } });
    for (const [id, expiresAt] of [["branch-a", 101], ["branch-b", 1000]]) d.append(id, "AUTHORITY_GRANTED", { grant: { ...template, authorityId: id, rootAuthorityId: "branch-parent", parentAuthorityId: "branch-parent", grantorId: "replacement", constraints: { ...template.constraints, expiresAt, maxDelegationDepth: 0 } } });
    for (const phase of ["finding", "outer"]) {
      const change = { setTime: 101 };
      await d.refuse(phase, disposeOp({ ...completed, attestationAuthority: "branch-parent" }, { attester: "session", ...(phase === "finding" ? { finding: change } : { outer: change }) }));
      d.setTime(100);
    }
    assert.ok(resource);
  });
  await t.test("D16 the retained-evidence reader (frozen lib/*.mjs, a spawned child) reports completion then persistent contest; IronTrellis reports the same views on the twin", async (t) => {
    const d = await legacyScenario(t); await activated(d); await d.handle({ attester: "session" }).dispose(completed);
    const { runObservation } = await import(refPath("lib/reader-runner.mjs"));
    const { encode } = await import(refPath("lib/reader-contract.mjs"));
    const path = join(d.f.dir, "observed.json");
    const write = () => writeFileSync(path, encode(d.events));
    write();
    const source = { path, source: "duty-case", disclosure: "evidence", configHash: null };
    const completedReport = runObservation(source, "survives", { agent: "worker" });
    assert.ok(JSON.stringify(completedReport).includes("COMPLETED_UNDER_POLICY")); assert.ok(JSON.stringify(completedReport).includes("NOT_PROVEN"));
    let twin = await twinOf(d.events, twinOwner());
    assert.equal(core.observeHistory(twin.events).survives("worker").answer.attemptDuties[0].currentView.dutyDisposition, "COMPLETED_UNDER_POLICY");
    await d.handle({ attester: "session" }).contest(contestInput("reader-contest")); write();
    const contested = runObservation(source, "handover_report");
    assert.ok(JSON.stringify(contested).includes("CONTESTED")); assert.ok(JSON.stringify(contested).includes("duty-disposition:complete"));
    twin = await twinOf(d.events, twinOwner());
    const view = core.observeHistory(twin.events).survives("worker").answer.attemptDuties[0].currentView;
    assert.equal(view.dutyDisposition, "CONTESTED"); assert.equal(view.lastRecordedDisposition.eventId, "duty-disposition:complete");
    compareAnswers("D16 / contested", d.events, twin.events, 100);
  });
  await differential(t, "D17 a later signed outside report changes freshness but does not itself complete or contest the duty", async (d) => {
    await activated(d); await d.handle({ attester: "session" }).dispose(completed); d.checkpoint("completed");
    const identity = refStateOf(d.events).intentAdmissions.get("job").adapterIdentity;
    await d.recorder().observe({ id: "later-outside-report", intent: "job", acknowledgment: ref.createRemoteServiceReportAcknowledgment(identity, digest("d").value) });
    const after = d.handle({ attester: "session" }).inspect("duty").policy;
    assert.equal(after.dutyDisposition, "NEEDS_REVIEW"); assert.equal(after.policy.contestCount, 0);
    d.checkpoint("needs-review");
    const again = await d.handle({ attester: "session" }).dispose(completed);
    assert.equal(again.alreadyRecorded, true);
  });
  t.diagnostic(`answers compared: ${compared}, refusals re-attempted: ${refusalsCompared}`);
});

// ---------------------------------------------------------------- duty-workflow.test.mjs (3 cases: the protected-evidence investigation example)

test("T5: duty-workflow (reference-0.3 duty-workflow.test.mjs) — the frozen investigation example on the legacy case, its twin on IronTrellis; digest refusals are the host example's", async (t) => {
  await t.test("W1 local incident/report commitments (readDocumentDigest: a host file rule, no engine) — the frozen helper is used as it is", () => {
    const dir = mkdtempSync(join(tmpdir(), "irontrellis-t5-doc-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
    const file = join(dir, "report"); writeFileSync(file, "incident");
    const d = readDocumentDigest(file); assert.equal(readDocumentDigest(file, d).value, d.value);
    writeFileSync(file, "different"); assert.throws(() => readDocumentDigest(file, d), /DOCUMENT_DIGEST_MISMATCH/);
  });
  await t.test("W2+W3 the frozen `investigateDuty` drives the legacy case (activation, two completions around a later report, a contest); the twin reproduces every view; wrong bytes and a changing incident refuse on the example host", async (t) => {
    const d = await legacyScenario(t);
    const file = join(d.f.dir, "incident"); writeFileSync(file, "incident");
    // W2: wrong incident bytes cannot grant or activate.
    await assert.rejects(refInvestigate({ local: d.f.options, dutyId: "duty", sourceFile: file, sourceDigest: digest("0"), reportDirectory: d.f.dir, observeAgain: async () => {} }), /DOCUMENT_DIGEST_MISMATCH/);
    assert.equal(refStateOf(d.events).attemptDutyPolicies.size, 0);
    // The example itself (the eight steps on the legacy engine), with the later report recorded by the reference recorder.
    const identity = () => refStateOf(d.events).intentAdmissions.get("job").adapterIdentity;
    const observeAgain = async () => { await d.recorder().observe({ id: "later-service-report", intent: "job", acknowledgment: ref.createRemoteServiceReportAcknowledgment(identity(), digest("d").value) }); };
    const result = await refInvestigate({ local: d.f.options, dutyId: "duty", sourceFile: file, sourceDigest: readDocumentDigest(file), reportDirectory: d.f.dir, observeAgain });
    assert.equal(result.disposition, "CONTESTED"); assert.equal(result.signatures, 6, "three dual-signature operations (the activation signs through the plain options signer)");
    const legacy = d.events;
    assert.deepEqual(legacy.slice(-4).map((e) => e.type), ["ATTEMPT_DUTY_DISPOSITION_RECORDED", "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]);
    const twin = await twinOf(legacy, twinOwner());
    const views = [];
    for (let n = legacy.length - 5; n <= legacy.length; n += 1) {
      const { T } = compareAnswers(`W / prefix ${n}`, legacy.slice(0, n), twin.events.slice(0, n), 100);
      views.push(T.view?.dutyDisposition ?? null);
    }
    assert.deepEqual(views, ["OPEN", "OPEN", "COMPLETED_UNDER_POLICY", "NEEDS_REVIEW", "COMPLETED_UNDER_POLICY", "CONTESTED"]);
    // W3: an incident that changes while the finding signer yields cannot produce a completion (the example host's digest check in its signer).
    const e = await legacyScenario(t);
    const file2 = join(e.f.dir, "incident"); writeFileSync(file2, "incident");
    let calls = 0;
    const local = { ...e.f.options, signHash: async (hash) => { calls++; if (calls === 2) writeFileSync(file2, "changed during finding"); return refSign(hash); } };
    await assert.rejects(refInvestigate({ local, dutyId: "duty", sourceFile: file2, sourceDigest: readDocumentDigest(file2), reportDirectory: e.f.dir, observeAgain: async () => {} }), /DOCUMENT_DIGEST_MISMATCH/);
    assert.equal(calls, 2); assert.equal(e.events.some((ev) => ev.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED"), false);
    compareAnswers("W3 / activated-only", e.events, (await twinOf(e.events, twinOwner())).events, 100);
  });
  t.diagnostic(`answers compared: ${compared}, refusals re-attempted: ${refusalsCompared}`);
});

// ---------------------------------------------------------------- duty-capacity.test.mjs (8) and duty-disposition-capacity.test.mjs (7): the quota census

test("T5: duty quota (reference-0.3 duty-capacity + duty-disposition-capacity) — `dutyReservationOf` versus the format-2 capacity ledger, and the activation's six slots end to end", async (t) => {
  const activate = (dutyId = "duty", limits = {}) => ({ id: `activate:${dutyId}`, type: "ATTEMPT_DUTY_POLICY_ACTIVATED", timestamp: 100, data: { descriptor: { dutyId, ...limits } } });
  const disposition = (n, dutyId = "duty", status = "COMPLETED_UNDER_POLICY") => ({ id: `disposition:${dutyId}:${n}`, type: "ATTEMPT_DUTY_DISPOSITION_RECORDED", timestamp: 100, data: { dutyId, status } });
  const contest = (n, dutyId = "duty") => ({ id: `contest:${dutyId}:${n}`, type: "ATTEMPT_DUTY_CONTEST_RECORDED", timestamp: 100, data: { dutyId } });
  /** The format-2 ledger over a synthetic (census-only) event list: `accountCapacity` event by event. */
  const ledgerOf = (events) => { const r = newCapacityLedger(); for (const e of events) accountCapacity(r, e); return r; };
  const same = (events, label) => {
    const theirs = dutyReservationOf(events), mine = ledgerOf(events);
    assert.equal(mine.dutyReserved, theirs.dutyReserved, `${label}: dutyReserved`);
    assert.equal(mine.capacityDutyQuota.size, theirs.activatedDuties, `${label}: activated duties`);
    compared += 1;
    return theirs;
  };
  await t.test("DC1 four dispositions and two contests consume only their corresponding finite reservations", () => {
    const events = [activate()];
    assert.deepEqual(same(events, "activated"), { activatedDuties: 1, dutyReserved: 6, withinLimits: true });
    for (let n = 1; n <= 4; n++) { events.push(disposition(n)); assert.equal(same(events, `d${n}`).dutyReserved, 6 - n); }
    assert.equal(same([...events, disposition(5)], "fifth").dutyReserved, 2);
    for (let n = 1; n <= 2; n++) { events.push(contest(n)); assert.equal(same(events, `c${n}`).dutyReserved, 2 - n); }
    assert.equal(same([...events, contest(3)], "third").dutyReserved, 0);
    assert.equal(same([...events, disposition(5)], "fifth-after").dutyReserved, 0);
  });
  await t.test("DC2 contest exhaustion leaves all four disposition slots and never resets counters", () => {
    const events = [activate(), contest(1), contest(2)];
    assert.equal(same(events, "two-contests").dutyReserved, 4);
    assert.equal(same([...events, contest(3)], "third").dutyReserved, 4);
    for (let n = 1; n <= 4; n++) events.push(disposition(n, "duty", "ESCALATED"));
    assert.equal(same(events, "all").dutyReserved, 0);
    assert.equal(same([...events, activate()], "duplicate").dutyReserved, 0);
  });
  await t.test("DC3 completion preserves unused quota and every duty has independent reservations", () => {
    const events = [activate(), activate("other"), disposition(1)];
    assert.equal(same(events, "two-duties").dutyReserved, 11);
    events.push(disposition(2), disposition(3), disposition(4), contest(1), contest(2));
    assert.equal(same(events, "spent").dutyReserved, 6);
    assert.equal(same([...events, disposition(5)], "fifth").dutyReserved, 6);
    assert.equal(same([...events, disposition(1, "other")], "other").dutyReserved, 5);
  });
  await t.test("DC4 unselected duties and pre-activation candidates cannot consume another duty's reserve", () => {
    assert.equal(same([activate(), disposition(1, "unknown")], "unknown-d").dutyReserved, 6);
    assert.equal(same([activate(), contest(1, "unknown")], "unknown-c").dutyReserved, 6);
    assert.equal(same([disposition(1), activate()], "pre-activation").dutyReserved, 6);
    assert.equal(same([contest(1)], "no-activation").dutyReserved, 0);
  });
  await t.test("C1+DC5 the activation census adds six independent slots on a real E5 history and leaves the lifecycle and job census intact (descriptor limits never matter)", async (t) => {
    const d = await legacyScenario(t);
    const legacy = d.events, before = refCapacityOf(legacy), twin = await twinOf(legacy, twinOwner()), mine = capacityOf(twin.state);
    assert.equal(mine.lifecycleReserved, before.lifecycleReserved); assert.equal(mine.declaredJobs, before.declaredJobs); assert.equal(mine.dutyReserved, before.dutyReserved ?? 0);
    for (const limits of [{ dispositionLimit: 4, contestLimit: 2 }, { dispositionLimit: 0, contestLimit: 0 }, { dispositionLimit: 99, contestLimit: 99 }]) {
      const theirs = refCapacityOf([...legacy, activate("duty", limits)]), ledger = ledgerOf([...twin.events, activate("duty", limits)]);
      assert.equal(theirs.dutyReserved, 6); assert.equal(ledger.dutyReserved, 6); assert.equal(ledger.lifecycleReserved, theirs.lifecycleReserved);
    }
    assert.equal(ledgerOf([...twin.events, activate("duty"), activate("another")]).dutyReserved, refCapacityOf([...legacy, activate("duty"), activate("another")]).dutyReserved);
    assert.equal(ledgerOf([...twin.events, activate("duty"), activate("duty")]).dutyReserved, 6);
    const suffix = [activate(), disposition(1), contest(1)], after = refCapacityOf([...legacy, ...suffix]), ledger = ledgerOf([...twin.events, ...suffix]);
    assert.equal(after.dutyReserved, 4); assert.equal(ledger.dutyReserved, 4);
    for (const key of ["lifecycleReserved", "declaredJobs"]) assert.equal(after[key], before[key]);
    assert.equal(ledger.lifecycleReserved, before.lifecycleReserved);
  });
  await t.test("C4+DC7 a signed activation reserves six slots durably on both engines; the quota is spent by dispositions and never released (format 2: SPEC §5.2/§13.5 — control events are never refused by a declared capacity, unlike the managed profile's control reserve)", async (t) => {
    const d = await legacyScenario(t); d.grant(); await d.handle().activate(d.input);
    assert.equal(refCapacityOf(d.events).dutyReserved, 6);
    const twin = await twinOf(d.events, twinOwner());
    assert.equal(capacityOf(twin.state).dutyReserved, 6);
    // Format 2, declared maxEvents at exactly the committed space: a new job is CAPACITY_CONTROL_ONLY while a disposition within the quota is admitted and control events pass.
    const state = twin.state, maxEvents = state.events.length + capacityOf(state).lifecycleReserved + 6;
    const declared = { ...twin.events[0], data: { ...twin.events[0].data, capacity: { maxEvents } } };
    const capped = replay([declared, ...twin.events.slice(1)]);
    assert.equal(capped.status, "REJECTED", "the control events bind the genesis hash: re-declaring capacity needs a re-signed twin");
    const re = await transcribeLegacyToFormat2([{ ...d.events[0], data: { ...plain(d.events[0].data), capacity: { maxEvents } } }, ...d.events.slice(1)], { sign: mySign });
    const report = capacityOf(re.state);
    assert.equal(report.maxEvents, maxEvents); assert.equal(report.mode, "CONTROL_ONLY"); assert.equal(report.dutyReserved, 6); assert.equal(report.canDeclareJob, false);
    assert.equal(core.capacityVerdict(re.state, { id: "job:2", type: "TRANSACTION_INTENT_DECLARED", timestamp: 100, data: { intentId: "job:2" } }, 100)?.code, "CAPACITY_CONTROL_ONLY");
    assert.equal(core.capacityVerdict(re.state, disposition(1), 100), undefined, "a disposition within the quota is admitted at the limit");
    assert.equal(core.capacityVerdict(re.state, { id: "grant", type: "AUTHORITY_GRANTED", timestamp: 100, data: {} }, 100), undefined, "control events are always admitted (SPEC §5.2)");
  });
  await t.test("C2, C3, C5–C8, DC6: the managed profile's 96-event / 1,024-event / 6 MiB / segment projections (`hasAdministrativeRoom`, `projectHistoryUsage`, `assertCapacityTransition` of the legacy store) have no format-2 counterpart by design (SPEC §5.2, LEFT-OUT-SWEEP C10, D-rows); format 2 declares `capacity` per deployment and the control-event reserve (format2-capacity.test.mjs)", () => {
    assert.equal(core.LEGACY_CAPACITY_PROFILE.maxEvents, 96);
    assert.equal(core.CAPACITY_PROFILE, "irontrellis-capacity/1");
  });
  t.diagnostic(`answers compared: ${compared}, refusals re-attempted: ${refusalsCompared}`);
});

// ---------------------------------------------------------------- A-28: legacy histories carrying types 29–31 (the oracle writes them)

test("A-28: a legacy history the oracle wrote with types 29–31 is read by the legacy reader exactly as the oracle reads it (views, attempts, queries, evidence index, quota byte-equal, no projection); types 32–40 and format 1 stay refused", async (t) => {
  // The frozen investigation example on the reference engine: activation, two completions around a later report, a contest.
  const d = await legacyScenario(t);
  const file = join(d.f.dir, "incident"); writeFileSync(file, "incident");
  const identity = () => refStateOf(d.events).intentAdmissions.get("job").adapterIdentity;
  const observeAgain = async () => { await d.recorder().observe({ id: "later-service-report", intent: "job", acknowledgment: ref.createRemoteServiceReportAcknowledgment(identity(), digest("d").value) }); };
  const result = await refInvestigate({ local: d.f.options, dutyId: "duty", sourceFile: file, sourceDigest: readDocumentDigest(file), reportDirectory: d.f.dir, observeAgain });
  assert.equal(result.disposition, "CONTESTED");
  const legacy = d.events;
  assert.deepEqual(legacy.filter((e) => core.DUTY_POLICY_EVENT_TYPES.has(e.type)).map((e) => e.type), ["ATTEMPT_DUTY_POLICY_ACTIVATED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]);
  assert.equal(core.detectFormat(legacy), core.LEGACY_FORMAT);
  // Every prefix replays as the legacy format; the legacy hashes (keccak) and the legacy domain make the answers byte-equal without the projection.
  const encoded = (v) => canonicalEncode(plain(v));
  const views = [];
  for (let n = 1; n <= legacy.length; n += 1) {
    const prefix = legacy.slice(0, n), r = replay(prefix);
    assert.equal(r.status, "ACCEPTED", `legacy prefix ${n} (${legacy[n - 1].type}): ${r.code} ${r.reason}`);
    assert.equal(r.state.format, core.LEGACY_FORMAT);
    const rs = refStateOf(prefix);
    assert.equal(r.state.head.hash, rs.head.hash, `head at ${n}`);
    const view = inspectDutyPolicyState(r.state, "duty");
    assert.equal(encoded(view), encoded(inspectPortableDutyPolicy(rs, "duty") ?? null), `view at ${n}`);
    assert.equal(encoded(inspectAttemptHistory(prefix).attempts), encoded(refInspectAttempts(prefix).attempts), `attempts at ${n}`);
    if (rs.attemptDutyPolicies.has("duty")) assert.equal(encoded(core.deriveDutyEvidenceIndex(r.state, "duty")), encoded(derivePortableDutyEvidenceIndex(rs, "duty")), `evidence index at ${n}`);
    assert.equal(capacityOf(r.state).dutyReserved, refCapacityOf(prefix).dutyReserved ?? 0, `dutyReserved at ${n}`);
    if (n > legacy.length - 6) views.push(view?.dutyDisposition ?? null);
    compared += 4;
  }
  assert.deepEqual(views, ["OPEN", "OPEN", "COMPLETED_UNDER_POLICY", "NEEDS_REVIEW", "COMPLETED_UNDER_POLICY", "CONTESTED"]);
  // The extended queries on the whole legacy history, both engines on the same bytes.
  const L = referenceAnswers(legacy, 100), T = trellisAnswers(legacy, 100);
  for (const key of Object.keys(L)) { assert.equal(encoded(T[key]), encoded(L[key]), `${key} on the legacy history differs`); compared += 1; }
  // The §7.2 duty record (A-16: `status` as written) carries the activation and the dispositions on the legacy state too.
  const duty = core.deriveRecord(replay(legacy).state, "duty", "duty");
  assert.equal(duty.status, "OPEN"); assert.equal(duty.dispositions.length, 3); assert.equal(duty.policy.position, legacy.findIndex((e) => e.type === "ATTEMPT_DUTY_POLICY_ACTIVATED"));
  // The gate stays narrow: a legacy history refuses a type past 31 and a format-1 history refuses type 29 (schema-level, before any transition).
  const head = legacy.at(-1);
  const planted = (type) => ({ id: `planted:${type}`, type, timestamp: head.timestamp, data: {} });
  for (const type of ["BUDGET_DECLARED", "STATE_CHECKPOINT", "REQUEST_REFUSED", "EFFECT_RECORDED"]) {
    assert.equal(core.validateEvent(planted(type), core.LEGACY_FORMAT, legacy.length).code, "UNSUPPORTED_EVENT_TYPE", type);
    const r = replay([...legacy, planted(type)]); assert.equal(r.status, "REJECTED"); assert.equal(r.code, "UNSUPPORTED_EVENT_TYPE"); assert.equal(r.position, legacy.length);
  }
  for (const type of [...core.DUTY_POLICY_EVENT_TYPES]) {
    assert.equal(core.validateEvent(planted(type), core.TRELLIS_FORMAT, 1).code, "UNSUPPORTED_EVENT_TYPE", `${type} in format 1`);
    assert.notEqual(core.validateEvent(planted(type), core.LEGACY_FORMAT, 1).code, "UNSUPPORTED_EVENT_TYPE", `${type} in legacy is a schema question`);
  }
  t.diagnostic(`legacy prefixes read: ${legacy.length}; answers compared on the legacy bytes: ${legacy.length * 4 + Object.keys(L).length}`);
});
