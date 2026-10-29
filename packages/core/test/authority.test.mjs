/**
 * Authority engine tests: conformance vectors, differential parity against the
 * frozen Continuity core-0.2 reference, consequential bindings with real
 * signatures, the raw path evaluation, the signed transition validators and a
 * benchmark. Run with: node --test --experimental-strip-types test/authority.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

import { referenceCore as core, referenceCore02, fixturesRoot, vectorsPath } from "./reference.mjs";
import { loadFactor } from "./helpers/timing.mjs";
const refEngine = await referenceCore02("core/portable-authority-engine.ts");
const refReplay = await referenceCore02("core/portable-replay.ts");
const refCanonical = await referenceCore02("core/canonical.ts");
const A = await import("../src/authority.ts");
const E = await import("../src/authority-evidence.ts");
const suites = await import("../src/crypto/suites.ts");
const hashMod = await import("../src/hash.ts");
const newReplay = existsSync(new URL("../src/replay.ts", import.meta.url)) ? await import("../src/replay.ts") : undefined;

// ---------------------------------------------------------------- helpers

const revive = (_key, value) =>
  value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value;
const loadFixture = (name) => JSON.parse(readFileSync(`${fixturesRoot}${name}`, "utf8"), revive);
const handover = loadFixture("handover-history.json");
const handoverDenied = loadFixture("handover-denied-history.json");
const mandate = loadFixture("mandate-history.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"), revive);
const HISTORIES = { "first-look": handover, "no-review-power": handoverDenied, mandate, "mandate-quantitative-only": mandate.slice(0, 6) };

/** JSON normalisation: sorted keys, bigint markers, so deep equality ignores key order but not array order. */
const norm = (value) => {
  const walk = (v) => {
    if (typeof v === "bigint") return { "$continuity.bigint": v.toString() };
    if (Array.isArray(v)) return v.map(walk);
    if (v !== null && typeof v === "object") {
      const out = {};
      for (const key of Object.keys(v).sort()) if (v[key] !== undefined) out[key] = walk(v[key]);
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(value));
};
const same = (actual, expected, message) => assert.equal(norm(actual), norm(expected), message);

/** Replays with the reference kernel and adapts its state into the IronTrellis `ReplayState` shape. */
function referenceState(events) {
  const kernel = refReplay.createPortableReplayKernel();
  const outcome = refCanonical.captureBoundedCanonicalReplayBodyIncrementally(events, { events }, kernel.visit);
  if (outcome.status !== "CAPTURED") throw new Error(`capture ${outcome.status}`);
  const fin = kernel.finish();
  if (fin.status !== "ACCEPTED") throw new Error(`reference replay rejected: ${fin.result.code} at ${fin.result.eventPosition}`);
  return adaptReferenceState(fin.state);
}
function adaptReferenceState(ref) {
  const runtimeSessions = new Map();
  for (const [id, session] of ref.runtimeSessions) runtimeSessions.set(id, { ...session, credentialScheme: "eip191-personal-sign-keccak256" });
  const eventPositionsById = new Map(ref.events.map((e, i) => [e.id, i]));
  const successionRules = new Map();
  for (const [id, rule] of ref.successionRules) successionRules.set(id, { data: rule.data ?? rule });
  return {
    format: "continuity-event/0.2",
    hashAlgorithm: "keccak256",
    signatureScheme: "eip191-personal-sign-keccak256",
    events: ref.events,
    eventHistoryHashes: ref.eventHistoryHashes,
    eventPositionsById,
    head: ref.head,
    genesis: ref.genesis,
    principals: ref.principals,
    agents: ref.agents,
    reservedAgentIds: new Map(),
    roles: ref.roles,
    successionRules,
    tenures: ref.tenures,
    currentTenureIdsByAgent: new Map(),
    runtimeSessions,
    runtimeSessionIdsByAgent: new Map(),
    credentialKeyIds: new Set(),
    credentialAddressKeysByAgent: new Map(),
    intentDeclarations: ref.intentDeclarations,
    intentAdmissions: ref.intentAdmissions,
    intentConsumptions: ref.intentConsumptions,
    intentOutcomeStates: ref.intentOutcomeStates,
    outcomeObservations: ref.outcomeObservations,
    attemptDuties: ref.attemptDuties,
    attemptDutyReviews: ref.attemptDutyReviews,
    attemptDutyIdsBySourceIntent: new Map(),
    receiptCommitments: ref.receiptCommitments,
    obligations: ref.obligations,
    obligationIdsBySourceIntent: new Map(),
    nonceReservationsByActor: ref.nonceReservationsByActor,
    authorities: ref.authorities,
    recognizedRoots: ref.recognizedRoots,
    authorityUsage: ref.authorityUsage,
    anchors: [],
  };
}
/** A `replayFn` for `authorizePortable`, backed by the reference kernel. */
function referenceReplayFn(events) {
  const result = core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events });
  if (result.status !== "ACCEPTED") return { status: "REJECTED", code: result.code };
  const state = referenceState(events);
  return { status: "ACCEPTED", state, head: state.head, eventCount: state.events.length };
}
const replayFns = [["reference-kernel", referenceReplayFn], ...(newReplay ? [["irontrellis-replay", (events) => newReplay.replay(events)]] : [])];
const stateOf = (events, fn = replayFns[replayFns.length - 1][1]) => {
  const r = fn(events);
  if (r.status !== "ACCEPTED") throw new Error(`replay rejected ${r.code} ${r.reason ?? ""}`);
  return r.state;
};

/** Reference decision without a per-call replay: capture with no events, evaluate against a kernel state. */
function referenceAuthorize(refState, body) {
  const input = { operationVersion: core.PORTABLE_AUTHORIZATION_VERSION, ...body, events: [], authoritative: true };
  const captured = refEngine.capturePortableAuthorityOperation(input, "AUTHORIZE");
  if (captured.status !== "CAPTURED") return { status: captured.status };
  return refEngine.authorizeCapturedPortableState(captured.capture, refState);
}
function referenceRawState(events) {
  const kernel = refReplay.createPortableReplayKernel();
  refCanonical.captureBoundedCanonicalReplayBodyIncrementally(events, { events }, kernel.visit);
  return kernel.finish().state;
}
const headOf = (events) => referenceRawState(events).head;

const body = (events, { actor, action, resource, at, amount, consequential = false, binding, domain, policyVersion, head, claimedAt, termsCommitment }) => {
  const h = head ?? headOf(events);
  const time = at ?? h.canonicalTime;
  const request = { actorId: actor, action, resource, claimedAt: claimedAt ?? time };
  if (amount !== undefined) request.amount = amount;
  if (termsCommitment !== undefined) request.termsCommitment = termsCommitment;
  const genesis = events[0].data;
  return {
    expectedHistoryHead: h,
    domain: domain ?? genesis.domain,
    policyVersion: policyVersion ?? genesis.policyVersion,
    rootRecognitionPolicy: A.ROOT_RECOGNITION_POLICY,
    request,
    evaluationTime: time,
    consequential,
    ...(binding === undefined ? {} : { binding }),
  };
};

const DEV_KEY = suites.keyPairFromPrivateKey("eip191-personal-sign-keccak256", "dev-1001", `0x${(1001).toString(16).padStart(64, "0")}`);
const OTHER_KEY = suites.keyPairFromPrivateKey("eip191-personal-sign-keccak256", "dev-1002", `0x${(1002).toString(16).padStart(64, "0")}`);
const signChallenge = async (keyPair, state, b, algorithm = "keccak256") => {
  const challenge = A.createRuntimeAuthorizationChallenge({
    domain: b.domain,
    request: b.request,
    evaluationTime: b.evaluationTime,
    policyVersion: b.policyVersion,
    historyHead: state.head,
    binding: b.binding,
  });
  return suites.signHashWith(keyPair)(A.hashRuntimeAuthorizationChallenge(challenge, algorithm));
};

// ---------------------------------------------------------------- (1) conformance vectors

test("all 19 authorization vectors produce the expected projections", () => {
  const authorization = vectors.filter((v) => v.kind === "authorization");
  assert.equal(authorization.length, 19);
  for (const vector of authorization) {
    const events = HISTORIES[vector.history.ref];
    assert.ok(events, vector.id);
    for (const [name, replayFn] of replayFns) {
      const result = A.authorizePortable({ ...vector.input, events }, replayFn);
      const projection = {
        decision: result.decision,
        code: result.code ?? null,
        scopeAssurance: result.scopeAssurance ?? null,
        controllingAuthorityIds: result.proof?.controllingAuthorityIds ?? null,
        failureCodes: (result.failures ?? []).map((f) => f.code),
      };
      same(projection, vector.expect, `${vector.id} via ${name}`);
      // And the full result equals the reference engine's, not only the projection.
      same(result, core.authorizePortable({ ...vector.input, events }), `${vector.id} full parity via ${name}`);
    }
  }
});

test("the spec's real ALLOW example is reproduced field by field", () => {
  const state = stateOf(handover);
  const result = A.authorizeState(state, body(handover, { actor: "b:first-look", action: "record-review-progress", resource: "obligation:first-look" }));
  assert.equal(result.decision, "ALLOW");
  assert.deepEqual(Object.keys(result).sort(), ["consequential", "decision", "operationVersion", "proof", "scopeAssurance"]);
  same(result.proof.authorityEvidence, [{ authorityId: "progress-b-authority:first-look", grantEventId: "first-look:progress-b-authority", grantEventPosition: 12 }]);
  same(result.proof.historyHead, { canonicalTime: 25, hash: "0x4958d40342fc047d3fff0d3ab0f36e572ea28d9a1bb6dcbfbc1961c52231b779", position: 25 });
  same(result.proof.effectiveConstraints, { actions: ["record-review-progress"], expiresAt: 1000, maxDelegationDepth: 0, quantitative: false, requiredIntersectionIds: [], resources: ["obligation:first-look"] });
  same(result.proof.recognizedRoot, { principalId: "principal:first-look", principalRecognitionEventId: "first-look:principal", rootAuthorityId: "progress-b-authority:first-look", rootGrantEventId: "first-look:progress-b-authority" });
  assert.equal(result.proof.usageSnapshot.length, 0);
});

test("evidence is ordered by event id with the head appended (spec §6.4 REVOKED example)", () => {
  const state = stateOf(handoverDenied);
  const result = A.authorizeState(state, body(handoverDenied, { actor: "b:no-review-power", action: "record-review-progress", resource: "obligation:no-review-power" }));
  assert.equal(result.code, "REVOKED");
  assert.deepEqual(result.failures.map((f) => f.code), ["REVOKED", "ACTION_NOT_ALLOWED"]);
  assert.deepEqual(
    result.failures[0].evidence.map((e) => e.eventId),
    [
      "no-review-power:a", "no-review-power:admission", "no-review-power:b", "no-review-power:collect-authority", "no-review-power:genesis",
      "no-review-power:obligate-authority", "no-review-power:principal", "no-review-power:progress-a-authority", "no-review-power:progress-b-authority",
      "no-review-power:review-authority", "no-review-power:stale-declared", "no-review-power:terminated", "no-review-power:tutorial-revoke-a",
      "no-review-power:tutorial-revoke-b-review",
    ],
  );
  assert.equal(result.failures[0].evidence[10].position, 26);
  assert.equal(result.failures[0].evidence[10].historyHash, state.head.hash);
});

test("head pin, causal time and the simple denials", () => {
  const state = stateOf(handover);
  const ok = body(handover, { actor: "b:first-look", action: "record-review-progress", resource: "obligation:first-look" });
  const pinned = A.authorizeState(state, { ...ok, expectedHistoryHead: { ...ok.expectedHistoryHead, position: 24 } });
  assert.equal(pinned.code, "HISTORY_RELATION_UNVERIFIED");
  assert.equal(pinned.scopeAssurance, "SUPPLIED_SCOPE");
  assert.equal(pinned.failures[0].evidence[0].eventId, "first-look:stale-declared");
  const early = A.authorizeState(state, { ...ok, evaluationTime: 10 });
  assert.equal(early.code, "CAUSAL_TIME_INVALID");
  assert.equal(A.authorizeState(state, { ...ok, evaluationTime: "25" }).code, "CAUSAL_TIME_INVALID");
  const domain = A.authorizeState(state, { ...ok, domain: { ...ok.domain, chainId: "1" } });
  assert.equal(domain.code, "DOMAIN_MISMATCH");
  assert.equal(domain.failures[0].evidence[0].eventId, "first-look:genesis");
  assert.equal(A.authorizeState(state, { ...ok, domain: { ...ok.domain, verifyingContract: ok.domain.verifyingContract.toUpperCase().replace("0X", "0x") } }).decision, "ALLOW");
  assert.equal(A.authorizeState(state, { ...ok, policyVersion: "other-policy/9.9" }).code, "POLICY_MISMATCH");
  assert.equal(A.authorizeState(state, { ...ok, request: { ...ok.request, action: "" } }).code, "INVALID_REQUEST");
  assert.equal(A.authorizeState(state, { ...ok, request: { ...ok.request, action: "", amount: -1n } }).code, "INVALID_REQUEST");
  assert.equal(A.authorizeState(state, { ...ok, request: { ...ok.request, amount: -1n } }).code, "INVALID_AMOUNT");
  assert.equal(A.authorizeState(state, { ...ok, request: { ...ok.request, amount: 5 } }).code, "INVALID_AMOUNT");
  assert.equal(A.authorizeState(state, { ...ok, request: { ...ok.request, extra: 1 } }).code, "INVALID_INPUT");
  assert.equal(A.authorizeState(state, { ...ok, binding: { runtimeSessionId: "x", controlEpoch: 1, roleId: "r", roleTenureId: "t" } }).code, "INVALID_INPUT");
  const principal = A.authorizeState(state, { ...ok, request: { ...ok.request, actorId: "principal:first-look" } });
  assert.equal(principal.code, "AGENT_INACTIVE");
  assert.deepEqual(principal.failures[0].evidence.map((e) => e.eventId), ["first-look:stale-declared"]);
  const terminated = A.authorizeState(state, { ...ok, request: { ...ok.request, actorId: "a:first-look" } });
  assert.deepEqual(terminated.failures[0].evidence.map((e) => e.eventId), ["first-look:a", "first-look:stale-declared", "first-look:terminated"]);
});

test("authorizePortable façade: capture, structure and replay outcomes", () => {
  const ok = { operationVersion: A.AUTHORIZATION_VERSION, events: handover, authoritative: true, ...body(handover, { actor: "b:first-look", action: "record-review-progress", resource: "obligation:first-look" }) };
  const fn = replayFns[replayFns.length - 1][1];
  assert.equal(A.authorizePortable(ok, fn).decision, "ALLOW");
  assert.throws(() => A.authorizePortable(null, fn), TypeError);
  assert.throws(() => A.authorizePortable([], fn), TypeError);
  assert.throws(() => A.authorizePortable({ ...ok, [Symbol("s")]: 1 }, fn), TypeError);
  assert.equal(A.authorizePortable({ ...ok, operationVersion: "nope" }, fn).code, "UNSUPPORTED_VERSION");
  assert.equal(A.authorizePortable({ ...ok, extra: 1 }, fn).code, "INVALID_INPUT");
  assert.equal(A.authorizePortable({ ...ok, events: {} }, fn).code, "INVALID_INPUT");
  assert.equal(A.authorizePortable({ ...ok, events: [] }, fn).code, "STATE_NOT_AUTHORITATIVE");
  assert.equal(A.authorizePortable({ ...ok, events: handover.slice(1) }, fn).code, "STATE_NOT_AUTHORITATIVE");
  assert.equal(A.authorizePortable({ ...ok, events: [...handover, { ...handover[25], id: "x", type: "NOT_A_TYPE" }] }, fn).code, "UNSUPPORTED_VERSION");
  assert.equal(A.authorizePortable({ ...ok, consequential: true }, fn).code, "INVALID_INPUT");
  assert.equal(A.authorizePortable({ ...ok, request: { ...ok.request, action: "a".repeat(257) } }, fn).code, "INVALID_INPUT");
  assert.equal(A.authorizePortable({ ...ok, expectedHistoryHead: { ...ok.expectedHistoryHead, hash: ok.expectedHistoryHead.hash.toUpperCase().replace("0X", "0x") } }, fn).code, "INVALID_INPUT");
  assert.equal(A.authorizePortable({ ...ok, request: { ...ok.request, amount: undefined } }, fn).decision, "ALLOW");
  assert.equal(A.authorizePortable({ ...ok, events: [...handover.slice(0, 25), { ...handover[25], timestamp: 25.5 }] }, fn).code, "STATE_NOT_AUTHORITATIVE", "a malformed event is a state failure");
  assert.throws(() => A.authorizePortable({ ...ok, request: new (class R {})() }, fn), TypeError);
  // Structural INVALID_INPUT wins over a replay rejection.
  assert.equal(A.authorizePortable({ ...ok, events: [], consequential: true }, fn).code, "INVALID_INPUT");
});

// ---------------------------------------------------------------- (2) differential: generated corpora

function makeRng(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (min, max) => min + Math.floor(next() * (max - min + 1)),
    pick: (list) => list[Math.floor(next() * list.length)],
    subset(list, { min = 1, max = list.length } = {}) {
      const size = Math.max(min, Math.min(max, 1 + Math.floor(next() * list.length)));
      const chosen = [];
      const pool = [...list];
      for (let taken = 0; taken < size && pool.length > 0; taken += 1) chosen.push(pool.splice(Math.floor(next() * pool.length), 1)[0]);
      return chosen.sort();
    },
    bool: (p = 0.5) => next() < p,
  };
}
const GENESIS_VERSIONS = {
  administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2",
  authorizationProofVersion: "continuity-authorization-proof/0.2",
  eventSchemaVersion: "continuity-event/0.2",
  queryEnvelopeVersion: "continuity-query-envelope/0.2",
  receiptSchemaVersion: "continuity-receipt/0.2",
  runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2",
  signatureScheme: "eip191-personal-sign-keccak256",
};
const ACTION_POOL = ["read", "write", "review", "collect", "escalate", "archive"];
const RESOURCE_POOL = ["alpha", "beta", "gamma", "delta"];
const constraints = ({ actions, resources, expiresAt, maxDelegationDepth, requiredIntersectionIds = [], notBefore, quantitative = false, maxAmount, maxCumulativeAmount, maxTransactions }) => {
  const record = { actions: [...actions].sort(), expiresAt, maxDelegationDepth, quantitative, requiredIntersectionIds: [...requiredIntersectionIds].sort(), resources: [...resources].sort() };
  if (notBefore !== undefined) record.notBefore = notBefore;
  if (maxAmount !== undefined) record.maxAmount = maxAmount;
  if (maxCumulativeAmount !== undefined) record.maxCumulativeAmount = maxCumulativeAmount;
  if (maxTransactions !== undefined) record.maxTransactions = maxTransactions;
  return record;
};

/**
 * Port of tests/generators.mjs `generateHistory`, extended with quantitative
 * roots, dependent intersection partners, ROOT/GLOBAL prohibitions (some
 * anchored, some subject-bound), notBefore windows and prohibition revocations.
 */
function generateHistory(seed) {
  const rng = makeRng(seed);
  const id = `s${seed}`;
  const q = (name) => `${name}:${id}`;
  const domain = { chainId: "31337", deploymentId: `generated:${id}`, protocol: "continuity", verifyingContract: "0x0000000000000000000000000000000000003002", version: "0.2" };
  const policyVersion = `generated-policy:${id}/0.2`;
  const globalPolicySourceId = q("policy-source");
  const events = [];
  let clock = 0;
  const emit = (type, name, data) => { events.push({ data, id: q(name), timestamp: clock, type }); clock += 1; };
  emit("DEPLOYMENT_INITIALIZED", "genesis", {
    adapterPolicyHash: core.PORTABLE_ADAPTER_POLICY_HASH, canonicalLineageId: q("lineage"), domain, finality: "LOCAL_ONLY", globalPolicySourceId,
    policyVersion, rootRecognitionPolicy: A.ROOT_RECOGNITION_POLICY, timeSource: "EVENT_TIMESTAMP", versions: GENESIS_VERSIONS,
  });
  const principalId = q("principal");
  const controllerId = q("controller");
  emit("PRINCIPAL_CREATED", "principal", { principalId });
  const agents = [];
  for (let i = 0; i < rng.int(2, 4); i += 1) {
    agents.push(q(`agent${i}`));
    emit("AGENT_CREATED", `agent${i}`, { agentId: agents[i], controllerId, initialControlEpoch: 1, principalId });
  }
  const roleId = q("role");
  const successionRuleId = q("succession");
  emit("ROLE_CREATED", "role", { exclusive: true, principalId, roleId });
  emit("SUCCESSION_RULE_DECLARED", "succession", {
    permittedEventTypes: ["AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"],
    predecessorAgentId: agents[0], principalId, roleId, ruleId: successionRuleId, successorAgentId: agents[1], trigger: "AGENT_TERMINATED",
  });
  emit("AGENT_APPOINTED", "appointment", { agentId: agents[0], principalId, roleId, roleTenureId: q("tenure0"), successionRuleId, tenureNumber: 1 });
  const actions = rng.subset(ACTION_POOL, { min: 2 });
  const resources = rng.subset(RESOURCE_POOL, { min: 1 }).map(q);
  const EXPIRY = 10_000;
  const grants = [];
  const grant = (name, g) => { grants.push(g); emit("AUTHORITY_GRANTED", name, { grant: g }); return g; };

  const roots = [];
  for (let i = 0; i < rng.int(1, Math.min(3, agents.length)); i += 1) {
    const authorityId = q(`root${i}`);
    const quantitative = rng.bool(0.35);
    roots.push(grant(`root${i}`, {
      authorityId,
      constraints: constraints({
        actions: rng.subset(actions, { min: 1 }), resources: rng.subset(resources, { min: 1 }), expiresAt: EXPIRY, maxDelegationDepth: rng.int(1, 3),
        notBefore: rng.bool(0.3) ? rng.int(1, 50) : undefined, quantitative,
        maxAmount: quantitative ? BigInt(rng.int(10, 100)) : undefined,
        maxCumulativeAmount: quantitative && rng.bool(0.5) ? BigInt(rng.int(100, 300)) : undefined,
        maxTransactions: quantitative && rng.bool(0.5) ? rng.int(0, 3) : undefined,
      }),
      granteeId: agents[i % agents.length], grantorId: principalId, independent: true, kind: "PERMISSION", rootAuthorityId: authorityId,
    }));
  }
  const delegations = [];
  for (const parent of roots) {
    if (parent.constraints.maxDelegationDepth === 0 || !rng.bool(0.85)) continue;
    const granteeId = rng.pick(agents.filter((a) => a !== parent.granteeId));
    const p = parent.constraints;
    delegations.push(grant(`deleg${delegations.length}`, {
      authorityId: q(`deleg${delegations.length}`),
      constraints: constraints({
        actions: rng.subset(p.actions, { min: 1 }), resources: rng.subset(p.resources, { min: 1 }),
        expiresAt: rng.bool(0.5) ? p.expiresAt : p.expiresAt - 100, maxDelegationDepth: Math.max(0, p.maxDelegationDepth - 1),
        requiredIntersectionIds: p.requiredIntersectionIds, notBefore: p.notBefore === undefined ? (rng.bool(0.2) ? 20 : undefined) : p.notBefore + rng.int(0, 10),
        quantitative: p.quantitative, maxAmount: p.maxAmount === undefined ? undefined : p.maxAmount - BigInt(rng.int(0, 5)),
        maxCumulativeAmount: p.maxCumulativeAmount, maxTransactions: p.maxTransactions,
      }),
      granteeId, grantorId: parent.granteeId, independent: true, kind: "PERMISSION", parentAuthorityId: parent.authorityId, rootAuthorityId: parent.rootAuthorityId,
    }));
  }
  // Intersections: an independent partner (never satisfies, spec trap 2) or a dependent one (satisfies when held by the same actor).
  let gatedAction;
  if (rng.bool(0.6)) {
    const holder = roots[0].granteeId;
    const partnerId = q("partner");
    const dependent = rng.bool(0.6);
    const partnerHolder = dependent && rng.bool(0.3) ? rng.pick(agents.filter((a) => a !== holder)) : holder;
    grant("partner", {
      authorityId: partnerId, constraints: constraints({ actions: rng.subset(actions, { min: 1 }), resources: [...resources], expiresAt: rng.bool(0.3) ? 9990 : EXPIRY, maxDelegationDepth: 0 }),
      granteeId: partnerHolder, grantorId: principalId, independent: !dependent, kind: "PERMISSION", rootAuthorityId: partnerId,
    });
    gatedAction = `gate-only-${id}`;
    const gatedId = q("gated");
    grant("gated", {
      authorityId: gatedId, constraints: constraints({ actions: [gatedAction], resources: [...resources], expiresAt: EXPIRY, maxDelegationDepth: 0, requiredIntersectionIds: [partnerId] }),
      granteeId: holder, grantorId: principalId, independent: true, kind: "PERMISSION", rootAuthorityId: gatedId,
    });
  }
  // Prohibitions: ROOT ones attenuate against the root (or an anchoring delegation), GLOBAL ones come from the policy source.
  const prohibitions = [];
  const prohibitionConstraints = (parent, rng) => {
    const p = parent.constraints;
    return constraints({
      actions: rng.subset(p.actions, { min: 1 }), resources: rng.subset(p.resources, { min: 1 }), expiresAt: rng.bool(0.3) ? p.expiresAt - 50 : p.expiresAt,
      maxDelegationDepth: 0, notBefore: p.notBefore === undefined ? undefined : p.notBefore, quantitative: p.quantitative,
      maxAmount: p.quantitative ? (rng.bool(0.5) ? p.maxAmount : p.maxAmount - 5n) : undefined,
      maxCumulativeAmount: p.maxCumulativeAmount === undefined ? undefined : p.maxCumulativeAmount, maxTransactions: p.maxTransactions === undefined ? undefined : p.maxTransactions,
    });
  };
  for (const root of roots) {
    if (!rng.bool(0.5)) continue;
    const anchor = rng.bool(0.4) ? delegations.find((d) => d.parentAuthorityId === root.authorityId && d.constraints.maxDelegationDepth >= 1) : undefined;
    const c = prohibitionConstraints(anchor ?? root, rng);
    if (c.maxCumulativeAmount !== undefined || c.maxTransactions !== undefined) continue; // prohibitions may not carry those caps
    const authorityId = q(`prohibit${prohibitions.length}`);
    const p = {
      authorityId, constraints: c, grantorId: anchor === undefined ? principalId : anchor.granteeId, kind: "PROHIBITION", rootAuthorityId: root.authorityId, scope: "ROOT",
      ...(anchor === undefined ? {} : { parentAuthorityId: anchor.authorityId }),
      ...(rng.bool(0.5) ? { subjectActorId: rng.pick(agents) } : {}),
    };
    prohibitions.push(p);
    grant(`prohibit${prohibitions.length - 1}`, p);
  }
  if (rng.bool(0.4)) {
    const authorityId = q("global");
    const quantitative = rng.bool(0.3);
    const p = {
      authorityId, constraints: constraints({ actions: rng.subset(actions, { min: 1 }), resources: rng.subset(resources, { min: 1 }), expiresAt: rng.bool(0.3) ? 9000 : EXPIRY, maxDelegationDepth: 0, quantitative, maxAmount: quantitative ? 50n : undefined, notBefore: rng.bool(0.3) ? 30 : undefined }),
      grantorId: globalPolicySourceId, kind: "PROHIBITION", scope: "GLOBAL", ...(rng.bool(0.5) ? { subjectActorId: rng.pick(agents) } : {}),
    };
    prohibitions.push(p);
    grant("global", p);
  }
  if (rng.bool(0.5)) {
    emit("CONTROL_EPOCH_ADVANCED", "epoch", { agentId: agents[0], controllerId, fromEpoch: 1, toEpoch: 2 });
    emit("AGENT_TERMINATED", "terminate", { agentId: agents[0], principalId, roleId, roleTenureId: q("tenure0"), successionRuleId });
    emit("ROLE_TRANSFERRED", "transfer", { fromAgentId: agents[0], fromRoleTenureId: q("tenure0"), principalId, roleId, successionRuleId, toAgentId: agents[1], toRoleTenureId: q("tenure1"), toTenureNumber: 2, transferKind: "SUCCESSION" });
  }
  let revoked = 0;
  for (const g of grants) {
    if (!rng.bool(0.3)) continue;
    const revokerId = g.kind === "PROHIBITION" && g.scope === "GLOBAL" ? globalPolicySourceId : g.parentAuthorityId === undefined ? principalId : g.grantorId;
    revoked += 1;
    emit("AUTHORITY_REVOKED", `revoke${revoked}`, { authorityId: g.authorityId, revokerId });
  }
  return { seed, events, domain, policyVersion, agents, actions: gatedAction === undefined ? actions : [...actions, gatedAction], resources, grants, rng };
}

/** A bounded, seeded request grid: actor × action × resource × amount × evaluation time. */
function requestGrid(history, { cap = 30 } = {}) {
  const combos = [];
  for (const actor of [...history.agents, "ghost", `${history.agents[0]}`]) for (const action of history.actions) for (const resource of [...history.resources, "unknown"]) combos.push({ actor, action, resource });
  const rng = makeRng(history.seed * 7919);
  const chosen = [];
  while (chosen.length < Math.min(cap, combos.length)) chosen.push(combos.splice(Math.floor(rng.next() * combos.length), 1)[0]);
  const head = headOf(history.events).canonicalTime;
  const grid = [];
  for (const c of chosen) {
    for (const amount of [undefined, 5n, 60n, 500n]) {
      for (const at of [head, head + 40, 9960, 10_000]) grid.push({ ...c, amount, at });
    }
  }
  return grid;
}

let compared = 0;
function compareHistory(events, requests, label) {
  const refState = referenceRawState(events);
  const state = adaptReferenceState(refState);
  const states = [["adapted", state], ...(newReplay ? [["irontrellis-replay", stateOf(events)]] : [])];
  for (const request of requests) {
    const b = body(events, { ...request, head: state.head });
    const expected = referenceAuthorize(refState, b);
    for (const [name, s] of states) {
      const actual = A.authorizeState(s, b);
      if (norm(actual) !== norm(expected)) {
        assert.fail(`${label} ${name} ${JSON.stringify(request, (k, v) => (typeof v === "bigint" ? v.toString() : v))}\n  actual   ${norm(actual)}\n  expected ${norm(expected)}`);
      }
      compared += 1;
    }
  }
}

test("differential: fixture histories against the reference engine", () => {
  for (const [name, events] of Object.entries(HISTORIES)) {
    const agents = [...referenceRawState(events).agents.keys()];
    const grants = [...referenceRawState(events).authorities.values()].map((r) => r.grant);
    const actions = [...new Set(grants.flatMap((g) => g.constraints.actions)), "delete-everything"];
    const resources = [...new Set(grants.flatMap((g) => g.constraints.resources)), "other"];
    const head = headOf(events).canonicalTime;
    const requests = [];
    for (const actor of [...agents, "ghost", "principal:first-look"]) for (const action of actions) for (const resource of resources) for (const amount of [undefined, 0n, 400n, 2500n, 2501n]) for (const at of [head, 999, 1000, 5000]) requests.push({ actor, action, resource, amount, at });
    compareHistory(events, requests, name);
  }
  assert.ok(compared > 1000);
});

test("differential: generated corpora seeds 1..40 (delegation, intersections, prohibitions, revocation, windows, quantities, terminations)", () => {
  const before = compared;
  let prohibitions = 0;
  let dependent = 0;
  for (let seed = 1; seed <= 40; seed += 1) {
    const history = generateHistory(seed);
    const replayed = core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events: history.events });
    assert.equal(replayed.status, "ACCEPTED", `seed ${seed} must replay: ${replayed.code} at ${replayed.eventPosition}`);
    prohibitions += history.grants.filter((g) => g.kind === "PROHIBITION").length;
    dependent += history.grants.filter((g) => g.independent === false).length;
    compareHistory(history.events, requestGrid(history), `seed ${seed}`);
    // Every prefix of the history is itself a valid history: the last few prefixes exercise pre-revocation states.
    for (const cut of [history.events.length - 1, history.events.length - 3]) {
      if (cut > 8) compareHistory(history.events.slice(0, cut), requestGrid(history, { cap: 6 }), `seed ${seed} prefix ${cut}`);
    }
  }
  assert.ok(prohibitions > 10 && dependent > 3, "the corpus must include prohibitions and dependent partners");
  console.log(`differential comparisons so far: ${compared} (${compared - before} on generated corpora)`);
});

test("differential: one mutable state grown event by event (incremental memo) matches fresh reference states", { skip: newReplay === undefined }, () => {
  let grown = 0;
  for (let seed = 1; seed <= 40; seed += 1) {
    const history = generateHistory(seed);
    const state = newReplay.createReplayState("continuity-event/0.2");
    const grid = requestGrid(history, { cap: 4 }).filter((r) => r.at === 10_000 || r.amount === 5n);
    for (let i = 0; i < history.events.length; i += 1) {
      const applied = newReplay.applyEvent(state, history.events[i]);
      assert.ok(applied.ok, `seed ${seed} event ${i}: ${applied.reason}`);
      if (i < 8) continue;
      const events = history.events.slice(0, i + 1);
      const refState = referenceRawState(events);
      for (const request of grid) {
        const b = body(events, { ...request, head: state.head, at: Math.max(request.at, state.head.canonicalTime) });
        same(A.authorizeState(state, b), referenceAuthorize(refState, b), `seed ${seed} after event ${i} ${history.events[i].type}`);
        grown += 1;
      }
    }
  }
  compared += grown;
  console.log(`incremental comparisons: ${grown}`);
});

test("differential: decisions listed as spec traps", () => {
  const state = stateOf(mandate);
  const refState = referenceRawState(mandate);
  const b = body(mandate, { actor: "buyer:mandate", action: "purchase", resource: "plush:mandate", amount: 2501n });
  const result = A.authorizeState(state, b);
  assert.equal(result.code, "ACTION_NOT_ALLOWED");
  assert.deepEqual(result.failures.map((f) => [f.code, f.terminalAuthorityId]), [["ACTION_NOT_ALLOWED", "report-authority:mandate"], ["AMOUNT_EXCEEDED", "mandate-authority:mandate"]]);
  same(result, referenceAuthorize(refState, b));
  const delegated = A.authorizeState(state, body(mandate, { actor: "researcher:mandate", action: "purchase", resource: "plush:mandate", amount: 400n }));
  assert.deepEqual(delegated.proof.controllingAuthorityIds, ["mandate-authority:mandate", "research-authority:mandate"]);
  same(delegated.proof.usageSnapshot, [
    { authorityId: "mandate-authority:mandate", admittedTransactionCount: 0, admittedCumulativeAmount: 0n },
    { authorityId: "research-authority:mandate", admittedTransactionCount: 0, admittedCumulativeAmount: 0n },
  ]);
  assert.equal(delegated.proof.effectiveConstraints.maxAmount, 500n);
});

// ---------------------------------------------------------------- (3) consequential bindings with real signatures

const PREFIX = handover.slice(0, 14); // through the declaration; head 13, the admission in the fixture was evaluated at 14
const FIXTURE_PROOF = handover[14].data.authorizationProof;
const BINDING = Object.freeze({
  runtimeSessionId: "session:first-look:a", credentialKeyId: "key:first-look:a", controlEpoch: 1, roleId: "role:first-look", roleTenureId: "tenure-a:first-look",
  intentId: "intent:first-look", nonce: FIXTURE_PROOF.nonce,
});
const consequentialBody = (events, at, request, binding, extra = {}) => body(events, { ...request, at, consequential: true, binding, ...extra });
const REQUEST = { actor: "a:first-look", action: "collect-evidence-packet", resource: "resource:first-look", claimedAt: FIXTURE_PROOF.request.claimedAt, termsCommitment: FIXTURE_PROOF.request.termsCommitment };

async function signed(events, at, request = REQUEST, binding = BINDING, key = DEV_KEY, extra = {}) {
  const state = stateOf(events);
  const unsigned = consequentialBody(events, at, request, binding, extra);
  // Without intent and nonce there is no challenge to sign; any well-formed signature is accepted unverified (spec §4 step 8.5).
  const runtimeSignature = binding.intentId === undefined || binding.nonce === undefined ? await suites.signHashWith(key)(`0x${"11".repeat(32)}`) : await signChallenge(key, state, unsigned);
  return { state, body: consequentialBody(events, at, request, { ...binding, runtimeSignature }, extra) };
}
const expectParity = (events, b, code) => {
  const state = stateOf(events);
  const result = A.authorizeState(state, b);
  assert.equal(result.decision === "ALLOW" ? "ALLOW" : result.code, code, JSON.stringify(result.failures ?? result.proof?.controllingAuthorityIds));
  same(result, core.authorizePortable({ operationVersion: A.AUTHORIZATION_VERSION, events, authoritative: true, ...b }), `reference parity for ${code}`);
  return result;
};

test("the fixture admission's challenge hash and signature are reproduced", () => {
  const state = stateOf(PREFIX);
  const challenge = A.createRuntimeAuthorizationChallenge({
    domain: FIXTURE_PROOF.domain, request: FIXTURE_PROOF.request, evaluationTime: 14, policyVersion: FIXTURE_PROOF.policyVersion, historyHead: state.head, binding: BINDING,
  });
  assert.deepEqual(Object.keys(challenge), [
    "version", "domain", "request", "authoritative", "consequential", "evaluationTime", "policyVersion", "rootRecognitionPolicy", "eventHistoryHash", "eventHistoryPosition",
    "runtimeSessionId", "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "intentId", "nonce",
  ]);
  assert.equal(A.hashRuntimeAuthorizationChallenge(challenge, "keccak256"), "0x0228e1f0314bf3d39ea8560262593403f938729a01e8f7946c0e92719916d72f");
  assert.equal(A.hashRuntimeAuthorizationChallenge(challenge, "keccak256"), handover[14].data.runtimeAuthorizationHash);
  assert.equal(A.hashRuntimeAuthorizationChallenge(challenge, "keccak256"), core.hashPortableRuntimeAuthorizationChallenge(core.createPortableRuntimeAuthorizationChallenge({ domain: FIXTURE_PROOF.domain, request: FIXTURE_PROOF.request, evaluationTime: 14, policyVersion: FIXTURE_PROOF.policyVersion, historyHead: state.head, binding: BINDING })));
  assert.ok(A.verifyRuntimeAuthorizationSignature(state.runtimeSessions.get("session:first-look:a"), challenge, handover[14].data.runtimeSignature, "keccak256"));
  assert.ok(!A.verifyRuntimeAuthorizationSignature(state.runtimeSessions.get("session:first-look:a"), challenge, handover[14].data.runtimeSignature, "sha256"));
  assert.throws(() => A.createRuntimeAuthorizationChallenge({ domain: FIXTURE_PROOF.domain, request: FIXTURE_PROOF.request, evaluationTime: 14, policyVersion: "p", historyHead: state.head, binding: { ...BINDING, nonce: undefined } }), TypeError);
});

test("consequential ALLOW reproduces the fixture's stored proof and every SESSION_/INTENT_/NONCE code", async () => {
  const { state, body: ok } = await signed(PREFIX, 14);
  const allow = expectParity(PREFIX, ok, "ALLOW");
  assert.equal(allow.consequential, true);
  same(allow.proof, FIXTURE_PROOF);
  assert.equal(ok.binding.runtimeSignature, handover[14].data.runtimeSignature);

  const rebind = (patch) => ({ ...ok, binding: { ...ok.binding, ...patch } });
  expectParity(PREFIX, rebind({ runtimeSessionId: "session:nope" }), "SESSION_NOT_FOUND");
  expectParity(PREFIX, rebind({ credentialKeyId: undefined }), "SESSION_CREDENTIAL_REQUIRED");
  expectParity(PREFIX, rebind({ runtimeSignature: undefined }), "SESSION_CREDENTIAL_REQUIRED");
  expectParity(PREFIX, rebind({ credentialKeyId: "key:wrong" }), "SESSION_CREDENTIAL_INVALID");
  const wrongKey = await signed(PREFIX, 14, REQUEST, BINDING, OTHER_KEY);
  expectParity(PREFIX, wrongKey.body, "SESSION_CREDENTIAL_INVALID");
  const flipped = ok.binding.runtimeSignature.slice(0, 130) + (ok.binding.runtimeSignature.endsWith("1b") ? "1c" : "1b");
  expectParity(PREFIX, rebind({ runtimeSignature: flipped }), "SESSION_CREDENTIAL_INVALID");
  expectParity(PREFIX, { ...ok, request: { ...ok.request, claimedAt: 14 } }, "SESSION_CREDENTIAL_INVALID"); // claimedAt is bound by the challenge
  expectParity(PREFIX, rebind({ controlEpoch: 2 }), "SESSION_CREDENTIAL_INVALID"); // the epoch is bound by the challenge
  const staleEpoch = await signed(PREFIX, 14, REQUEST, { ...BINDING, controlEpoch: 2 });
  expectParity(PREFIX, staleEpoch.body, "STALE_EPOCH");
  // Session expiry: expiresAt 10000 is exclusive and checked before the credential.
  const late = await signed(PREFIX, 10_000);
  expectParity(PREFIX, late.body, "SESSION_EXPIRED");
  const justBefore = await signed(PREFIX, 9_999);
  assert.equal(A.authorizeState(justBefore.state, justBefore.body).code, "EXPIRED");
  // Role tenure: wrong tenure id is signed correctly but not current; the signature is verified before the tenure.
  const tenure = await signed(PREFIX, 14, REQUEST, { ...BINDING, roleTenureId: "tenure-b:first-look" });
  const tenureResult = expectParity(PREFIX, tenure.body, "ROLE_TENURE_NOT_CURRENT");
  assert.deepEqual(tenureResult.failures[0].evidence.map((e) => e.eventId), ["first-look:appointment", "first-look:declared", "first-look:role"]);
  // Intent: absent (signature not verified at all), undeclared, mismatching, replayed, nonce reused.
  expectParity(PREFIX, rebind({ intentId: undefined, nonce: undefined, runtimeSignature: wrongKey.body.binding.runtimeSignature }), "INTENT_REQUIRED");
  const undeclared = await signed(PREFIX, 14, REQUEST, { ...BINDING, intentId: "intent:unknown" });
  expectParity(PREFIX, undeclared.body, "INTENT_NOT_DECLARED");
  const mismatch = await signed(PREFIX, 14, { ...REQUEST, resource: "resource:other" });
  expectParity(PREFIX, mismatch.body, "INTENT_MISMATCH");
  const withAmount = await signed(PREFIX, 14, { ...REQUEST, amount: 1n });
  expectParity(PREFIX, withAmount.body, "INTENT_MISMATCH");
  const admitted = handover.slice(0, 15);
  const replayed = await signed(admitted, 15);
  expectParity(admitted, replayed.body, "INTENT_REPLAY");
  // A fresh intent reusing the reserved nonce wins the algebra and is then denied.
  const reused = [...admitted, { ...handover[13], id: "first-look:redeclared", timestamp: 15, data: { ...handover[13].data, intentId: "intent:second" } }];
  assert.equal(core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events: reused }).status, "ACCEPTED");
  const nonce = await signed(reused, 15, REQUEST, { ...BINDING, intentId: "intent:second" });
  const nonceResult = expectParity(reused, nonce.body, "NONCE_ALREADY_ADMITTED");
  assert.equal(nonceResult.failures[0].subjectId, BINDING.nonce);
  // Fenced: the agent's epoch advanced past the session's (prefix through the epoch advance, before termination).
  const fencedEvents = handover.slice(0, 20);
  const fenced = await signed(fencedEvents, 19, REQUEST, { ...BINDING, intentId: undefined, nonce: undefined });
  expectParity(fencedEvents, fenced.body, "SESSION_FENCED");
  const fencedNewEpoch = await signed(fencedEvents, 19, REQUEST, { ...BINDING, controlEpoch: 2, intentId: undefined, nonce: undefined });
  expectParity(fencedEvents, fencedNewEpoch.body, "SESSION_FENCED");
  // Structural: a malformed signature is INVALID_INPUT, not a credential failure.
  assert.equal(A.authorizeState(state, rebind({ runtimeSignature: ok.binding.runtimeSignature.slice(0, 130) + "00" })).code, "INVALID_INPUT");
  assert.equal(A.authorizeState(state, rebind({ runtimeSignature: ok.binding.runtimeSignature.toUpperCase().replace("0X", "0x") })).code, "INVALID_INPUT");
});

test("format-1 hooks: sha256 challenge hashing and per-session ed25519 verification", async () => {
  const legacy = stateOf(PREFIX);
  const ed = suites.generateKeyPair("ed25519", "ed-a");
  const session = { ...legacy.runtimeSessions.get("session:first-look:a"), credentialScheme: "ed25519", credentialAddressKey: ed.credential };
  const trellisDomain = { protocol: "irontrellis", version: "1", deploymentId: "trellis:first-look" };
  const state = { ...legacy, format: "irontrellis-event/1", hashAlgorithm: "sha256", signatureScheme: "ed25519", genesis: { ...legacy.genesis, domain: trellisDomain }, runtimeSessions: new Map([["session:first-look:a", session]]) };
  const unsigned = consequentialBody(PREFIX, 14, REQUEST, BINDING, { domain: trellisDomain });
  const runtimeSignature = await signChallenge(ed, state, unsigned, "sha256");
  assert.equal(runtimeSignature.length, 130);
  const ok = { ...unsigned, binding: { ...BINDING, runtimeSignature } };
  assert.equal(A.authorizeState(state, ok).decision, "ALLOW");
  const keccakSigned = await signChallenge(ed, state, unsigned, "keccak256");
  assert.equal(A.authorizeState(state, { ...unsigned, binding: { ...BINDING, runtimeSignature: keccakSigned } }).code, "SESSION_CREDENTIAL_INVALID");
  assert.equal(A.authorizeState(legacy, { ...ok, domain: legacy.genesis.domain }).code, "INVALID_INPUT", "a 64-byte signature is not a legacy Signature65");
  assert.equal(A.authorizeState(state, { ...ok, domain: { ...trellisDomain, deploymentId: "other" } }).code, "DOMAIN_MISMATCH");
  assert.equal(A.authorizeState(state, { ...ok, domain: legacy.genesis.domain }).code, "INVALID_INPUT", "a legacy domain is not a format-1 domain");
  const allow = A.authorizeState(state, ok);
  same(allow.proof.domain, trellisDomain);
  assert.equal(allow.proof.intentId, "intent:first-look");
});

// ---------------------------------------------------------------- (4) evaluateAuthorityPath (raw path)

const RAW_HEAD = { hash: `0x${"ab".repeat(32)}`, position: 7, canonicalTime: 100 };
const rawScope = (extra = {}) => ({
  domain: { protocol: "continuity", version: "0.2", deploymentId: "exp", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000003002" },
  policyVersion: "exp-policy/0.2", rootRecognitionPolicy: A.ROOT_RECOGNITION_POLICY, historyHead: RAW_HEAD, evaluationTime: 100,
  recognizedRoots: [{ rootAuthorityId: "root", principalId: "P", principalRecognitionEventId: "ev-p", rootGrantEventId: "ev-root" }], globalPolicySourceId: "policy", ...extra,
});
const rawRoot = (extra = {}) => ({
  kind: "PERMISSION", authorityId: "root", grantorId: "P", granteeId: "A", rootAuthorityId: "root", independent: true,
  constraints: { actions: ["write", "read"], resources: ["r1"], quantitative: false, maxDelegationDepth: 1, requiredIntersectionIds: [] }, ...extra,
});
const rawInput = (extra = {}) => ({
  operationVersion: A.AUTHORITY_EVALUATION_VERSION, scope: rawScope(), request: { actorId: "A", action: "read", resource: "r1", claimedAt: 100 },
  permissions: [rawRoot()], prohibitions: [], authorityEvidence: [{ authorityId: "root", grantEventId: "ev-root", grantEventPosition: 3 }], revokedAuthorityIds: [], usage: [], ...extra,
});
const rawParity = (input, code) => {
  const result = A.evaluateAuthorityPath(input);
  assert.equal(result.decision === "ALLOW" ? "ALLOW" : result.code, code, norm(result));
  same(result, core.evaluatePortableAuthorityPath(input), `raw parity ${code}`);
  return result;
};

test("evaluateAuthorityPath: the spec's raw ALLOW and the structural / delegation outcomes", () => {
  const allow = rawParity(rawInput(), "ALLOW");
  assert.equal(allow.scopeAssurance, "SUPPLIED_SCOPE");
  assert.deepEqual(allow.proof.effectiveConstraints.actions, ["read", "write"]);
  assert.deepEqual(allow.proof.permissionPath[0].constraints.actions, ["read", "write"]);
  same(allow.proof.authorityEvidence, [{ authorityId: "root", grantEventId: "ev-root", grantEventPosition: 3 }]);
  rawParity(rawInput({ scope: rawScope({ rootRecognitionPolicy: "other/1" }) }), "POLICY_MISMATCH");
  rawParity(rawInput({ scope: rawScope({ evaluationTime: 99 }) }), "CAUSAL_TIME_INVALID");
  rawParity(rawInput({ scope: rawScope({ evaluationTime: "100" }) }), "CAUSAL_TIME_INVALID");
  rawParity(rawInput({ request: { actorId: "A", action: "read", resource: "r1", claimedAt: 100, amount: 5 } }), "INVALID_AMOUNT");
  rawParity(rawInput({ request: { actorId: "", action: "read", resource: "r1", claimedAt: 100 } }), "INVALID_REQUEST");
  rawParity(rawInput({ request: { actorId: "A", action: "read", resource: "r1" } }), "INVALID_INPUT");
  rawParity({ ...rawInput(), binding: {} }, "INVALID_INPUT");
  rawParity({ ...rawInput(), operationVersion: A.AUTHORIZATION_VERSION }, "UNSUPPORTED_VERSION");
  rawParity(rawInput({ permissions: [rawRoot({ constraints: { ...rawRoot().constraints, actions: ["read", "read"] } })] }), "INVALID_DELEGATION");
  rawParity(rawInput({ permissions: [rawRoot({ constraints: { ...rawRoot().constraints, actions: [] } })] }), "INVALID_DELEGATION");
  rawParity(rawInput({ permissions: [rawRoot({ constraints: { ...rawRoot().constraints, maxAmount: 5n } })] }), "INVALID_DELEGATION");
  rawParity(rawInput({ permissions: [rawRoot({ constraints: { ...rawRoot().constraints, notBefore: 5, expiresAt: 5 } })] }), "INVALID_DELEGATION");
  rawParity(rawInput({ permissions: [rawRoot(), rawRoot()] }), "INVALID_DELEGATION");
  rawParity(rawInput({ prohibitions: [{ kind: "PROHIBITION", scope: "GLOBAL", authorityId: "g", grantorId: "policy", constraints: { ...rawRoot().constraints, requiredIntersectionIds: ["x"], maxDelegationDepth: 0 } }] }), "INVALID_DELEGATION");
  rawParity(rawInput({ permissions: [rawRoot({ constraints: { ...rawRoot().constraints, actions: Array.from({ length: 257 }, (_, i) => `a${i}`) } })] }), "INVALID_INPUT");
  rawParity(rawInput({ permissions: [rawRoot({ authorityId: "a".repeat(257), rootAuthorityId: "a".repeat(257) })] }), "INVALID_INPUT");
  rawParity(rawInput({ revokedAuthorityIds: ["root", "root"] }), "INVALID_INPUT");
  rawParity(rawInput({ revokedAuthorityIds: ["root"] }), "REVOKED");
  rawParity(rawInput({ authorityEvidence: [] }), "INVALID_DELEGATION");
  rawParity(rawInput({ usage: [{ authorityId: "root", admittedTransactionCount: 0, admittedCumulativeAmount: 0n }] }), "INVALID_DELEGATION");
  rawParity(rawInput({ scope: rawScope({ recognizedRoots: [] }) }), "NO_AUTHORITY");
  rawParity(rawInput({ request: { actorId: "B", action: "read", resource: "r1", claimedAt: 100 } }), "NO_AUTHORITY");
  rawParity(rawInput({ request: { actorId: "A", action: "delete", resource: "r1", claimedAt: 100 } }), "ACTION_NOT_ALLOWED");
  rawParity(rawInput({ scope: rawScope({ evaluationTime: 200 }), permissions: [rawRoot({ constraints: { ...rawRoot().constraints, expiresAt: 200 } })] }), "EXPIRED");
  // A cycle through parent links and a chain deeper than 32.
  const cyc = [rawRoot({ authorityId: "x", parentAuthorityId: "y", grantorId: "A" }), rawRoot({ authorityId: "y", parentAuthorityId: "x", grantorId: "A" })];
  rawParity(rawInput({ permissions: cyc, authorityEvidence: cyc.map((g) => ({ authorityId: g.authorityId, grantEventId: "e", grantEventPosition: 1 })) }), "INVALID_DELEGATION");
  const chain = [rawRoot({ constraints: { ...rawRoot().constraints, maxDelegationDepth: 40 } })];
  for (let i = 1; i <= 33; i += 1) chain.push(rawRoot({ authorityId: `d${i}`, parentAuthorityId: i === 1 ? "root" : `d${i - 1}`, grantorId: "A", constraints: { ...rawRoot().constraints, maxDelegationDepth: 40 - i } }));
  rawParity(rawInput({ permissions: chain, authorityEvidence: chain.map((g) => ({ authorityId: g.authorityId, grantEventId: "e", grantEventPosition: 1 })) }), "INVALID_INPUT");
  // Delegation + intersection partners and prohibitions in the raw path.
  const gated = rawRoot({ authorityId: "gated", rootAuthorityId: "gated", constraints: { ...rawRoot().constraints, requiredIntersectionIds: ["p2", "p1"], maxDelegationDepth: 3 } });
  const p1 = rawRoot({ authorityId: "p1", rootAuthorityId: "p1", independent: false, constraints: { ...rawRoot().constraints, expiresAt: 50, maxDelegationDepth: 0 } });
  const p2 = rawRoot({ authorityId: "p2", rootAuthorityId: "p2", independent: false, constraints: { ...rawRoot().constraints, resources: ["r2", "r1"], notBefore: 3, maxDelegationDepth: 0, actions: ["read"] } });
  const roots = ["gated", "p1", "p2"].map((r) => ({ rootAuthorityId: r, principalId: "P", principalRecognitionEventId: "ev-p", rootGrantEventId: `ev-${r}` }));
  const evidence = ["gated", "p1", "p2"].map((r, i) => ({ authorityId: r, grantEventId: `ev-${r}`, grantEventPosition: i + 1 }));
  const inter = rawInput({ scope: rawScope({ recognizedRoots: roots, historyHead: { ...RAW_HEAD, canonicalTime: 10 }, evaluationTime: 10 }), permissions: [gated, p1, p2], authorityEvidence: evidence });
  const interAllow = rawParity(inter, "ALLOW");
  assert.deepEqual(interAllow.proof.controllingAuthorityIds, ["gated", "p1", "p2"]);
  same(interAllow.proof.effectiveConstraints, { actions: ["read"], resources: ["r1"], quantitative: false, notBefore: 3, expiresAt: 50, maxDelegationDepth: 0, requiredIntersectionIds: ["p1", "p2"] });
  assert.deepEqual(interAllow.proof.intersections.map((i) => [i.requiredAuthorityId, i.requiredByAuthorityIds]), [["p1", ["gated"]], ["p2", ["gated"]]]);
  const expiredPartner = rawParity({ ...inter, scope: rawScope({ recognizedRoots: roots, historyHead: { ...RAW_HEAD, canonicalTime: 10 }, evaluationTime: 60 }) }, "EXPIRED");
  assert.deepEqual([expiredPartner.failures[0].failingAuthorityId, expiredPartner.failures[0].authorityPathIds], ["p1", ["gated"]]);
  const independentPartner = rawParity({ ...inter, permissions: [gated, { ...p1, independent: true, constraints: { ...p1.constraints, actions: ["write"] } }, p2] }, "MISSING_INTERSECTION");
  assert.deepEqual(independentPartner.failures.map((f) => [f.code, f.failingAuthorityId, f.authorityPathIds]), [["MISSING_INTERSECTION", "p1", ["gated"]], ["ACTION_NOT_ALLOWED", "p1", ["p1"]]]);
  const coveringPartner = rawParity({ ...inter, permissions: [gated, { ...p1, independent: true }, p2] }, "ALLOW");
  assert.deepEqual(coveringPartner.proof.controllingAuthorityIds, ["p1"], "an independent partner that covers the request wins on its own");
  // A prohibition cannot hang under a root that requires intersections (it may carry none, yet must inherit them): INVALID_DELEGATION.
  const gatedProhibition = { kind: "PROHIBITION", scope: "ROOT", authorityId: "no-read", grantorId: "P", rootAuthorityId: "gated", constraints: { actions: ["read"], resources: ["r1"], quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [] } };
  rawParity({ ...inter, prohibitions: [gatedProhibition], authorityEvidence: [...evidence, { authorityId: "no-read", grantEventId: "ev-no", grantEventPosition: 9 }] }, "INVALID_DELEGATION");
  const prohibition = { ...gatedProhibition, rootAuthorityId: "root", constraints: { ...gatedProhibition.constraints, expiresAt: 150 } };
  const withProhibition = (expiresAt, subjectActorId) => rawInput({ prohibitions: [{ ...prohibition, constraints: { ...prohibition.constraints, expiresAt }, ...(subjectActorId === undefined ? {} : { subjectActorId }) }], authorityEvidence: [...rawInput().authorityEvidence, { authorityId: "no-read", grantEventId: "ev-no", grantEventPosition: 9 }] });
  const prohibited = rawParity(withProhibition(150), "PROHIBITED");
  assert.deepEqual([prohibited.failures[0].failingAuthorityId, prohibited.failures[0].authorityPathIds, prohibited.failures[0].rootAuthorityId], ["no-read", ["root"], "root"]);
  rawParity(withProhibition(150, "B"), "ALLOW");
  const expiredProhibition = rawParity(withProhibition(50), "ALLOW");
  assert.deepEqual(expiredProhibition.proof.checkedProhibitionIds, ["no-read"]);
  assert.deepEqual(expiredProhibition.proof.authorityEvidence.map((e) => e.authorityId), ["no-read", "root"]);
  const revokedProhibition = rawParity({ ...withProhibition(150), revokedAuthorityIds: ["no-read"] }, "ALLOW");
  assert.deepEqual(revokedProhibition.proof.checkedProhibitionIds, ["no-read"]);
  const global = { kind: "PROHIBITION", scope: "GLOBAL", authorityId: "g", grantorId: "policy", constraints: { actions: ["read"], resources: ["r1"], quantitative: true, maxAmount: 10n, maxDelegationDepth: 0, requiredIntersectionIds: [] } };
  const withGlobal = (amount) => ({ ...rawInput({ prohibitions: [global], authorityEvidence: [...rawInput().authorityEvidence, { authorityId: "g", grantEventId: "ev-g", grantEventPosition: 5 }] }), request: { actorId: "A", action: "read", resource: "r1", claimedAt: 100, ...(amount === undefined ? {} : { amount }) } });
  rawParity(withGlobal(undefined), "ALLOW");
  rawParity(withGlobal(10n), "PROHIBITED");
  rawParity(withGlobal(11n), "ALLOW");
  assert.throws(() => A.evaluateAuthorityPath(42), TypeError);
});

test("evaluateAuthorityPath, G6.9 A-166: the §4.2 overflow set applies to supplied usage (both disjuncts); a byte-later root wins over an overflowing one", () => {
  const MAX = (1n << 256n) - 1n, U53_MAX = Number.MAX_SAFE_INTEGER;
  const pay = (amount) => ({ actorId: "A", action: "pay", resource: "r1", claimedAt: 100, amount });
  const grant = (authorityId, caps) => rawRoot({ authorityId, rootAuthorityId: authorityId,
    constraints: { actions: ["pay"], resources: ["r1"], quantitative: true, maxDelegationDepth: 0, requiredIntersectionIds: [], ...caps } });
  const corpus = (grants, usage, amount) => rawInput({
    scope: rawScope({ recognizedRoots: grants.map((g) => ({ rootAuthorityId: g.authorityId, principalId: "P", principalRecognitionEventId: "ev-p", rootGrantEventId: `ev-${g.authorityId}` })) }),
    request: pay(amount), permissions: grants,
    authorityEvidence: grants.map((g, i) => ({ authorityId: g.authorityId, grantEventId: `ev-${g.authorityId}`, grantEventPosition: 3 + i })),
    usage: usage.map(([authorityId, admittedTransactionCount, admittedCumulativeAmount]) => ({ authorityId, admittedTransactionCount, admittedCumulativeAmount })),
  });
  const verdict = (r) => (r.decision === "ALLOW" ? `ALLOW ${r.proof.recognizedRoot.rootAuthorityId}` : `${r.decision} ${r.code} ${r.evidence?.failures?.map((f) => f.failingAuthorityId).join(",") ?? ""}`.trim());
  const capped = (id) => grant(id, { maxCumulativeAmount: 10n });
  const counted = (id) => grant(id, { maxTransactions: 5 });
  // Count disjunct: count 2^53 − 1 under a maxCumulativeAmount-only grant, amount within the cap.
  const count = A.evaluateAuthorityPath(corpus([capped("o-first")], [["o-first", U53_MAX, 0n]], 1n));
  assert.equal(count.decision, "DENY"); assert.equal(count.code, "AMOUNT_OVERFLOW"); assert.equal(count.scopeAssurance, "SUPPLIED_SCOPE");
  assert.equal(A.evaluateAuthorityPath(corpus([capped("o-first")], [["o-first", U53_MAX - 1, 0n]], 1n)).decision, "ALLOW", "count 2^53 − 2 does not overflow");
  assert.equal(verdict(A.evaluateAuthorityPath(corpus([capped("o-first"), capped("o-second")], [["o-first", U53_MAX, 0n], ["o-second", 0, 0n]], 1n))), "ALLOW o-second");
  // Amount disjunct: usage MAX under a maxTransactions-only grant, count below the cap.
  const amount = A.evaluateAuthorityPath(corpus([counted("o-first")], [["o-first", 1, MAX]], 1n));
  assert.equal(amount.decision, "DENY"); assert.equal(amount.code, "AMOUNT_OVERFLOW");
  assert.equal(A.evaluateAuthorityPath(corpus([counted("o-first")], [["o-first", 1, MAX - 1n]], 1n)).decision, "ALLOW", "MAX − 1 + 1 = MAX does not overflow");
  assert.equal(verdict(A.evaluateAuthorityPath(corpus([counted("o-first"), counted("o-second")], [["o-first", 1, MAX - 1n], ["o-second", 0, 0n]], 2n))), "ALLOW o-second");
  // The step-5 order is unchanged: CUMULATIVE_AMOUNT_EXCEEDED precedes AMOUNT_OVERFLOW, which precedes TRANSACTION_COUNT_EXCEEDED.
  assert.equal(A.evaluateAuthorityPath(corpus([grant("o-first", { maxCumulativeAmount: MAX })], [["o-first", 0, MAX]], 1n)).code, "CUMULATIVE_AMOUNT_EXCEEDED");
  assert.equal(A.evaluateAuthorityPath(corpus([grant("o-first", { maxTransactions: 1 })], [["o-first", 1, MAX]], 1n)).code, "AMOUNT_OVERFLOW");
});

// ---------------------------------------------------------------- (5) signed transitions: admission, administration, receipts

test("validateIntentAdmissionTransition accepts the fixture admission and rebuilds the admission record", () => {
  const state = stateOf(PREFIX);
  const full = referenceRawState(handover.slice(0, 15));
  const result = A.validateIntentAdmissionTransition(state, handover[14], 14, full.head);
  assert.ok(result.ok, result.reason);
  assert.deepEqual(result.usage, []);
  same(result.admission, full.intentAdmissions.get("intent:first-look"));
  const tampered = { ...handover[14], data: { ...handover[14].data, runtimeSignature: handover[14].data.runtimeSignature.slice(0, 130) + (handover[14].data.runtimeSignature.endsWith("1b") ? "1c" : "1b") } };
  assert.equal(A.validateIntentAdmissionTransition(state, tampered, 14, full.head).ok, false);
  const movedHead = A.validateIntentAdmissionTransition(stateOf(handover.slice(0, 13)), handover[14], 14, full.head);
  assert.equal(movedHead.ok, false);
  const wrongProof = { ...handover[14], data: { ...handover[14].data, authorizationProof: { ...FIXTURE_PROOF, checkedProhibitionIds: ["x"] } } };
  assert.equal(A.validateIntentAdmissionTransition(state, wrongProof, 14, full.head).ok, false);
});

/** A quantitative history with a runtime session, role and declared intents, admitted through the reference proposer. */
async function quantitativeAdmissions() {
  const base = mandate.slice(0, 6);
  const q = (name) => `${name}:mandate`;
  let clock = 6;
  const events = [...base];
  const emit = (type, id, data) => { events.push({ data, id, timestamp: clock, type }); clock += 1; };
  emit("ROLE_CREATED", "role:mandate", { exclusive: true, principalId: q("principal"), roleId: q("role") });
  emit("SUCCESSION_RULE_DECLARED", "succession:mandate", { permittedEventTypes: ["AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"], predecessorAgentId: q("buyer"), principalId: q("principal"), roleId: q("role"), ruleId: q("succession"), successorAgentId: q("researcher"), trigger: "AGENT_TERMINATED" });
  emit("AGENT_APPOINTED", "appoint:mandate", { agentId: q("buyer"), principalId: q("principal"), roleId: q("role"), roleTenureId: q("tenure"), successionRuleId: q("succession"), tenureNumber: 1 });
  emit("RUNTIME_SESSION_ADMITTED", "session:mandate", { agentId: q("buyer"), controlEpoch: 1, controllerId: q("controller"), credentialAddress: DEV_KEY.credential, credentialKeyId: q("key"), expiresAt: 20000, sessionId: q("session") });
  const profile = handover[13].data.adapterProfile;
  const declare = (n, amount) => emit("TRANSACTION_INTENT_DECLARED", `declare${n}:mandate`, { action: "purchase", actorId: q("buyer"), adapterProfile: profile, amount, intentId: `intent${n}:mandate`, nonce: `nonce${n}:mandate`, resource: q("plush"), roleId: q("role"), roleTenureId: q("tenure") });
  declare(1, 1500n);
  declare(2, 1500n);
  declare(3, 100n);
  declare(4, 10n);
  assert.equal(core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events }).status, "ACCEPTED");
  const admit = async (n, amount) => {
    const head = headOf(events);
    const time = head.canonicalTime + 1;
    const binding = { runtimeSessionId: q("session"), credentialKeyId: q("key"), controlEpoch: 1, roleId: q("role"), roleTenureId: q("tenure"), intentId: `intent${n}:mandate`, nonce: `nonce${n}:mandate` };
    const request = { actorId: q("buyer"), action: "purchase", resource: q("plush"), claimedAt: time, amount };
    const runtimeSignature = await signChallenge(DEV_KEY, { head }, { domain: base[0].data.domain, request, evaluationTime: time, policyVersion: base[0].data.policyVersion, binding });
    const proposal = core.proposePortableIntentAdmission({
      operationVersion: core.PORTABLE_INTENT_ADMISSION_VERSION, events: [...events], expectedHistoryHead: head, admissionEventId: `admit${n}:mandate`, domain: base[0].data.domain,
      policyVersion: base[0].data.policyVersion, request, evaluationTime: time, binding: { ...binding, runtimeSignature },
    });
    return proposal;
  };
  return { events, admit };
}

test("usage accumulates only from accepted admissions, per capped dimension, and the next decision sees it", async () => {
  const { events, admit } = await quantitativeAdmissions();
  const first = await admit(1, 1500n);
  assert.equal(first.status, "PROPOSED", JSON.stringify(first, (k, v) => (typeof v === "bigint" ? v.toString() : v)).slice(0, 300));
  const pre = stateOf(events);
  const validation = A.validateIntentAdmissionTransition(pre, first.admissionEvent, events.length, first.prospectiveHead);
  assert.ok(validation.ok, validation.reason);
  same(validation.usage, [{ authorityId: "mandate-authority:mandate", admittedTransactionCount: 1, admittedCumulativeAmount: 1500n }]);
  same(validation.admission, referenceRawState([...events, first.admissionEvent]).intentAdmissions.get("intent1:mandate"));
  events.push(first.admissionEvent);
  const afterOne = stateOf(events);
  same(afterOne.authorityUsage.get("mandate-authority:mandate"), validation.usage[0]);
  const second = await admit(2, 1500n);
  assert.equal(second.status, "PROPOSED");
  events.push(second.admissionEvent);
  const afterTwo = stateOf(events);
  const snapshot = A.authorizeState(afterTwo, body(events, { actor: "buyer:mandate", action: "purchase", resource: "plush:mandate", amount: 100n }));
  assert.equal(snapshot.decision, "ALLOW");
  same(snapshot.proof.usageSnapshot, [{ authorityId: "mandate-authority:mandate", admittedTransactionCount: 2, admittedCumulativeAmount: 3000n }]);
  const over = A.authorizeState(afterTwo, body(events, { actor: "buyer:mandate", action: "purchase", resource: "plush:mandate", amount: 2001n }));
  assert.equal(over.code, "CUMULATIVE_AMOUNT_EXCEEDED");
  same(over, referenceAuthorize(referenceRawState(events), body(events, { actor: "buyer:mandate", action: "purchase", resource: "plush:mandate", amount: 2001n })));
  const third = await admit(3, 100n);
  assert.equal(third.status, "PROPOSED");
  events.push(third.admissionEvent);
  const afterThree = stateOf(events);
  const count = A.authorizeState(afterThree, body(events, { actor: "buyer:mandate", action: "purchase", resource: "plush:mandate", amount: 10n }));
  assert.equal(count.code, "TRANSACTION_COUNT_EXCEEDED");
  const fourth = await admit(4, 10n);
  assert.equal(fourth.status, "DENIED");
  assert.equal(fourth.authorization.code, "TRANSACTION_COUNT_EXCEEDED");
  // A retried admission event against the wrong pre-state is refused, so the reservation cannot be applied twice.
  assert.equal(A.validateIntentAdmissionTransition(afterThree, third.admissionEvent, events.length, third.prospectiveHead).ok, false);
  compareHistory(events, [{ actor: "buyer:mandate", action: "purchase", resource: "plush:mandate", amount: 1n }, { actor: "researcher:mandate", action: "purchase", resource: "plush:mandate", amount: 1n }], "quantitative admissions");
});

test("administrative transitions: the fixture's OBLIGATION_CREATED and OBLIGATION_PERFORMANCE_ASSIGNED validate at their pre-event states", () => {
  for (const [position, roleTenureId] of [[18, "tenure-a:first-look"], [23, "tenure-b:first-look"]]) {
    const state = stateOf(handover.slice(0, position));
    const event = handover[position];
    const derived = A.deriveAdministrativeRequirements(state, event);
    assert.equal(derived.roleTenureId, roleTenureId);
    same(derived.request, event.data.administrativeAuthorization.challenge.request);
    const result = A.validateAdministrativeTransition(state, event, position);
    assert.ok(result.ok, result.reason);
    same(A.createAdministrativePolicyProof(state, derived, event.timestamp), event.data.administrativeAuthorization.authorityProof);
    assert.equal(A.createAdministrativePolicyProof(state, derived, event.timestamp).consequential, false);
    assert.ok(refEngine.validatePortableAdministrativeTransition(referenceRawState(handover.slice(0, position)), event, derived));
    same(A.administrativeTransitionEffect(event), refEngine_effect(event));
    const wrapper = event.data.administrativeAuthorization;
    const badSignature = { ...event, data: { ...event.data, administrativeAuthorization: { ...wrapper, runtimeSignature: wrapper.runtimeSignature.slice(0, 130) + (wrapper.runtimeSignature.endsWith("1b") ? "1c" : "1b") } } };
    assert.equal(A.validateAdministrativeTransition(state, badSignature, position).ok, false);
    const badProof = { ...event, data: { ...event.data, administrativeAuthorization: { ...wrapper, authorityProof: { ...wrapper.authorityProof, usageSnapshot: [] , checkedProhibitionIds: ["x"] } } } };
    assert.equal(A.validateAdministrativeTransition(state, badProof, position).ok, false);
    assert.equal(A.validateAdministrativeTransition(stateOf(handover.slice(0, position - 1)), event, position).ok, false, "head moved");
  }
  assert.equal(A.validateAdministrativeTransition(stateOf(PREFIX), handover[14], 14).ok, false);
  assert.equal(A.createAdministrativePolicyProof(stateOf(PREFIX), { request: { actorId: "a:first-look", action: "OBLIGATE", resource: "resource:first-look", claimedAt: 14, amount: 1n }, requiredPrincipalId: "principal:first-look", requiredAuthorityIds: [], roleId: "role:first-look", roleTenureId: "tenure-a:first-look" }, 14), undefined);
  assert.equal(A.createAdministrativePolicyProof(stateOf(PREFIX), { request: { actorId: "a:first-look", action: "OBLIGATE", resource: "resource:first-look", claimedAt: 14 }, requiredPrincipalId: "principal:other", requiredAuthorityIds: [], roleId: "role:first-look", roleTenureId: "tenure-a:first-look" }, 14), undefined);
  assert.equal(A.createAdministrativePolicyProof(stateOf(PREFIX), { request: { actorId: "a:first-look", action: "OBLIGATE", resource: "resource:first-look", claimedAt: 14 }, requiredPrincipalId: "principal:first-look", requiredAuthorityIds: ["review-authority:first-look"], roleId: "role:first-look", roleTenureId: "tenure-a:first-look" }, 14), undefined);
});
const refAdminCodec = await referenceCore02("core/portable-administration-codec.ts");
const refEngine_effect = (event) => refAdminCodec.portableAdministrativeTransitionEffect(event);

test("evaluateReceiptPolicy matches the reference on the admitted proof over time", () => {
  for (const events of [handover, handoverDenied, handover.slice(0, 15), handover.slice(0, 21)]) {
    const state = stateOf(events);
    const refState = referenceRawState(events);
    const proof = events[14].data.authorizationProof;
    for (const at of [14, 25, 999, 1000, 10]) {
      same(A.evaluateReceiptPolicy(state, proof, at), refEngine.evaluatePortableReceiptPolicy(refState, proof, at), `receipt policy at ${at} (${events.length} events)`);
    }
  }
  const live = A.evaluateReceiptPolicy(stateOf(handover.slice(0, 15)), handover[14].data.authorizationProof, 14);
  assert.equal(live.live, true);
  const revoked = A.evaluateReceiptPolicy(stateOf(handover), handover[14].data.authorizationProof, 25);
  assert.deepEqual([revoked.live, revoked.decisiveAuthorityIds, revoked.decisiveAgentIds], [false, ["collect-authority:first-look"], ["a:first-look"]]);
});

test("normalizedGrant, attenuation and combineConstraints", () => {
  const grant = mandate[5].data.grant;
  const normalized = A.normalizedGrant({ ...grant, constraints: { ...grant.constraints, actions: ["z", "a"], resources: ["Beta", "alpha"] } });
  assert.deepEqual([normalized.constraints.actions, normalized.constraints.resources], [["a", "z"], ["Beta", "alpha"]]);
  same(A.normalizedGrant(handover[8].data.grant), handover[8].data.grant);
  const root = mandate[4].data.grant.constraints;
  assert.ok(A.constraintsAreAttenuated(root, grant.constraints));
  assert.ok(!A.constraintsAreAttenuated(root, { ...grant.constraints, maxAmount: 2501n }));
  assert.ok(!A.constraintsAreAttenuated(root, { ...grant.constraints, quantitative: false, maxAmount: undefined, maxCumulativeAmount: undefined }));
  assert.ok(!A.constraintsAreAttenuated({ ...root, maxDelegationDepth: 0 }, grant.constraints));
  same(A.combineConstraints([mandate[4].data.grant, mandate[5].data.grant]), { actions: ["purchase"], resources: ["plush:mandate"], quantitative: true, expiresAt: 10000, maxAmount: 500n, maxCumulativeAmount: 1000n, maxTransactions: 2, maxDelegationDepth: 1, requiredIntersectionIds: [] });
  assert.equal(E.compareIds("Alpha", "alpha") < 0 && E.compareIds("alpha", "zeta") < 0 && E.compareIds("a", "ab") < 0, true);
  assert.equal(E.compareIds("\u{1F600}", "�") > 0, true, "astral code points sort after U+FFFD in UTF-8 order");
});

// ---------------------------------------------------------------- (6) narrowed DENY evidence (format 1) vs legacy parity

const eventsMod = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const TRELLIS_FORMAT = "irontrellis-event/1";
const WIDE_GRANTS = 3000;
const WIDE_REQUEST = { actor: "agent:actor", action: "read", resource: "doc:1" };
const wideConstraints = (extra = {}) => ({ actions: ["read"], resources: ["doc:1"], quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [], expiresAt: 1_000_000, ...extra });
const widePermission = (authorityId, granteeId, extra = {}) => ({
  kind: "PERMISSION", authorityId, grantorId: "owner", granteeId, rootAuthorityId: authorityId, independent: true, constraints: wideConstraints(), ...extra,
});

/**
 * The raw (unsigned) events of a history with 3,000 grants to other actors
 * and two candidates for `agent:actor`: an expired grant (the EXPIRED headline)
 * and a write-only grant (ACTION_NOT_ALLOWED). Around them: a ROOT prohibition
 * on the expired grant, a relevant GLOBAL prohibition that was revoked, an
 * irrelevant GLOBAL one, a foreign grant, other revocations and epoch advances.
 * Timestamps equal positions; the head is a CONTROL_EPOCH_ADVANCED of another agent.
 */
function wideHistoryEvents(genesisData) {
  const raw = [];
  const emit = (id, type, data) => raw.push({ id, type, timestamp: raw.length, data });
  emit("genesis", "DEPLOYMENT_INITIALIZED", genesisData);
  emit("principal", "PRINCIPAL_CREATED", { principalId: "owner" });
  emit("agent-actor", "AGENT_CREATED", { agentId: "agent:actor", principalId: "owner", controllerId: "controller", initialControlEpoch: 1 });
  for (let i = 0; i < 10; i += 1) emit(`agent-o${i}`, "AGENT_CREATED", { agentId: `agent:o${i}`, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 });
  emit("grant-actor", "AUTHORITY_GRANTED", { grant: widePermission("auth:actor", "agent:actor", { constraints: wideConstraints({ expiresAt: 100, maxDelegationDepth: 1 }) }) });
  emit("grant-actor-write", "AUTHORITY_GRANTED", { grant: widePermission("auth:actor-write", "agent:actor", { constraints: wideConstraints({ actions: ["write"] }) }) });
  emit("prohibit-root", "AUTHORITY_GRANTED", { grant: { kind: "PROHIBITION", scope: "ROOT", authorityId: "prohibit:root", grantorId: "owner", rootAuthorityId: "auth:actor", constraints: wideConstraints({ expiresAt: 60 }) } });
  emit("prohibit-global-hit", "AUTHORITY_GRANTED", { grant: { kind: "PROHIBITION", scope: "GLOBAL", authorityId: "prohibit:global-hit", grantorId: "policy-source", constraints: wideConstraints() } });
  emit("prohibit-global-other", "AUTHORITY_GRANTED", { grant: { kind: "PROHIBITION", scope: "GLOBAL", authorityId: "prohibit:global-other", grantorId: "policy-source", constraints: wideConstraints({ actions: ["write"] }) } });
  emit("grant-foreign", "AUTHORITY_GRANTED", { grant: widePermission("auth:foreign", "agent:o0") });
  for (let i = 0; i < WIDE_GRANTS; i += 1) emit(`g${i}`, "AUTHORITY_GRANTED", { grant: widePermission(`auth:o${i}`, `agent:o${i % 10}`) });
  emit("revoke-global-hit", "AUTHORITY_REVOKED", { authorityId: "prohibit:global-hit", revokerId: "policy-source" });
  emit("revoke-other", "AUTHORITY_REVOKED", { authorityId: "auth:o0", revokerId: "owner" });
  emit("epoch-other", "CONTROL_EPOCH_ADVANCED", { agentId: "agent:o1", controllerId: "controller", fromEpoch: 1, toEpoch: 2 });
  emit("epoch-actor", "CONTROL_EPOCH_ADVANCED", { agentId: "agent:actor", controllerId: "controller", fromEpoch: 1, toEpoch: 2 });
  emit("epoch-other2", "CONTROL_EPOCH_ADVANCED", { agentId: "agent:o2", controllerId: "controller", fromEpoch: 1, toEpoch: 2 });
  return raw;
}

/** An incremental format-1 builder (as in test/replay.test.mjs): each control event is signed by the ed25519 owner key over its predecessor head. */
function trellisHistory(owner) {
  const domain = { protocol: "irontrellis", version: "1", deploymentId: "deployment:wide" };
  const genesisData = {
    domain, versions: { ...eventsMod.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: [{ keyId: owner.keyId, scheme: "ed25519", credential: owner.credential }],
    adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:wide", policyVersion: "policy:wide/1",
    rootRecognitionPolicy: A.ROOT_RECOGNITION_POLICY, globalPolicySourceId: "policy-source", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
  };
  const state = newReplay.createReplayState(TRELLIS_FORMAT);
  const history = [];
  const sign = suites.signHashWith(owner);
  const add = async (raw) => {
    let data = raw.data;
    if (state.events.length > 0 && eventsMod.isControlEvent(raw.type)) {
      const hash = eventsMod.controlAuthorizationHash({ domain, eventId: raw.id, eventType: raw.type, timestamp: raw.timestamp,
        previousHead: { hash: state.head.hash, position: state.head.position }, effectHash: hashMod.hashCanonical(raw.data, "sha256") }, "sha256");
      data = { ...raw.data, controlAuthorization: { keyId: owner.keyId, signature: await sign(hash) } };
    }
    const event = { ...raw, data };
    const applied = newReplay.applyEvent(state, event);
    assert.ok(applied.ok, `${raw.id}: ${applied.reason}`);
    history.push(event);
  };
  return { state, history, add, genesisData };
}

const evidenceIds = (failure) => failure.evidence.map((e) => e.eventId);
const sortedById = (ids) => [...ids].sort(E.compareIds);

test("format 1: a DENY cites only the decision-relevant events (3,000 foreign grants), grows with the state, and cites the binding's evidence", { skip: newReplay === undefined }, async () => {
  const owner = suites.generateKeyPair("ed25519", "owner:wide");
  const b = trellisHistory(owner);
  for (const raw of wideHistoryEvents(b.genesisData)) await b.add(raw);
  const replayed = newReplay.replay(b.history);
  assert.equal(replayed.status, "ACCEPTED", replayed.reason);
  const state = replayed.state;
  assert.equal(state.format, TRELLIS_FORMAT);
  const ask = (s, extra = {}) => A.authorizeState(s, body(b.history, { ...WIDE_REQUEST, head: s.head, ...extra }));

  // Before: the legacy predicate would cite every authority event — two failures × ~3,000 references collapse to OUTPUT_LIMIT_EXCEEDED.
  const legacySize = E.decisionEvidence(E.createEvidenceContext(state)).length;
  assert.ok(2 * legacySize > E.MAX_RESULT_EVIDENCE, `legacy decision evidence ${legacySize}`);

  const deny = ask(state);
  assert.equal(deny.decision, "DENY");
  assert.equal(deny.code, "EXPIRED");
  assert.deepEqual(deny.failures.map((f) => [f.code, f.terminalAuthorityId]), [["EXPIRED", "auth:actor"], ["ACTION_NOT_ALLOWED", "auth:actor-write"]]);
  const expected = sortedById(["genesis", "agent-actor", "epoch-actor", "grant-actor", "grant-actor-write", "prohibit-root", "prohibit-global-hit", "revoke-global-hit", "epoch-other2"]);
  for (const failure of deny.failures) assert.deepEqual(evidenceIds(failure), expected);
  assert.equal(deny.failures[0].evidence, deny.failures[1].evidence, "one shared list");
  const head = deny.failures[0].evidence.find((e) => e.eventId === "epoch-other2");
  same(head, { kind: "EVENT", eventId: "epoch-other2", eventType: "CONTROL_EPOCH_ADVANCED", position: state.head.position, historyHash: state.head.hash });
  for (const ref of deny.failures[0].evidence) assert.equal(ref.historyHash, state.eventHistoryHashes[ref.position]);
  console.log(`narrowed DENY evidence on ${state.events.length} events / ${state.authorities.size} authorities: before ${legacySize} refs per failure × 2 failures (OUTPUT_LIMIT_EXCEEDED), after ${deny.failures[0].evidence.length} refs per failure`);

  // ALLOW proofs are untouched: another agent's decision proves the byte-least of its 300 grants.
  const allow = ask(state, { actor: "agent:o3" });
  assert.equal(allow.decision, "ALLOW");
  assert.deepEqual(allow.proof.controllingAuthorityIds, ["auth:o1003"]);
  // A GLOBAL prohibition hit: the prohibitions relevant to `write` replace those relevant to `read` (the ROOT one covers only `read`).
  const prohibited = ask(state, { action: "write" });
  assert.deepEqual([prohibited.code, prohibited.failures[0].failingAuthorityId], ["PROHIBITED", "prohibit:global-other"]);
  assert.deepEqual(evidenceIds(prohibited.failures[0]), sortedById(["genesis", "agent-actor", "epoch-actor", "grant-actor", "grant-actor-write", "prohibit-global-other", "epoch-other2"]));
  // The budget is unchanged: an actor with 300 failing candidates (≈306 references each) still collapses.
  assert.equal(ask(state, { actor: "agent:o1", resource: "doc:none" }).code, "OUTPUT_LIMIT_EXCEEDED");

  // The builder's own (incrementally grown) state gives the same answer, then grows: the memo is extended, not rebuilt from a stale list.
  same(ask(b.state), deny);
  const t0 = b.state.head.canonicalTime + 1;
  const more = [
    ["grant-dep", "AUTHORITY_GRANTED", { grant: widePermission("auth:dep", "agent:actor", { independent: false }) }],
    ["grant-gated", "AUTHORITY_GRANTED", { grant: widePermission("auth:gated", "agent:actor", { constraints: wideConstraints({ requiredIntersectionIds: ["auth:dep", "auth:foreign"] }) }) }],
    ["revoke-actor", "AUTHORITY_REVOKED", { authorityId: "auth:actor", revokerId: "owner" }],
    ["epoch-actor-2", "CONTROL_EPOCH_ADVANCED", { agentId: "agent:actor", controllerId: "controller", fromEpoch: 2, toEpoch: 3 }],
  ];
  for (let i = 0; i < more.length; i += 1) await b.add({ id: more[i][0], type: more[i][1], timestamp: t0 + i, data: more[i][2] });
  const grown = ask(b.state);
  assert.equal(grown.code, "REVOKED");
  assert.deepEqual(grown.failures.map((f) => [f.code, f.terminalAuthorityId, f.failingAuthorityId]), [
    ["REVOKED", "auth:actor", "auth:actor"], ["MISSING_INTERSECTION", "auth:gated", "auth:foreign"], ["ACTION_NOT_ALLOWED", "auth:actor-write", "auth:actor-write"],
  ]);
  const grownExpected = sortedById([
    "genesis", "agent-actor", "epoch-actor", "epoch-actor-2", "grant-actor", "revoke-actor", "grant-actor-write", "prohibit-root", "prohibit-global-hit", "revoke-global-hit",
    "grant-gated", "grant-dep", "grant-foreign",
  ]);
  for (const failure of grown.failures) assert.deepEqual(evidenceIds(failure), grownExpected);
  same(grown, ask(newReplay.replay(b.history).state), "grown state equals a fresh replay");

  // With a consequential binding the session, tenure and intent evidence is cited exactly as the binding denials cite it.
  const runtime = suites.generateKeyPair("ed25519", "runtime:wide");
  const t1 = b.state.head.canonicalTime + 1;
  const bound = [
    ["role", "ROLE_CREATED", { roleId: "role:wide", principalId: "owner", exclusive: true }],
    ["appoint", "AGENT_APPOINTED", { agentId: "agent:actor", roleId: "role:wide", roleTenureId: "tenure:wide", tenureNumber: 1, principalId: "owner" }],
    ["session", "RUNTIME_SESSION_ADMITTED", { sessionId: "session:wide", agentId: "agent:actor", controllerId: "controller", controlEpoch: 3, credentialKeyId: "key:wide", credentialScheme: "ed25519", credentialPublicKey: runtime.credential }],
    ["declare", "TRANSACTION_INTENT_DECLARED", { intentId: "intent:wide", nonce: "nonce:wide", actorId: "agent:actor", action: "read", resource: "doc:1", roleId: "role:wide", roleTenureId: "tenure:wide", adapterProfile: editions.knownAdapterProfile("adapter:simulated") }],
    ["declare-other", "TRANSACTION_INTENT_DECLARED", { intentId: "intent:other", nonce: "nonce:other", actorId: "agent:actor", action: "read", resource: "doc:1", roleId: "role:wide", roleTenureId: "tenure:wide", adapterProfile: editions.knownAdapterProfile("adapter:simulated") }],
    ["epoch-other3", "CONTROL_EPOCH_ADVANCED", { agentId: "agent:o3", controllerId: "controller", fromEpoch: 1, toEpoch: 2 }],
  ];
  for (let i = 0; i < bound.length; i += 1) await b.add({ id: bound[i][0], type: bound[i][1], timestamp: t1 + i, data: bound[i][2] });
  const binding = { runtimeSessionId: "session:wide", credentialKeyId: "key:wide", controlEpoch: 3, roleId: "role:wide", roleTenureId: "tenure:wide", intentId: "intent:wide", nonce: "nonce:wide" };
  const unsigned = body(b.history, { ...WIDE_REQUEST, head: b.state.head, consequential: true, binding });
  const signedBody = { ...unsigned, binding: { ...binding, runtimeSignature: await signChallenge(runtime, b.state, unsigned, "sha256") } };
  const consequential = A.authorizeState(b.state, signedBody);
  assert.equal(consequential.code, "REVOKED");
  const ctx = E.createEvidenceContext(b.state);
  const bindingIds = [
    ...E.sessionLifecycleEvidence(ctx, "agent:actor", "session:wide"), ...E.tenureLifecycleEvidence(ctx, "role:wide", "tenure:wide"), ...E.intentDecisionEvidence(ctx, "agent:actor", "intent:wide", "nonce:wide"),
  ].map((e) => e.eventId);
  assert.deepEqual(sortedById(new Set(bindingIds)), sortedById(["agent-actor", "epoch-actor", "epoch-actor-2", "session", "role", "appoint", "declare", "epoch-other3"]));
  const consequentialExpected = sortedById(new Set([...grownExpected, ...bindingIds]));
  for (const failure of consequential.failures) assert.deepEqual(evidenceIds(failure), consequentialExpected);
  for (const id of ["epoch-other", "declare-other", "g1", "principal"]) assert.ok(!consequentialExpected.includes(id), id);
});

test("legacy: the same 3,000-grant shape keeps authorityDecisionEvidence and collapses to OUTPUT_LIMIT_EXCEEDED exactly as the reference", () => {
  const genesis = {
    adapterPolicyHash: core.PORTABLE_ADAPTER_POLICY_HASH, canonicalLineageId: "lineage:wide", domain: { chainId: "31337", deploymentId: "deployment:wide", protocol: "continuity", verifyingContract: "0x0000000000000000000000000000000000003002", version: "0.2" },
    finality: "LOCAL_ONLY", globalPolicySourceId: "policy-source", policyVersion: "policy:wide/0.2", rootRecognitionPolicy: A.ROOT_RECOGNITION_POLICY, timeSource: "EVENT_TIMESTAMP", versions: GENESIS_VERSIONS,
  };
  const events = wideHistoryEvents(genesis);
  const refState = referenceRawState(events);
  const b = body(events, { ...WIDE_REQUEST, head: refState.head });
  const expected = referenceAuthorize(refState, b);
  assert.equal(expected.decision, "INDETERMINATE");
  assert.equal(expected.code, "OUTPUT_LIMIT_EXCEEDED");
  const states = [["adapted", adaptReferenceState(refState)], ...(newReplay ? [["irontrellis-replay", stateOf(events)]] : [])];
  for (const [name, state] of states) {
    assert.equal(state.format, "continuity-event/0.2");
    same(A.authorizeState(state, b), expected, name);
    // A single failure (the GLOBAL prohibition on `write`) fits the budget and still cites every authority event (unchanged legacy semantics).
    const writeBody = { ...b, request: { ...b.request, action: "write" } };
    const single = A.authorizeState(state, writeBody);
    assert.equal(single.code, "PROHIBITED");
    same(single, referenceAuthorize(refState, writeBody), `${name} single failure`);
    assert.equal(single.failures[0].evidence.length, E.decisionEvidence(E.createEvidenceContext(state)).length);
    assert.ok(single.failures[0].evidence.length > WIDE_GRANTS);
  }
});

// ---------------------------------------------------------------- (7) benchmark

/** The new engine replays incrementally (no whole-array capture); the reference kernel caps histories at 4096 events. */
function benchState(events) {
  if (newReplay !== undefined) {
    const result = newReplay.replay(events);
    if (result.status === "ACCEPTED") return result.state;
    console.log(`bench: the engine's replay rejected the 10k history (${result.code}: ${result.reason ?? ""} at ${result.position}); building the state directly`);
  }
  // The legacy prefix commitment is a canonical list and therefore stops at 4096 events; format 1 hashes incrementally.
  const hasher = new hashMod.HistoryHasher("irontrellis-event/1");
  const state = adaptReferenceState({ ...referenceRawState(events.slice(0, 2)), events: [], eventHistoryHashes: [] });
  const authorities = new Map();
  const recognizedRoots = new Map();
  const eventHistoryHashes = [];
  const agents = new Map();
  const principals = new Map();
  events.forEach((event, position) => {
    eventHistoryHashes.push(hasher.push(event));
    const d = event.data;
    if (event.type === "PRINCIPAL_CREATED") principals.set(d.principalId, { id: d.principalId, creationEventId: event.id, creationEventPosition: position });
    if (event.type === "AGENT_CREATED") agents.set(d.agentId, { id: d.agentId, principalId: d.principalId, controllerId: d.controllerId, currentControlEpoch: 1, terminated: false });
    if (event.type === "AUTHORITY_GRANTED") {
      authorities.set(d.grant.authorityId, { grant: d.grant, grantEventId: event.id, grantEventPosition: position });
      recognizedRoots.set(d.grant.authorityId, { rootAuthorityId: d.grant.authorityId, principalId: "P", principalRecognitionEventId: "principal", rootGrantEventId: event.id });
    }
    if (event.type === "AUTHORITY_REVOKED") authorities.set(d.authorityId, { ...authorities.get(d.authorityId), revocationEventId: event.id, revocationEventPosition: position, revokerId: d.revokerId });
  });
  const last = events[events.length - 1];
  return { ...state, events, eventHistoryHashes, head: { hash: eventHistoryHashes[events.length - 1], position: events.length - 1, canonicalTime: last.timestamp }, principals, agents, authorities, recognizedRoots, eventPositionsById: new Map(events.map((e, i) => [e.id, i])) };
}

test("benchmark: authorizeState on 10,000 events / 3,000 grants for one actor", () => {
  const events = [];
  let clock = 0;
  const emit = (type, id, data) => { events.push({ data, id, timestamp: clock, type }); clock += 1; };
  const genesis = { ...handover[0].data, domain: { ...handover[0].data.domain, deploymentId: "bench" }, canonicalLineageId: "bench", policyVersion: "bench/0.2", globalPolicySourceId: "policy:bench" };
  emit("DEPLOYMENT_INITIALIZED", "genesis", genesis);
  emit("PRINCIPAL_CREATED", "principal", { principalId: "P" });
  const AGENTS = 100;
  for (let i = 0; i < AGENTS; i += 1) emit("AGENT_CREATED", `agent${i}`, { agentId: `agent${i}`, controllerId: "ctl", initialControlEpoch: 1, principalId: "P" });
  const grantTo = (n, grantee, tag) => {
    for (let i = 0; i < n; i += 1) {
      const authorityId = `${tag}${i}`;
      emit("AUTHORITY_GRANTED", `g-${authorityId}`, { grant: { authorityId, constraints: { actions: [`act${i % 50}`], expiresAt: 1_000_000, maxDelegationDepth: 1, quantitative: false, requiredIntersectionIds: [], resources: [`res${i % 20}`] }, granteeId: grantee, grantorId: "P", independent: true, kind: "PERMISSION", rootAuthorityId: authorityId } });
    }
  };
  grantTo(3000, "agent0", "own");
  let others = 0;
  while (events.length < 9_800) grantTo(1, `agent${1 + (others % (AGENTS - 1))}`, `other${others++}-`);
  while (events.length < 10_000) emit("AUTHORITY_REVOKED", `r${events.length}`, { authorityId: `other${events.length - 9_800}-0`, revokerId: "P" });
  const started = performance.now();
  const built = benchState(events);
  const replayMs = performance.now() - started;
  const ask = (state, action, resource) => A.authorizeState(state, body(events, { actor: "agent0", action, resource, head: state.head }));
  const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  // A fresh state object each round measures the cold path (corpus validation + indexes + one decision).
  const cold = [];
  for (let round = 0; round < 15; round += 1) {
    const state = { ...built };
    const t = performance.now();
    assert.equal(ask(state, "act7", "res7").decision, "ALLOW");
    cold.push(performance.now() - t);
  }
  const state = { ...built };
  ask(state, "act0", "res0");
  const warm = [];
  for (let i = 0; i < 20; i += 1) {
    const t = performance.now();
    assert.equal(ask(state, `act${i}`, `res${i}`).decision, "ALLOW");
    warm.push(performance.now() - t);
  }
  // An append-only state that grew since the last decision is extended, not rebuilt.
  const grown = { ...built, events: [...built.events], eventHistoryHashes: [...built.eventHistoryHashes], authorities: new Map(built.authorities), recognizedRoots: new Map(built.recognizedRoots), eventPositionsById: new Map(built.eventPositionsById) };
  ask(grown, "act1", "res1");
  const incremental = [];
  for (let i = 0; i < 5; i += 1) {
    const position = grown.events.length;
    const grant = { authorityId: `late${i}`, constraints: { actions: ["late"], expiresAt: 1_000_000, maxDelegationDepth: 0, quantitative: false, requiredIntersectionIds: [], resources: ["res1"] }, granteeId: "agent0", grantorId: "P", independent: true, kind: "PERMISSION", rootAuthorityId: `late${i}` };
    const event = { data: { grant }, id: `late-${i}`, timestamp: position, type: "AUTHORITY_GRANTED" };
    grown.events.push(event);
    grown.eventHistoryHashes.push(hashMod.hashCanonical([grown.eventHistoryHashes[position - 1], event], "sha256"));
    grown.authorities.set(grant.authorityId, { grant, grantEventId: event.id, grantEventPosition: position });
    grown.recognizedRoots.set(grant.authorityId, { rootAuthorityId: grant.authorityId, principalId: "P", principalRecognitionEventId: "principal", rootGrantEventId: event.id });
    grown.eventPositionsById.set(event.id, position);
    grown.head = { hash: grown.eventHistoryHashes[position], position, canonicalTime: position };
    const t = performance.now();
    const result = ask(grown, "late", "res1");
    incremental.push(performance.now() - t);
    assert.equal(result.decision, "ALLOW");
    assert.deepEqual(result.proof.controllingAuthorityIds, ["late0"], "the byte-least root wins");
  }
  const denyStart = performance.now();
  const deny = ask(state, "nope", "res1");
  const denyMs = performance.now() - denyStart;
  assert.equal(deny.code, "OUTPUT_LIMIT_EXCEEDED", "3,000 failing candidates × ~10k evidence refs exceed the output budget");
  const steady = median(cold.slice(-5));
  console.log(`bench (${events.length} events, 3000 grants for agent0): state build ${replayMs.toFixed(1)} ms; authorize cold (fresh state, corpus rebuilt) steady median ${steady.toFixed(2)} ms, min ${Math.min(...cold).toFixed(2)} ms, first call ${cold[0].toFixed(2)} ms (JIT); after append ${median(incremental).toFixed(2)} ms; warm ${median(warm).toFixed(3)} ms; deny ${denyMs.toFixed(2)} ms`);
  // Under the full suite the heap is heavy with earlier states, so the minimum is the stable cold figure; run this test alone for medians.
  // The bounds are loose on purpose (the targets are ~10 ms): CI and shared hosts are noisy, and a timing test must not fail under load,
  // so they are scaled by the machine's current speed (helpers/timing.mjs; 1 on a quiet host). A 10 ms bound failed under load once.
  const factor = loadFactor();
  assert.ok(Math.min(...cold) <= 30 * factor, `cold authorize min ${Math.min(...cold)} ms (bound 30 ms × load factor ${factor.toFixed(2)})`);
  assert.ok(median(warm) <= 30 * factor && median(incremental) <= 30 * factor, `warm ${median(warm)} ms, after append ${median(incremental)} ms (load factor ${factor.toFixed(2)})`);
});

// ---------------------------------------------------------------- block 3.2: the plausible-candidate pass
//
// evaluateAlgebra first looks for the winner among an actor's candidates whose terminal grant names the requested
// action and resource (a per-resource index, for actors with more than 32 candidates) and falls back to the full
// candidate loop when none wins. Decisions must be byte-identical whether that pass runs for every actor (threshold 0),
// for none (Infinity) or at the default threshold, and identical to the reference engine.

test("plausible-candidate pass: generated corpora and fixtures decide identically with the pass forced on (reference parity)", () => {
  const previous = A.setCandidateIndexThresholdForTests(0);
  try {
    const before = compared;
    for (const [name, events] of Object.entries(HISTORIES)) {
      const raw = referenceRawState(events);
      const grants = [...raw.authorities.values()].map((r) => r.grant);
      const actions = [...new Set(grants.flatMap((g) => g.constraints.actions)), "delete-everything"];
      const resources = [...new Set(grants.flatMap((g) => g.constraints.resources)), "other"];
      const head = headOf(events).canonicalTime;
      const requests = [];
      for (const actor of [...raw.agents.keys(), "ghost"]) for (const action of actions) for (const resource of resources) for (const amount of [undefined, 400n]) for (const at of [head, 5000]) requests.push({ actor, action, resource, amount, at });
      compareHistory(events, requests, `forced ${name}`);
    }
    for (let seed = 1; seed <= 40; seed += 1) {
      const history = generateHistory(seed);
      compareHistory(history.events, requestGrid(history), `forced seed ${seed}`);
    }
    // Grown event by event: the index is built on first use and then maintained by indexCandidate (extendMemo).
    for (let seed = 1; seed <= 12; seed += 1) {
      const history = generateHistory(seed);
      const state = newReplay.createReplayState("continuity-event/0.2");
      const grid = requestGrid(history, { cap: 4 }).filter((r) => r.at === 10_000 || r.amount === 5n);
      for (let i = 0; i < history.events.length; i += 1) {
        assert.ok(newReplay.applyEvent(state, history.events[i]).ok);
        if (i < 8) continue;
        const events = history.events.slice(0, i + 1);
        const refState = referenceRawState(events);
        for (const request of grid) {
          const b = body(events, { ...request, head: state.head, at: Math.max(request.at, state.head.canonicalTime) });
          same(A.authorizeState(state, b), referenceAuthorize(refState, b), `forced grown seed ${seed} after event ${i}`);
          compared += 1;
        }
      }
    }
    assert.ok(compared - before > 5000, `${compared - before} comparisons`);
  } finally {
    A.setCandidateIndexThresholdForTests(previous);
  }
});

test("plausible-candidate pass: an actor with 1,200 candidates (ties, revocations, expiries, prohibitions) decides as the full loop", () => {
  const events = [];
  let clock = 0;
  const emit = (type, id, data) => { events.push({ data, id, timestamp: clock, type }); clock += 1; };
  const genesis = { ...handover[0].data, domain: { ...handover[0].data.domain, deploymentId: "candidates" }, canonicalLineageId: "candidates", policyVersion: "candidates/0.2", globalPolicySourceId: "policy:candidates" };
  emit("DEPLOYMENT_INITIALIZED", "genesis", genesis);
  emit("PRINCIPAL_CREATED", "principal", { principalId: "P" });
  emit("AGENT_CREATED", "agent-w", { agentId: "w", controllerId: "ctl", initialControlEpoch: 1, principalId: "P" });
  const constraintsOf = [];
  for (let i = 0; i < 1200; i += 1) {
    const authorityId = `g${String(i).padStart(4, "0")}`;
    const constraints = constraintsOf[i] = { actions: [`act${i % 7}`, ...(i % 3 === 0 ? ["shared"] : [])].sort(), maxDelegationDepth: 1, quantitative: i % 11 === 0, requiredIntersectionIds: [], resources: [`res${i % 13}`, ...(i % 5 === 0 ? ["common"] : [])].sort(),
      ...(i % 17 === 0 ? { expiresAt: 1500 } : { expiresAt: 1_000_000 }), ...(i % 11 === 0 ? { maxAmount: 100n } : {}) };
    emit("AUTHORITY_GRANTED", `e-${authorityId}`, { grant: { authorityId, constraints, granteeId: "w", grantorId: "P", independent: true, kind: "PERMISSION", rootAuthorityId: authorityId } });
  }
  for (let i = 0; i < 1200; i += 19) emit("AUTHORITY_REVOKED", `r${i}`, { authorityId: `g${String(i).padStart(4, "0")}`, revokerId: "P" });
  // ROOT prohibitions (their root's constraints, one delegation level less: attenuated) on a few roots.
  for (let i = 3; i < 1200; i += 97) emit("AUTHORITY_GRANTED", `p${i}`, { grant: { authorityId: `no${i}`, constraints: { ...constraintsOf[i], maxDelegationDepth: 0 }, grantorId: "P", kind: "PROHIBITION", rootAuthorityId: `g${String(i).padStart(4, "0")}`, scope: "ROOT", subjectActorId: "w" } });
  const replayed = newReplay.replay(events);
  assert.equal(replayed.status, "ACCEPTED", `${replayed.code} ${replayed.reason} at ${replayed.position}`);
  const state = replayed.state;
  const requests = [];
  for (const action of ["act0", "act3", "act6", "shared", "nothing"]) for (const resource of ["res0", "res5", "res12", "common", "nowhere"]) for (const amount of [undefined, 50n, 500n]) for (const at of [clock, 2000]) requests.push({ actor: "w", action, resource, amount, at });
  const decide = (threshold) => {
    const previous = A.setCandidateIndexThresholdForTests(threshold);
    try {
      const fresh = { ...state }; // a new memo key: the corpus and the index are built under this threshold
      return requests.map((request) => norm(A.authorizeState(fresh, body(events, { ...request, head: fresh.head }))));
    } finally {
      A.setCandidateIndexThresholdForTests(previous);
    }
  };
  const full = decide(Infinity), forced = decide(0), standard = decide(32);
  let allows = 0;
  for (let i = 0; i < requests.length; i += 1) {
    assert.equal(forced[i], full[i], `forced ${JSON.stringify(requests[i], (k, v) => (typeof v === "bigint" ? `${v}` : v))}`);
    assert.equal(standard[i], full[i], `default threshold ${i}`);
    if (JSON.parse(full[i]).decision === "ALLOW") allows += 1;
  }
  assert.ok(allows > 20 && allows < requests.length - 20, `a mix of ALLOW (${allows}) and refusals`);
  // And the reference engine agrees on a sample (it evaluates every candidate).
  const raw = referenceRawState(events);
  for (const request of requests.filter((_, i) => i % 9 === 0)) {
    const b = body(events, { ...request, head: state.head });
    same(A.authorizeState({ ...state }, b), referenceAuthorize(raw, b), `reference ${request.action} ${request.resource}`);
  }
});
