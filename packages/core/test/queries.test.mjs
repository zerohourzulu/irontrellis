/**
 * WHY / RESPONSIBLE / SURVIVES: conformance vectors, differential tests against
 * the Continuity 0.2 reference engine, the unsorted-grant crash fix and the
 * output-limit boundary.
 *
 * Reference calls cost ~0.25 s each (the reference replays every history it
 * touches), so the public-envelope differential runs on a bounded sample by
 * default; `QUERIES_DIFF=full` runs the complete grid. The answer-level
 * differential (reference projection functions over pre-replayed states) runs
 * the complete grid always.
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { referenceCore as ref, referenceCore02, referenceCore03, referencePath, viemAccounts, vectorsPath, DEMO_CASE } from "./reference.mjs";
const { createPortableReplayKernel } = await referenceCore02("core/portable-replay.ts");
const { captureBoundedCanonicalReplayBodyIncrementally } = await referenceCore02("core/canonical.ts");
const refSurvives = await referenceCore02("core/portable-query-survives.ts");
const refResponsibility = await referenceCore02("core/portable-query-responsibility.ts");
const mine = await import("../src/queries.ts");
const { hashCanonical } = await import("../src/hash.ts");
const authority = existsSync(new URL("../src/authority.ts", import.meta.url)) ? await import("../src/authority.ts") : undefined;
const FULL = process.env.QUERIES_DIFF === "full";

// ------------------------------------------------------------------ helpers

const revive = (_key, value) => (value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value);
const load = path => JSON.parse(readFileSync(referencePath(path), "utf8"), revive);
const sortKeys = value => Array.isArray(value) ? value.map(sortKeys)
  : value !== null && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sortKeys(value[key])])) : value;
/** JSON normalisation with bigint markers, keys sorted, undefined dropped. */
const norm = value => sortKeys(JSON.parse(JSON.stringify(value, (_k, x) => (typeof x === "bigint" ? { "$continuity.bigint": x.toString() } : x))));
const same = (actual, expected, label) => assert.deepEqual(norm(actual), norm(expected), label);

/** Reference replay kernel → reference state (undefined when not ACCEPTED). */
const refState = events => {
  const kernel = createPortableReplayKernel();
  const captured = captureBoundedCanonicalReplayBodyIncrementally(events, Object.freeze({ operationVersion: ref.PORTABLE_REPLAY_VERSION, events }), kernel.visit);
  if (captured.status !== "CAPTURED") return undefined;
  const result = kernel.finish();
  return result.status === "ACCEPTED" ? result.state : undefined;
};
/** Reference state → the IronTrellis ReplayState shape (same map names, plus the format fields). */
const toReplayState = state => ({
  ...state, format: "continuity-event/0.2", hashAlgorithm: "keccak256", signatureScheme: "eip191-personal-sign-keccak256",
  eventPositionsById: new Map(state.events.map((event, index) => [event.id, index])),
  runtimeSessions: new Map([...state.runtimeSessions].map(([id, session]) => [id, { ...session, credentialScheme: "eip191-personal-sign-keccak256" }])),
  anchors: [],
});
const stateCache = new WeakMap();
const stateOf = events => {
  let cached = stateCache.get(events);
  if (cached === undefined) { const state = refState(events); cached = { ref: state, mine: state === undefined ? undefined : toReplayState(state) }; stateCache.set(events, cached); }
  return cached;
};
const replayFn = events => {
  const state = refState(events);
  return state === undefined ? { status: "REJECTED", code: "TRANSITION_INVALID" } : { status: "ACCEPTED", state: toReplayState(state), head: state.head, eventCount: state.events.length };
};
const refAuthorize = (state, body) => ref.authorizePortable({ operationVersion: ref.PORTABLE_AUTHORIZATION_VERSION, events: state.events, ...body, authoritative: true });
const authorizers = authority === undefined ? [["reference-authorize", refAuthorize]] : [["authorizeState", (state, body) => authority.authorizeState(state, body)], ["reference-authorize", refAuthorize]];
const disclosure = kind => ref.portablePublicQueryDisclosure(kind);
const headOf = events => stateOf(events).ref.head;
let compared = 0, crashes = 0;
const isReferenceCrash = error => error instanceof TypeError && /Inconsistent internal responsibility projection inputs/.test(error.message);

/** A reference state whose stored grants carry sorted lists: what the reference's RESPONSIBLE needs to stop crashing (spec 03 §C.6). */
const normalizedRef = state => ({ ...state, authorities: new Map([...state.authorities].map(([id, record]) => {
  const constraints = { ...record.grant.constraints };
  for (const key of ["actions", "resources", "requiredIntersectionIds"]) constraints[key] = [...constraints[key]].sort(ref.compareProtocolStrings);
  return [id, { ...record, grant: { ...record.grant, constraints } }];
})) });
const callState = (kind, evaluation, observed, input, authorize) => kind === "SURVIVES" ? mine.survivesState(observed, input, evaluation) : mine[`${kind.toLowerCase()}State`](evaluation, observed, input, { authorize });

/** One public-envelope comparison: reference façade vs my State functions (every authorizer) and my façade (first authorizer). */
function diffEnvelope(kind, evaluationEvents, observedEvents, input, label, { facade = true, facadeOnly = false } = {}) {
  const request = { operationVersion: ref.PORTABLE_QUERY_VERSION, evaluationEvents, observedEvents, ...input, disclosure: input.disclosure ?? disclosure(kind) };
  const stateInput = { ...input, disclosure: request.disclosure };
  let expected;
  try { expected = ref[`${kind.toLowerCase()}Portable`](request); }
  catch (error) {
    if (!isReferenceCrash(error)) throw error;
    // The reference crashed on an unsorted grant. The oracle is the reference projection over a state whose stored
    // grants are normalised, inside the scope the reference's WHY reports for the same question.
    crashes += 1;
    const refEvaluation = stateOf(evaluationEvents).ref, refObserved = stateOf(observedEvents).ref, binding = input.consequentialBinding;
    const authorization = refAuthorize(refEvaluation, { expectedHistoryHead: refEvaluation.head, domain: input.authorizationDomain, policyVersion: refEvaluation.genesis.policyVersion,
      rootRecognitionPolicy: refEvaluation.genesis.rootRecognitionPolicy, request: input.request, evaluationTime: input.evaluationTime, consequential: binding !== undefined, ...(binding === undefined ? {} : { binding }) });
    const oracle = refResponsibility.derivePortableResponsibility(normalizedRef(refEvaluation), normalizedRef(refObserved), authorization);
    const why = ref.whyPortable({ ...request, disclosure: disclosure("WHY") });
    assert.equal(why.epistemicStatus, "ESTABLISHED", `${label}: reference WHY`);
    expected = { version: why.version, kind: "RESPONSIBLE", epistemicStatus: "ESTABLISHED", scope: { ...why.scope, disclosure: request.disclosure }, answer: oracle.answer };
  }
  if (!facadeOnly) {
    for (const [name, authorize] of kind === "SURVIVES" ? [["none", undefined]] : authorizers) {
      const actual = callState(kind, stateOf(evaluationEvents).mine, stateOf(observedEvents).mine, stateInput, authorize);
      same(actual, expected, `${label} [${kind} state/${name}]`);
      assert.ok(Object.isFrozen(actual) && Object.isFrozen(actual.scope), `${label}: frozen`);
    }
  }
  if (facade || facadeOnly) {
    const actual = kind === "SURVIVES" ? mine.survivesPortable(request, replayFn) : mine[`${kind.toLowerCase()}Portable`](request, replayFn, { authorize: authorizers[0][1] });
    same(actual, expected, `${label} [${kind} portable]`);
  }
  compared += 1;
  return expected;
}

/** Actors, actions and resources worth asking about in a history. */
function gridOf(events) {
  const state = stateOf(events).ref;
  const actors = [...state.agents.keys()], actions = new Set(), resources = new Set();
  for (const record of state.authorities.values()) {
    for (const action of record.grant.constraints.actions) actions.add(action);
    for (const resource of record.grant.constraints.resources) resources.add(resource);
  }
  actions.add("unknown-action"); resources.add("unknown:resource");
  const combos = [];
  for (const actor of [...actors, "ghost:agent"]) for (const action of actions) for (const resource of resources) combos.push({ actorId: actor, action, resource });
  return { actors, combos, domain: state.genesis.domain, head: state.head };
}
const sample = (list, count) => (FULL || list.length <= count ? list : list.filter((_item, index) => index % Math.ceil(list.length / count) === 0));

// ------------------------------------------------------------------ histories

const handover = load("tests/fixtures/handover-history.json");
const candidateFixtures = [
  ["handover", handover],
  ["handover-denied", load("tests/fixtures/handover-denied-history.json")],
  ["mandate", load("tests/fixtures/mandate-history.json")],
  ["simulated-r1", load("tests/fixtures/original-core/cases/core02-simulated-r1/export/history.json")],
  ["packet-r1", load("tests/fixtures/original-core/cases/core02-packet-r1/export/history.json")],
  ["legacy-handover", load("tests/fixtures/original-core/legacy-handover-history.json")],
  ["legacy-intake", load("tests/fixtures/original-core/legacy-intake-history.json")],
  ["demo", JSON.parse(readFileSync(`${DEMO_CASE}export/history.json`, "utf8"), revive)],
];
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"), revive);
const vectorHistories = { "first-look": handover, "no-review-power": candidateFixtures[1][1], mandate: candidateFixtures[2][1], "mandate-quantitative-only": candidateFixtures[2][1].slice(0, 6) };
const vectorEvents = vector => vectorHistories[vector.history.ref].slice(0, vector.history.eventCount);

// Ported from tests/generators.mjs (mulberry32; identical histories for identical seeds).
function makeRng(seed) {
  let state = seed >>> 0;
  const next = () => { state = (state + 0x6d2b79f5) >>> 0; let t = state; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  return {
    next, int: (min, max) => min + Math.floor(next() * (max - min + 1)), pick: list => list[Math.floor(next() * list.length)],
    subset(list, { min = 1, max = list.length } = {}) {
      const size = Math.max(min, Math.min(max, 1 + Math.floor(next() * list.length)));
      const chosen = [], pool = [...list];
      for (let taken = 0; taken < size && pool.length > 0; taken += 1) chosen.push(pool.splice(Math.floor(next() * pool.length), 1)[0]);
      return chosen.sort();
    },
    bool: (probability = 0.5) => next() < probability,
  };
}
const GENESIS_VERSIONS = Object.freeze({
  administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2", authorizationProofVersion: "continuity-authorization-proof/0.2",
  eventSchemaVersion: "continuity-event/0.2", queryEnvelopeVersion: "continuity-query-envelope/0.2", receiptSchemaVersion: "continuity-receipt/0.2",
  runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2", signatureScheme: "eip191-personal-sign-keccak256",
});
const ACTION_POOL = ["read", "write", "review", "collect", "escalate", "archive"], RESOURCE_POOL = ["alpha", "beta", "gamma", "delta"];
const constraints = ({ actions, resources, expiresAt, maxDelegationDepth, requiredIntersectionIds = [], notBefore }) => {
  const record = { actions: [...actions].sort(), expiresAt, maxDelegationDepth, quantitative: false, requiredIntersectionIds: [...requiredIntersectionIds].sort(), resources: [...resources].sort() };
  if (notBefore !== undefined) record.notBefore = notBefore;
  return record;
};
function generateHistory(seed) {
  const rng = makeRng(seed), id = `s${seed}`, qualify = name => `${name}:${id}`;
  const domain = Object.freeze({ chainId: "31337", deploymentId: `generated:${id}`, protocol: "continuity", verifyingContract: "0x0000000000000000000000000000000000003002", version: "0.2" });
  const events = []; let clock = 0;
  const emit = (type, name, data) => { events.push({ data, id: qualify(name), timestamp: clock, type }); clock += 1; };
  emit("DEPLOYMENT_INITIALIZED", "genesis", { adapterPolicyHash: ref.PORTABLE_ADAPTER_POLICY_HASH, canonicalLineageId: qualify("lineage"), domain, finality: "LOCAL_ONLY",
    globalPolicySourceId: qualify("policy-source"), policyVersion: `generated-policy:${id}/0.2`, rootRecognitionPolicy: ref.PORTABLE_ROOT_RECOGNITION_POLICY, timeSource: "EVENT_TIMESTAMP", versions: GENESIS_VERSIONS });
  const principalId = qualify("principal"), controllerId = qualify("controller");
  emit("PRINCIPAL_CREATED", "principal", { principalId });
  const agents = [];
  for (let index = 0; index < rng.int(2, 4); index += 1) { agents.push(qualify(`agent${index}`)); emit("AGENT_CREATED", `agent${index}`, { agentId: agents[index], controllerId, initialControlEpoch: 1, principalId }); }
  const roleId = qualify("role"), successionRuleId = qualify("succession");
  emit("ROLE_CREATED", "role", { exclusive: true, principalId, roleId });
  emit("SUCCESSION_RULE_DECLARED", "succession", { permittedEventTypes: ["AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"], predecessorAgentId: agents[0], principalId, roleId, ruleId: successionRuleId, successorAgentId: agents[1], trigger: "AGENT_TERMINATED" });
  emit("AGENT_APPOINTED", "appointment", { agentId: agents[0], principalId, roleId, roleTenureId: qualify("tenure0"), successionRuleId, tenureNumber: 1 });
  const actions = rng.subset(ACTION_POOL, { min: 2 }), resources = rng.subset(RESOURCE_POOL, { min: 1 }).map(qualify), EXPIRY = 10_000;
  const roots = [];
  for (let index = 0; index < rng.int(1, Math.min(3, agents.length)); index += 1) {
    const authorityId = qualify(`root${index}`);
    const grant = { authorityId, constraints: constraints({ actions: rng.subset(actions, { min: 1 }), resources: rng.subset(resources, { min: 1 }), expiresAt: EXPIRY, maxDelegationDepth: rng.int(1, 3) }),
      granteeId: agents[index % agents.length], grantorId: principalId, independent: true, kind: "PERMISSION", rootAuthorityId: authorityId };
    roots.push(grant); emit("AUTHORITY_GRANTED", `root${index}`, { grant });
  }
  const delegations = [];
  for (const parent of roots) {
    if (parent.constraints.maxDelegationDepth === 0 || !rng.bool(0.85)) continue;
    const granteeId = rng.pick(agents.filter(agent => agent !== parent.granteeId));
    if (granteeId === undefined) continue;
    const grant = { authorityId: qualify(`deleg${delegations.length}`), constraints: constraints({ actions: rng.subset(parent.constraints.actions, { min: 1 }), resources: rng.subset(parent.constraints.resources, { min: 1 }),
      expiresAt: rng.bool(0.5) ? parent.constraints.expiresAt : parent.constraints.expiresAt - 100, maxDelegationDepth: Math.max(0, parent.constraints.maxDelegationDepth - 1), requiredIntersectionIds: parent.constraints.requiredIntersectionIds }),
      granteeId, grantorId: parent.granteeId, independent: true, kind: "PERMISSION", parentAuthorityId: parent.authorityId, rootAuthorityId: parent.rootAuthorityId };
    delegations.push(grant); emit("AUTHORITY_GRANTED", `deleg${delegations.length - 1}`, { grant });
  }
  const intersecting = [];
  if (roots.length > 0 && rng.bool(0.6)) {
    const base = roots[0], partnerId = qualify("partner");
    const partner = { authorityId: partnerId, constraints: constraints({ actions: rng.subset(actions, { min: 1 }), resources: [...resources], expiresAt: EXPIRY, maxDelegationDepth: 0 }), granteeId: base.granteeId, grantorId: principalId, independent: true, kind: "PERMISSION", rootAuthorityId: partnerId };
    emit("AUTHORITY_GRANTED", "partner", { grant: partner }); intersecting.push(partner);
    const gatedId = qualify("gated");
    const gated = { authorityId: gatedId, constraints: constraints({ actions: [`gate-only-${id}`], resources: [...resources], expiresAt: EXPIRY, maxDelegationDepth: 0, requiredIntersectionIds: [partnerId] }), granteeId: base.granteeId, grantorId: principalId, independent: true, kind: "PERMISSION", rootAuthorityId: gatedId };
    emit("AUTHORITY_GRANTED", "gated", { grant: gated }); intersecting.push(gated);
  }
  const allGrants = [...roots, ...delegations, ...intersecting];
  if (rng.bool(0.5)) {
    emit("CONTROL_EPOCH_ADVANCED", "epoch", { agentId: agents[0], controllerId, fromEpoch: 1, toEpoch: 2 });
    emit("AGENT_TERMINATED", "terminate", { agentId: agents[0], principalId, roleId, roleTenureId: qualify("tenure0"), successionRuleId });
    emit("ROLE_TRANSFERRED", "transfer", { fromAgentId: agents[0], fromRoleTenureId: qualify("tenure0"), principalId, roleId, successionRuleId, toAgentId: agents[1], toRoleTenureId: qualify("tenure1"), toTenureNumber: 2, transferKind: "SUCCESSION" });
  }
  let revoked = 0;
  for (const grant of allGrants) {
    if (!rng.bool(0.35)) continue;
    revoked += 1; emit("AUTHORITY_REVOKED", `revoke${revoked}`, { authorityId: grant.authorityId, revokerId: grant.parentAuthorityId === undefined ? principalId : grant.grantorId });
  }
  return events;
}
const generated = Array.from({ length: 30 }, (_x, index) => [`seed-${index + 1}`, generateHistory(index + 1)]);
/**
 * Review block 3 (SURVIVES event index): a generated history followed by a chain of REASSIGNMENT transfers, so a tenure
 * is opened by one ROLE_TRANSFERRED and closed by a later one. Its evidence is the union of several `where` lookups
 * (ROLE_CREATED, AGENT_APPOINTED, AGENT_UNAPPOINTED, ROLE_TRANSFERRED from, ROLE_TRANSFERRED to) whose concatenation
 * is out of history order before `positionsIn` sorts it. (Removing that sort turned out to be an equivalent mutant: the
 * projection writer sorts every row's evidence in `finish`, and the output budget is all or nothing. These histories
 * keep chained transfers, which the generator above never produces, in the reference differential.)
 */
function generateReassignedHistory(seed) {
  const events = generateHistory(seed);
  let clock = events[events.length - 1].timestamp + 1;
  const id = `s${seed}`, qualify = (name) => `${name}:${id}`;
  const terminated = new Set(events.filter((event) => event.type === "AGENT_TERMINATED").map((event) => event.data.agentId));
  const agents = events.filter((event) => event.type === "AGENT_CREATED").map((event) => event.data.agentId).filter((agent) => !terminated.has(agent));
  const transfer = [...events].reverse().find((event) => event.type === "ROLE_TRANSFERRED");
  let holder = transfer === undefined ? qualify("agent0") : transfer.data.toAgentId;
  let tenure = transfer === undefined ? qualify("tenure0") : transfer.data.toRoleTenureId;
  let number = transfer === undefined ? 1 : transfer.data.toTenureNumber;
  const principalId = qualify("principal"), roleId = qualify("role");
  for (const extra of ["extra0", "extra1"]) { // enough active agents for a chain, whatever the generator terminated
    events.push({ data: { agentId: qualify(extra), controllerId: qualify("controller"), initialControlEpoch: 1, principalId }, id: qualify(extra), timestamp: clock, type: "AGENT_CREATED" });
    clock += 1;
    agents.push(qualify(extra));
  }
  for (let step = 0; step < 3; step += 1) {
    const next = agents.filter((agent) => agent !== holder)[step % Math.max(1, agents.length - 1)];
    if (next === undefined) break;
    const toTenure = qualify(`reassigned${step}`);
    events.push({ data: { fromAgentId: holder, fromRoleTenureId: tenure, principalId, roleId, toAgentId: next, toRoleTenureId: toTenure, toTenureNumber: number + 1, transferKind: "REASSIGNMENT" },
      id: qualify(`reassign${step}`), timestamp: clock, type: "ROLE_TRANSFERRED" });
    clock += 1;
    holder = next, tenure = toTenure, number += 1;
  }
  return events;
}
const reassigned = Array.from({ length: 6 }, (_x, index) => [`reassigned-seed-${index + 1}`, generateReassignedHistory(index + 1)]);

// Core 0.3 local-owner histories: a signed handover with a duty (lifecycle) and E5/E6 attempt-duty histories.
const { generatePrivateKey, privateKeyToAccount } = viemAccounts;
const sign = account => hash => account.signMessage({ message: { raw: hash } });
const tempDirs = [];
const tempDir = () => { const dir = mkdtempSync(join(tmpdir(), "irontrellis-queries-")); tempDirs.push(dir); return dir; };
process.on("exit", () => { for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true }); });
async function buildLifecycleHistory() {
  const { createLocalDomain, createLocalOwner } = await referenceCore03("local-owner.ts");
  const { openLocalSimulation, commitTerms } = await referenceCore03("simulation.ts");
  const { openLocalRuntime } = await referenceCore03("runtime.ts");
  const a = privateKeyToAccount(generatePrivateKey()), b = privateKeyToAccount(generatePrivateKey());
  let tick = 100;
  const config = { historyFile: join(tempDir(), "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick };
  const owner = createLocalOwner(config);
  for (const id of ["bea", "alex"]) owner.createAgent({ id });
  owner.createRole({ id: "reviewer" }); owner.declareSuccession({ id: "handover", from: "bea", to: "alex", role: "reviewer" });
  owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  owner.admitRuntime({ session: "session:bea", agent: "bea", epoch: 1, key: "key:bea", address: a.address, expiresAt: 200 });
  owner.admitRuntime({ session: "session:alex", agent: "alex", epoch: 1, key: "key:alex", address: b.address, expiresAt: 200 });
  owner.grant({ id: "collect", to: "bea", actions: ["OBLIGATE", "read"], resources: ["incident:42"], expiresAt: 180 });
  owner.grant({ id: "review", to: "alex", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: 180 });
  const options = { ...config, session: "session:bea", signHash: sign(a) };
  const op = { id: "operation:42", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: "Synthetic incident review" }) };
  const sim = openLocalSimulation(options), runtime = openLocalRuntime(options);
  // A second branch runs the same operation from the same prefix at a later time: a genuine same-intent fork.
  const otherFile = join(tempDir(), "history.jsonl");
  copyFileSync(config.historyFile, otherFile);
  await openLocalSimulation({ ...options, historyFile: otherFile, now: () => 101 }).run(op);
  const forkB = (await referenceCore03("local-owner.ts")).openLocalOwner({ ...config, historyFile: otherFile }).exportHistory();
  await sim.run(op);
  const forkA = owner.exportHistory();
  await sim.recordReceipt(op);
  await runtime.obligate({ id: "duty:42", operation: op.id, description: "Review the collected material.", deadline: 170, succession: "handover", reviewAuthority: "review" });
  tick = 110;
  owner.succeed({ id: "handover:42", rule: "handover", fromAgent: "bea", fromTenure: "shift:1", toAgent: "alex", toTenure: "shift:2", role: "reviewer", number: 2 });
  owner.grant({ id: "assign", to: "alex", actions: ["ASSIGN_PERFORMANCE"], resources: ["duty:42"], expiresAt: 180 });
  await openLocalRuntime({ ...options, session: "session:alex", signHash: sign(b) }).assign({ id: "assign:42", obligation: "duty:42" });
  return { events: owner.exportHistory(), fork: [forkA, forkB] };
}
async function buildAttemptHistory(e5) {
  const { createLocalAttemptOwner, createLocalReviewOwner, createLocalDomain } = await referenceCore03("local-owner.ts");
  const { openLocalExecution, commitTerms } = await referenceCore03("execution.ts");
  const { openLocalAttemptRecorder } = await referenceCore03("attempts.ts");
  const { stateOf: refStateOf } = await referenceCore03("local-store.ts");
  const first = privateKeyToAccount(`0x${"11".repeat(32)}`), second = privateKeyToAccount(`0x${"22".repeat(32)}`);
  let at = 100;
  const config = { historyFile: join(tempDir(), "history.jsonl"), domain: createLocalDomain(), owner: "owner", controller: "controller", now: () => at };
  const owner = (e5 ? createLocalAttemptOwner : createLocalReviewOwner)(config);
  owner.createAgent({ id: "first" }); owner.createRole({ id: "operator" });
  owner.appoint({ agent: "first", role: "operator", tenure: "tenure:1", number: 1 });
  owner.admitRuntime({ agent: "first", session: "session:first", epoch: 1, key: "key:first", address: first.address, expiresAt: 2000 });
  owner.grant({ id: "execute", to: "first", actions: ["make-fixture"], resources: ["synthetic"], expiresAt: 1000, maxAmount: 50n, maxCumulativeAmount: 50n, maxTransactions: 1 });
  const options = { ...config, session: "session:first", signHash: sign(first) };
  const unknown = input => { const identity = ref.derivePortableAdapterIdentity(input); return { status: "OUTCOME_UNKNOWN", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }; };
  const policy = e5 ? ref.PORTABLE_ADAPTER_POLICY_E5_HASH : ref.PORTABLE_ADAPTER_POLICY_E6_HASH;
  const adapter = { adapterProfile: ref.approvedPortableAdapterProfileForPolicy(policy, ref.REMOTE_SERVICE_REPORT_ADAPTER_ID), submit: async input => unknown(input), reconcile: unknown };
  await openLocalExecution(options, adapter, "REMOTE_REPORT").run({ id: "job:1", action: "make-fixture", resource: "synthetic", role: "operator", tenure: "tenure:1", amount: 50n, counterparty: "synthetic:vendor", termsCommitment: commitTerms({ units: "SYNTHETIC" }) });
  // Core 0.3 records grant lists as given; the E5 history keeps this unsorted list so the reference crash path is exercised.
  const recordActions = e5 ? ["OBSERVE_OUTCOME", "CREATE_ATTEMPT_DUTY", "ASSIGN_ATTEMPT_DUTY"] : ["ASSIGN_ATTEMPT_DUTY", "CREATE_ATTEMPT_DUTY", "OBSERVE_OUTCOME"];
  owner.grant({ id: "records:first", to: "first", actions: recordActions, resources: ["job:1"], expiresAt: 1000 });
  owner.grant({ id: "close:first", to: "first", actions: ["CLOSE_ATTEMPT_DUTY"], resources: ["job:1"], expiresAt: 1000 });
  const recorder = openLocalAttemptRecorder(options);
  await recorder.createDuty({ id: "investigate", intent: "job:1", description: "Investigate retained evidence; no fulfillment claim", deadline: 2000 });
  const acknowledgment = digest => ref.createRemoteServiceReportAcknowledgment(refStateOf(owner.exportHistory()).intentAdmissions.get("job:1").adapterIdentity, digest);
  await recorder.observe({ id: "z", intent: "job:1", acknowledgment: acknowledgment(`0x${"b".repeat(64)}`) });
  await recorder.observe({ id: "a", intent: "job:1", acknowledgment: acknowledgment(`0x${"c".repeat(64)}`) });
  if (!e5) await recorder.reviewDuty({ id: "review:1", duty: "investigate", summaryDigest: `0x${"a".repeat(64)}` });
  owner.createAgent({ id: "second" });
  owner.declareSuccession({ id: "succession", from: "first", to: "second", role: "operator" });
  at = 120;
  owner.succeed({ id: "handover", rule: "succession", fromAgent: "first", fromTenure: "tenure:1", toAgent: "second", toTenure: "tenure:2", role: "operator", number: 2 });
  owner.admitRuntime({ agent: "second", session: "session:second", epoch: 1, key: "key:second", address: second.address, expiresAt: 2000 });
  owner.grant({ id: "records:second", to: "second", actions: recordActions, resources: ["job:1"], expiresAt: 1000 });
  owner.grant({ id: "close:second", to: "second", actions: ["CLOSE_ATTEMPT_DUTY"], resources: ["job:1"], expiresAt: 1000 });
  const next = openLocalAttemptRecorder({ ...options, session: "session:second", signHash: sign(second) });
  await next.assignDuty({ id: "to-second", duty: "investigate" });
  if (!e5) await next.reviewDuty({ id: "second-review", duty: "investigate", summaryDigest: `0x${"a".repeat(64)}` });
  return owner.exportHistory();
}
const lifecycle = await buildLifecycleHistory();
const core03 = [
  ["core-0.3-lifecycle", lifecycle.events],
  ["core-0.3-attempts-e5", await buildAttemptHistory(true)],
  ["core-0.3-attempts-e6", await buildAttemptHistory(false)],
];

// The two "legacy-*" exports predate the 0.2.2 schema and no longer replay in the reference; they are skipped when they do not.
for (const [name, events] of [...core03, ...generated, ...reassigned]) assert.ok(stateOf(events).ref !== undefined, `${name} replays in the reference`);
for (const [name, events] of reassigned) assert.ok(events.filter((event) => event.type === "ROLE_TRANSFERRED").length >= 3, `${name} chains transfers`);
const fixtures = candidateFixtures.filter(([, events]) => stateOf(events).ref !== undefined);
assert.ok(fixtures.length >= 6, "fixture histories replay in the reference");
const allHistories = [...fixtures, ...core03, ...generated, ...reassigned];

/** The admitted binding of every TRANSACTION_INTENT_ADMITTED in a history, with the prefix it was signed against. */
const admittedBindings = events => events.flatMap((event, position) => {
  if (event.type !== "TRANSACTION_INTENT_ADMITTED") return [];
  const proof = event.data.authorizationProof;
  const binding = { runtimeSessionId: proof.runtimeSessionId, credentialKeyId: proof.credentialKeyId, controlEpoch: proof.controlEpoch, roleId: proof.roleId,
    roleTenureId: proof.roleTenureId, intentId: proof.intentId, nonce: proof.nonce, runtimeSignature: event.data.runtimeSignature };
  return [{ position, prefix: events.slice(0, position), request: proof.request, domain: proof.domain, binding, evaluationTime: event.data.evaluationTime }];
});

// ------------------------------------------------------------------ 1. conformance vectors

const projectSurvives = result => !Object.hasOwn(result, "answer") ? { established: false, code: result.code, epistemicStatus: result.epistemicStatus } : {
  established: true, exists: result.answer.exists, lifecycleStatus: result.answer.lifecycleStatus,
  obligationIds: result.answer.obligations.map(row => row.obligationId).sort(),
  currentAssignments: result.answer.currentPerformanceAssignments.map(row => ({ obligationId: row.obligationId, assigneeId: row.assigneeId, successionRuleId: row.successionRuleId ?? null })),
  currentRoleTenureCount: result.answer.currentRoleTenures.length, transferredRoleTenureCount: result.answer.transferredRoleTenures.length,
  invalidatedAuthorityIds: result.answer.invalidatedAuthorityDependencies.map(row => row.authorityId).sort(),
  unresolvedIntentIds: result.answer.unresolvedIntents.map(row => row.intentId).sort(),
};
test("conformance: every survives vector projects to its expectation (state and portable paths)", () => {
  const survivesVectors = vectors.filter(vector => vector.kind === "survives");
  assert.equal(survivesVectors.length, 4);
  for (const vector of survivesVectors) {
    const events = vectorEvents(vector);
    const input = { targetAgentId: vector.input.targetAgentId, evaluationTime: vector.input.evaluationTime, disclosure: mine.publicQueryDisclosure("SURVIVES") };
    assert.deepEqual(projectSurvives(mine.survivesState(stateOf(events).mine, input)), vector.expect, vector.id);
    assert.deepEqual(projectSurvives(mine.survivesPortable({ operationVersion: mine.QUERY_VERSION, observedEvents: events, ...input }, replayFn)), vector.expect, `${vector.id} (portable)`);
  }
});

test("field paths and public disclosures match the reference", () => {
  assert.equal(mine.QUERY_ANSWER_FIELD_PATHS.length, 485);
  assert.equal(hashCanonical(mine.QUERY_ANSWER_FIELD_PATHS, "keccak256"), "0xcf32ec76f16d5729d18b566261110a21fae4d95590a2e6dd790a9b4a4d8e244e");
  for (const kind of ["WHY", "RESPONSIBLE", "SURVIVES"]) same(mine.publicQueryDisclosure(kind), ref.portablePublicQueryDisclosure(kind), kind);
  same(mine.QUERY_EXTERNAL_ASSUMPTIONS, ref.PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS);
  assert.equal(mine.QUERY_VERSION, ref.PORTABLE_QUERY_VERSION);
});

// ------------------------------------------------------------------ 2. differential: answers over the complete grid (fast path)

test("differential: SURVIVES and RESPONSIBLE projections agree with the reference over every combination", () => {
  let checked = 0;
  for (const [name, events] of allHistories) {
    const { ref: refS, mine: myS } = stateOf(events);
    const grid = gridOf(events);
    const times = [grid.head.canonicalTime, grid.head.canonicalTime + 5, 10_000];
    for (const actor of [...grid.actors, "ghost:agent"]) for (const time of times) {
      same(mine.deriveSurvives(myS, actor, time), refSurvives.derivePortableSurvives(refS, actor, time), `${name} survives ${actor}@${time}`); checked += 1;
    }
    if (authority === undefined) continue;
    for (const combo of grid.combos) for (const time of times.slice(0, 2)) {
      const body = { expectedHistoryHead: refS.head, domain: grid.domain, policyVersion: refS.genesis.policyVersion, rootRecognitionPolicy: refS.genesis.rootRecognitionPolicy,
        request: { ...combo, claimedAt: time }, evaluationTime: time, consequential: false };
      const authorization = authority.authorizeState(myS, body);
      if (authorization.decision === "INDETERMINATE") continue;
      const actual = mine.deriveResponsibility(myS, myS, authorization);
      let expected;
      try { expected = refResponsibility.derivePortableResponsibility(refS, refS, authorization); }
      catch (error) {
        if (!isReferenceCrash(error)) throw error;
        crashes += 1;
        expected = refResponsibility.derivePortableResponsibility(normalizedRef(refS), normalizedRef(refS), authorization);
      }
      same(actual, expected, `${name} responsible ${JSON.stringify(combo)}@${time}`);
      checked += 1;
    }
  }
  assert.ok(checked > 500, `checked ${checked}`);
});

// ------------------------------------------------------------------ 3. differential: public envelopes (reference façade vs mine)

test("differential: WHY / RESPONSIBLE / SURVIVES envelopes on the fixture and Core 0.3 histories", () => {
  for (const [name, events] of [...fixtures, ...core03]) {
    const grid = gridOf(events), head = grid.head;
    const prefix = events.slice(0, Math.max(2, events.length - 3));
    const combos = sample(grid.combos, 8);
    combos.forEach((combo, index) => {
      const time = index % 2 === 0 ? head.canonicalTime : head.canonicalTime + 7;
      const input = { authorizationDomain: grid.domain, request: { ...combo, claimedAt: time }, evaluationTime: time };
      for (const kind of ["WHY", "RESPONSIBLE"]) {
        diffEnvelope(kind, events, events, input, `${name} same-head ${JSON.stringify(combo)}@${time}`, { facade: index < 2 });
        if (index % 4 === 0) {
          const prefixHead = headOf(prefix), at = Math.max(prefixHead.canonicalTime, time);
          diffEnvelope(kind, prefix, events, { ...input, request: { ...combo, claimedAt: at }, evaluationTime: at }, `${name} extension ${JSON.stringify(combo)}@${at}`, { facade: false });
        }
      }
    });
    for (const actor of sample([...grid.actors, "ghost:agent"], 3)) {
      for (const time of [head.canonicalTime, head.canonicalTime + 7]) diffEnvelope("SURVIVES", events, events, { targetAgentId: actor, evaluationTime: time }, `${name} survives ${actor}@${time}`, { facade: time === head.canonicalTime });
      const at = Math.max(headOf(prefix).canonicalTime, head.canonicalTime);
      diffEnvelope("SURVIVES", prefix, events, { targetAgentId: actor, evaluationTime: at }, `${name} survives extension ${actor}`, { facade: false });
    }
  }
});

test("differential: consequential bindings (same head and strict extension) on every admitted intent", () => {
  for (const [name, events] of [...fixtures, ...core03]) {
    for (const admitted of admittedBindings(events)) {
      const input = { authorizationDomain: admitted.domain, request: admitted.request, evaluationTime: admitted.evaluationTime, consequentialBinding: admitted.binding };
      for (const kind of ["WHY", "RESPONSIBLE"]) {
        const sameHead = diffEnvelope(kind, admitted.prefix, admitted.prefix, input, `${name} binding same-head @${admitted.position}`);
        const extension = diffEnvelope(kind, admitted.prefix, events, input, `${name} binding extension @${admitted.position}`);
        if (kind === "WHY" && sameHead.epistemicStatus === "ESTABLISHED" && sameHead.answer.authorization.decision === "ALLOW") {
          assert.equal(sameHead.answer.presentConsequentialUse, true);
          assert.equal(extension.answer.presentConsequentialUse, false);
        }
        // The binding evaluated against a history that already contains the admission is bound to an older head.
        diffEnvelope(kind, events, events, input, `${name} binding post-admission @${admitted.position}`, { facade: false });
      }
      diffEnvelope("WHY", admitted.prefix, admitted.prefix, { ...input, consequentialBinding: { ...admitted.binding, intentId: undefined, nonce: undefined, credentialKeyId: undefined } }, `${name} binding without intent`, { facade: false });
    }
  }
});

test("differential: generated histories (seeds 1..30), same head and strict extension", () => {
  for (const [name, events] of generated) {
    const grid = gridOf(events), head = grid.head;
    const prefix = events.slice(0, events.length - 2);
    const combos = sample(grid.combos, FULL ? Infinity : 4);
    combos.forEach((combo, index) => {
      const times = FULL ? [head.canonicalTime, head.canonicalTime + 5] : [index % 2 === 0 ? head.canonicalTime : head.canonicalTime + 5];
      for (const time of times) {
        const input = { authorizationDomain: grid.domain, request: { ...combo, claimedAt: time }, evaluationTime: time };
        for (const kind of ["WHY", "RESPONSIBLE"]) {
          diffEnvelope(kind, events, events, input, `${name} ${JSON.stringify(combo)}@${time}`, { facade: index === 0 });
          if (FULL || index % 2 === 0) diffEnvelope(kind, prefix, events, input, `${name} extension ${JSON.stringify(combo)}@${time}`, { facade: false });
        }
      }
    });
    const actor = grid.actors[0];
    diffEnvelope("SURVIVES", events, events, { targetAgentId: actor, evaluationTime: head.canonicalTime }, `${name} survives ${actor}`, { facade: false });
    if (FULL) for (const each of grid.actors.slice(1)) diffEnvelope("SURVIVES", prefix, events, { targetAgentId: each, evaluationTime: head.canonicalTime }, `${name} survives extension ${each}`, { facade: false });
  }
});

test("differential: vector histories (prefixes) answer identically", () => {
  for (const vector of vectors.filter(item => item.history !== undefined)) {
    const events = vectorEvents(vector);
    if (vector.kind === "survives") { diffEnvelope("SURVIVES", events, events, { targetAgentId: vector.input.targetAgentId, evaluationTime: vector.input.evaluationTime }, vector.id); continue; }
    const input = { authorizationDomain: vector.input.domain, request: vector.input.request, evaluationTime: vector.input.evaluationTime };
    diffEnvelope(vector.id.includes("quantitative") ? "WHY" : "RESPONSIBLE", events, events, input, vector.id, { facade: false });
  }
});

// ------------------------------------------------------------------ 4. envelope failure paths

test("differential: failure envelopes (time, disclosure, forks, foreign versions, malformed input)", () => {
  const events = handover, head = headOf(events), domain = events[0].data.domain;
  const request = { actorId: "b:first-look", action: "record-review-progress", resource: "obligation:first-look", claimedAt: 25 };
  const why = { authorizationDomain: domain, request, evaluationTime: 25 };
  // Causal time: behind the head, float, -0, string, bigint.
  for (const time of [24, 25.5, -0, "25", 25n]) {
    diffEnvelope("WHY", events, events, { ...why, evaluationTime: time }, `time ${String(time)}`, { facade: false });
    diffEnvelope("SURVIVES", events, events, { targetAgentId: "a:first-look", evaluationTime: time }, `survives time ${String(time)}`, { facade: false });
  }
  // Disclosure: withheld core field, unsorted list, missing needed path, empty list, extra keys.
  const pub = disclosure("WHY");
  for (const bad of [{ ...pub, withheldFields: ["answer"] }, { ...pub, includedFields: [...pub.includedFields].reverse() }, { ...pub, includedFields: pub.includedFields.filter(p => p !== "authorization.proof.request.claimedAt") },
    { ...pub, includedFields: [] }, { ...pub, extra: true }, { ...pub, withheldFields: ["zzz"] }, { ...pub, includedFields: [...pub.includedFields, "zzz"] }]) {
    diffEnvelope("WHY", events, events, { ...why, disclosure: bad }, "disclosure variant", { facade: false });
  }
  same(mine.survivesState(stateOf(events).mine, { targetAgentId: "a:first-look", evaluationTime: 25, disclosure: { ...disclosure("SURVIVES"), includedFields: disclosure("SURVIVES").includedFields.filter(p => p !== "exists") } }).code, "DISCLOSURE_INVALID");
  // A disclosure failure is reported after a causal-time failure.
  diffEnvelope("WHY", events, events, { ...why, evaluationTime: 1, disclosure: { ...pub, withheldFields: ["answer"] } }, "time before disclosure", { facade: false });
  // Observed shorter than evaluation → UNVERIFIED with the two heads; a fork → the divergent pair.
  diffEnvelope("WHY", events, events.slice(0, 13), why, "observed shorter");
  diffEnvelope("SURVIVES", events, events.slice(0, 13), { targetAgentId: "a:first-look", evaluationTime: 25 }, "survives observed shorter");
  const forkA = [...events.slice(0, 13), { ...events[13], id: "fork:a", type: "AGENT_CREATED", data: { agentId: "fa:first-look", controllerId: "controller:first-look", initialControlEpoch: 1, principalId: "principal:first-look" } }];
  const forkB = [...events.slice(0, 13), { ...events[13], id: "fork:b", type: "AGENT_CREATED", data: { agentId: "fb:first-look", controllerId: "controller:first-look", initialControlEpoch: 1, principalId: "principal:first-look" } }];
  diffEnvelope("WHY", forkA, forkB, { ...why, request: { ...request, claimedAt: 13 }, evaluationTime: 13 }, "fork why");
  diffEnvelope("SURVIVES", forkA, forkB, { targetAgentId: "a:first-look", evaluationTime: 13 }, "fork survives");
  diffEnvelope("SURVIVES", forkA, forkB, { targetAgentId: "a:first-look", evaluationTime: 12 }, "fork survives below observed head", { facade: false });
  // Same-intent fork: two branches admitting the same intent at different times → EVIDENCE_DISPUTED for the actor / the binding.
  const [forkLeft, forkRight] = lifecycle.fork, admitted = admittedBindings(forkLeft)[0];
  assert.ok(admitted !== undefined && admittedBindings(forkRight)[0]?.position === admitted.position);
  const disputed = diffEnvelope("SURVIVES", forkLeft, forkRight, { targetAgentId: "bea", evaluationTime: 200 }, "same-intent fork survives");
  assert.equal(disputed.code, "EVIDENCE_DISPUTED"); assert.equal(disputed.epistemicStatus, "DISPUTED"); assert.equal(disputed.evidence.length, 2);
  assert.equal(diffEnvelope("SURVIVES", forkLeft, forkRight, { targetAgentId: "alex", evaluationTime: 200 }, "same-intent fork unrelated target").code, "HISTORY_RELATION_UNVERIFIED");
  const forkWhy = { authorizationDomain: admitted.domain, request: admitted.request, evaluationTime: 200 };
  assert.equal(diffEnvelope("WHY", forkLeft, forkRight, { ...forkWhy, consequentialBinding: admitted.binding }, "same-intent fork why binding").code, "EVIDENCE_DISPUTED");
  assert.equal(diffEnvelope("RESPONSIBLE", forkLeft, forkRight, forkWhy, "same-intent fork responsible no binding").code, "HISTORY_RELATION_UNVERIFIED");
  // Same-intent conflicts on the parent history's admission when the branches merely differ later.
  diffEnvelope("RESPONSIBLE", lifecycle.events, forkRight, { ...forkWhy, consequentialBinding: admitted.binding }, "lifecycle vs fork");
  // Foreign versions → EVIDENCE_UNAVAILABLE; malformed / unsupported input.
  const foreign = [{ ...events[0], data: { ...events[0].data, versions: { ...events[0].data.versions, eventSchemaVersion: "other/9" } } }, ...events.slice(1)];
  diffEnvelope("SURVIVES", foreign, events, { targetAgentId: "a:first-look", evaluationTime: 25 }, "foreign evaluation", { facadeOnly: true });
  diffEnvelope("WHY", events, foreign, why, "foreign observed", { facadeOnly: true });
  for (const [label, input] of [
    ["not an object", 5], ["array", []], ["missing version", { observedEvents: events }],
    ["wrong version", { operationVersion: "continuity-query-envelope/0.1", observedEvents: events, targetAgentId: "a", evaluationTime: 25, disclosure: disclosure("SURVIVES") }],
    ["unknown key", { operationVersion: mine.QUERY_VERSION, observedEvents: events, targetAgentId: "a", evaluationTime: 25, disclosure: disclosure("SURVIVES"), extra: 1 }],
    ["binding on survives", { operationVersion: mine.QUERY_VERSION, observedEvents: events, targetAgentId: "a", evaluationTime: 25, disclosure: disclosure("SURVIVES"), consequentialBinding: {} }],
    ["missing evaluation events", { operationVersion: mine.QUERY_VERSION, observedEvents: events, authorizationDomain: domain, request, evaluationTime: 25, disclosure: pub }],
    ["object time", { operationVersion: mine.QUERY_VERSION, observedEvents: events, targetAgentId: "a", evaluationTime: {}, disclosure: disclosure("SURVIVES") }],
    ["empty history", { operationVersion: mine.QUERY_VERSION, observedEvents: [], targetAgentId: "a", evaluationTime: 25, disclosure: disclosure("SURVIVES") }],
    ["non-genesis first", { operationVersion: mine.QUERY_VERSION, observedEvents: events.slice(1), targetAgentId: "a", evaluationTime: 25, disclosure: disclosure("SURVIVES") }],
    ["broken replay", { operationVersion: mine.QUERY_VERSION, observedEvents: [events[0], events[2]], targetAgentId: "a", evaluationTime: 25, disclosure: disclosure("SURVIVES") }],
    ["bad request", { operationVersion: mine.QUERY_VERSION, evaluationEvents: events, observedEvents: events, authorizationDomain: domain, request: { ...request, extra: 1 }, evaluationTime: 25, disclosure: pub }],
    ["bad domain", { operationVersion: mine.QUERY_VERSION, evaluationEvents: events, observedEvents: events, authorizationDomain: { ...domain, chainId: "x" }, request, evaluationTime: 25, disclosure: pub }],
    ["other domain", { operationVersion: mine.QUERY_VERSION, evaluationEvents: events, observedEvents: events, authorizationDomain: { ...domain, chainId: "1" }, request, evaluationTime: 25, disclosure: pub }],
    ["getter", Object.defineProperty({ operationVersion: mine.QUERY_VERSION, observedEvents: events, evaluationTime: 25, disclosure: disclosure("SURVIVES") }, "targetAgentId", { get: () => "a", enumerable: true })],
  ]) {
    const kind = input?.authorizationDomain !== undefined ? "WHY" : "SURVIVES";
    same(mine[`${kind.toLowerCase()}Portable`](input, replayFn, { authorize: authorizers[0][1] }), ref[`${kind.toLowerCase()}Portable`](input), label);
    compared += 1;
  }
});

// ------------------------------------------------------------------ 5. the unsorted-grant crash (spec 03 §C.6)

test("RESPONSIBLE never throws on unsorted grant lists and answers as the sorted history does", () => {
  const grant = (actions, resources) => ({ authorityId: "zeta-authority:first-look", constraints: { actions, expiresAt: 1000, maxDelegationDepth: 0, quantitative: false, requiredIntersectionIds: [], resources },
    granteeId: "b:first-look", grantorId: "principal:first-look", independent: true, kind: "PERMISSION", rootAuthorityId: "zeta-authority:first-look" });
  const append = g => [...handover, { data: { grant: g }, id: "first-look:zeta-authority", timestamp: 26, type: "AUTHORITY_GRANTED" }];
  const domain = handover[0].data.domain;
  for (const [unsorted, sorted] of [
    [grant(["zeta", "alpha"], ["resource:first-look"]), grant(["alpha", "zeta"], ["resource:first-look"])],
    [grant(["alpha", "zeta"], ["resource:first-look", "aaa:first-look"]), grant(["alpha", "zeta"], ["aaa:first-look", "resource:first-look"])],
  ]) {
    const unsortedEvents = append(unsorted), sortedEvents = append(sorted);
    assert.ok(stateOf(unsortedEvents).ref !== undefined && stateOf(sortedEvents).ref !== undefined);
    const input = { authorizationDomain: domain, request: { actorId: "b:first-look", action: "zeta", resource: "resource:first-look", claimedAt: 26 }, evaluationTime: 26, disclosure: disclosure("RESPONSIBLE") };
    const portable = { operationVersion: mine.QUERY_VERSION, evaluationEvents: unsortedEvents, observedEvents: unsortedEvents, ...input };
    assert.throws(() => ref.responsiblePortable(portable), /Inconsistent internal responsibility projection inputs/);
    const expected = ref.responsiblePortable({ ...portable, evaluationEvents: sortedEvents, observedEvents: sortedEvents });
    assert.equal(expected.epistemicStatus, "ESTABLISHED");
    assert.deepEqual(expected.answer.attributions.map(row => [row.kind, row.subjectId]),
      [["ACTOR", "b:first-look"], ["DECLARED_PRINCIPAL", "principal:first-look"], ["MANDATOR", "principal:first-look"], ["AUTHORITY_SOURCE", "zeta-authority:first-look"], ["CONTROLLER", "controller:first-look"]]);
    // Everything but the heads/hashes must agree: the evidence only uses grant positions, which do not depend on list order.
    const strip = envelope => norm({ ...envelope, scope: { ...envelope.scope, evaluationHead: null, observedHead: null }, answer: { ...envelope.answer,
      attributions: envelope.answer.attributions.map(row => ({ ...row, evidence: row.evidence.map(e => ({ ...e, historyHash: e.position === 26 ? null : e.historyHash })) })) } });
    for (const [name, authorize] of authorizers) {
      const actual = mine.responsibleState(stateOf(unsortedEvents).mine, stateOf(unsortedEvents).mine, input, { authorize });
      assert.equal(actual.epistemicStatus, "ESTABLISHED", name);
      assert.deepEqual(strip(actual), strip(expected), name);
      // And the exact envelope for the sorted history matches the reference byte for byte.
      same(mine.responsibleState(stateOf(sortedEvents).mine, stateOf(sortedEvents).mine, input, { authorize }), expected, name);
      same(mine.whyState(stateOf(unsortedEvents).mine, stateOf(unsortedEvents).mine, { ...input, disclosure: disclosure("WHY") }, { authorize }),
        ref.whyPortable({ ...portable, disclosure: disclosure("WHY") }), `${name} why`);
    }
  }
});

// ------------------------------------------------------------------ 6. output limit boundary

function overflowHistory(gatedCount) {
  const domain = { chainId: "31337", deploymentId: "overflow", protocol: "continuity", verifyingContract: "0x0000000000000000000000000000000000003002", version: "0.2" };
  const events = []; let clock = 0;
  const emit = (type, id, data) => { events.push({ data, id, timestamp: clock, type }); clock += 1; };
  emit("DEPLOYMENT_INITIALIZED", "genesis", { adapterPolicyHash: ref.PORTABLE_ADAPTER_POLICY_HASH, canonicalLineageId: "lineage", domain, finality: "LOCAL_ONLY", globalPolicySourceId: "policy-source", policyVersion: "policy/0.2", rootRecognitionPolicy: ref.PORTABLE_ROOT_RECOGNITION_POLICY, timeSource: "EVENT_TIMESTAMP", versions: GENESIS_VERSIONS });
  emit("PRINCIPAL_CREATED", "principal", { principalId: "principal" });
  emit("AGENT_CREATED", "agent", { agentId: "agent", controllerId: "controller", initialControlEpoch: 1, principalId: "principal" });
  const c = extra => ({ actions: ["read"], expiresAt: 5, maxDelegationDepth: 0, quantitative: false, requiredIntersectionIds: [], resources: ["r"], ...extra });
  const partners = Array.from({ length: 32 }, (_x, index) => `partner${String(index).padStart(3, "0")}`);
  for (const id of partners) emit("AUTHORITY_GRANTED", `g-${id}`, { grant: { authorityId: id, constraints: c({}), granteeId: "agent", grantorId: "principal", independent: true, kind: "PERMISSION", rootAuthorityId: id } });
  for (let index = 0; index < gatedCount; index += 1) {
    const id = `gated${String(index).padStart(3, "0")}`;
    emit("AUTHORITY_GRANTED", `g-${id}`, { grant: { authorityId: id, constraints: c({ requiredIntersectionIds: partners }), granteeId: "agent", grantorId: "principal", independent: true, kind: "PERMISSION", rootAuthorityId: id } });
  }
  return events;
}
test("output limit: evidence occurrences past 4096 give OUTPUT_LIMIT_EXCEEDED exactly as the reference; just under stays ESTABLISHED", () => {
  const over = overflowHistory(130), under = overflowHistory(120);
  const overflowed = diffEnvelope("SURVIVES", over, over, { targetAgentId: "agent", evaluationTime: 1000 }, "overflow", { facade: false });
  assert.equal(overflowed.code, "OUTPUT_LIMIT_EXCEEDED");
  assert.deepEqual(Object.keys(overflowed.scope).sort(), ["canonicalLineageId", "domain", "evaluationHead", "externalAssumptions", "finality", "freshness", "headRelationship", "observedHead", "policyVersion", "rootRecognitionPolicy", "unavailableEvidence", "versions", "withheldEvidence"]);
  const established = diffEnvelope("SURVIVES", under, under, { targetAgentId: "agent", evaluationTime: 1000 }, "under limit", { facade: false });
  assert.equal(established.answer.invalidatedAuthorityDependencies.length, 152);
  // The disclosure check precedes the overflow check.
  const missing = disclosure("SURVIVES").includedFields.filter(path => path !== "invalidatedAuthorityDependencies.evidence");
  assert.equal(mine.survivesState(stateOf(over).mine, { targetAgentId: "agent", evaluationTime: 1000, disclosure: { ...disclosure("SURVIVES"), includedFields: missing } }).code, "DISCLOSURE_INVALID");
  // Output measurement matches the reference budget on ordinary values.
  const value = { a: [1n, "x", { b: null }], c: { d: true } };
  assert.deepEqual(mine.measureOutput(value), { bytes: Buffer.byteLength(ref.canonicalEncode(value)), depth: 3 });
});

// ------------------------------------------------------------------ 7. the engine's own replay states (when replay.ts is present)

test("engine states: queries over replay.ts states answer exactly as over reference-derived states", async () => {
  if (!existsSync(new URL("../src/replay.ts", import.meta.url))) return;
  const { replay } = await import("../src/replay.ts");
  let checked = 0, rejected = [];
  for (const [name, events] of allHistories) {
    const result = replay(events);
    if (result.status !== "ACCEPTED") { rejected.push(`${name}:${result.code}`); continue; }
    const engine = result.state, reference = stateOf(events).mine, grid = gridOf(events), time = grid.head.canonicalTime + 3;
    for (const actor of [...grid.actors, "ghost:agent"]) {
      const input = { targetAgentId: actor, evaluationTime: time, disclosure: disclosure("SURVIVES") };
      same(mine.survivesState(engine, input), mine.survivesState(reference, input), `${name} survives ${actor}`);
      same(mine.survivesPortable({ operationVersion: mine.QUERY_VERSION, observedEvents: events, ...input }, replay), mine.survivesState(reference, input), `${name} survives portable ${actor}`);
      checked += 1;
    }
    if (authority === undefined) continue;
    for (const combo of sample(grid.combos, 6)) {
      const input = { authorizationDomain: grid.domain, request: { ...combo, claimedAt: time }, evaluationTime: time, disclosure: disclosure("RESPONSIBLE") };
      same(mine.responsibleState(engine, engine, input), mine.responsibleState(reference, reference, input), `${name} responsible ${JSON.stringify(combo)}`);
      const why = { ...input, disclosure: disclosure("WHY") };
      same(mine.whyState(engine, engine, why), mine.whyState(reference, reference, why), `${name} why ${JSON.stringify(combo)}`);
      checked += 1;
    }
  }
  console.log(`engine states: ${checked} answers checked; histories rejected by replay.ts: ${rejected.length === 0 ? "none" : rejected.join(", ")}`);
  assert.ok(checked > 100, `checked ${checked}`);
});

test("evidence order and identity helpers", () => {
  const refs = [
    { kind: "EXTERNAL", evidenceType: "a", reference: "r", attesterId: "x" }, { kind: "RECEIPT_COMMITMENT", receiptContentHash: `0x${"0".repeat(64)}`, eventId: "z", position: 1 },
    { kind: "EVENT", eventId: "b", eventType: "T", position: 5, historyHash: `0x${"1".repeat(64)}` }, { kind: "EVENT", eventId: "a", eventType: "T", position: 9, historyHash: `0x${"1".repeat(64)}` },
    { kind: "EVENT", eventId: "a", eventType: "T", position: 2, historyHash: `0x${"1".repeat(64)}` }, { kind: "AUTHORITY", authorityId: "x", grantEventId: "g" },
    { kind: "RUNTIME_CREDENTIAL", keyId: "k", sessionId: "s", admissionEventId: "e" },
  ];
  assert.deepEqual(mine.queryEvidence(refs, refs).map(item => [item.kind, item.eventId ?? item.authorityId ?? item.keyId ?? item.evidenceType, item.position]),
    [["EVENT", "a", 2], ["EVENT", "a", 9], ["EVENT", "b", 5], ["AUTHORITY", "x", undefined], ["RUNTIME_CREDENTIAL", "k", undefined], ["RECEIPT_COMMITMENT", "z", 1], ["EXTERNAL", "a", undefined]]);
});

after(() => { console.log(`queries differential: ${compared} public envelopes compared against the reference (${crashes} reference crashes on unsorted grants answered)`); });
