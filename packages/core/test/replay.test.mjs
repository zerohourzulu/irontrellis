// Replay differential tests: conformance vectors, fixture histories (JSON and
// JSONL), core-0.3-generated histories with signed transitions, replay-level
// mutations, incremental application, and the format-1 signed-control history.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { referenceCore as core, referenceCore02, referenceCore03, fixturePath, viemAccounts, vectorsPath, DEMO_CASE } from "./reference.mjs";
import { assertDecisionParity } from "./decision-parity.mjs";
const refReplay = await referenceCore02("core/portable-replay.ts");
const refCanonical = await referenceCore02("core/canonical.ts");
const { PortableFileEventStore } = await referenceCore02("indexer/portable-file-event-store.ts");
const { replay, replayFrom, applyEvent, createReplayState, detectFormat, REPLAY_VERSION } = await import("../src/replay.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const { hashCanonical, hashEventHistoryPrefixes } = await import("../src/hash.ts");
const { canonicalEncode } = await import("../src/canonical.ts");
const suites = await import("../src/crypto/suites.ts");

const revive = (_key, value) =>
  value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value;
const load = (path) => JSON.parse(readFileSync(path, "utf8"), revive);
const fixture = (name) => load(fixturePath(name));
const FIXTURES = ["handover-history.json", "handover-denied-history.json", "mandate-history.json",
  "original-core/cases/core02-packet-r1/export/history.json", "original-core/cases/core02-simulated-r1/export/history.json",
  "original-core/legacy-handover-history.json", "original-core/legacy-intake-history.json"];
const JSONL = [fixturePath("handover-history.jsonl"), fixturePath("original-core/cases/core02-packet-r1/history.jsonl"),
  `${DEMO_CASE}history.jsonl`];

const refResult = (history) => core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events: history });
/** The reference kernel state (what core-0.3 `stateOf` builds). */
const refState = (history) => {
  const kernel = refReplay.createPortableReplayKernel();
  const captured = refCanonical.captureBoundedCanonicalReplayBodyIncrementally(history, Object.freeze({ operationVersion: core.PORTABLE_REPLAY_VERSION, events: history }), kernel.visit);
  assert.equal(captured.status, "CAPTURED");
  const result = kernel.finish();
  assert.equal(result.status, "ACCEPTED");
  return result.state;
};
const STATE_MAPS = ["principals", "agents", "reservedAgentIds", "roles", "successionRules", "tenures", "runtimeSessions", "intentDeclarations", "intentAdmissions",
  "intentConsumptions", "intentOutcomeStates", "outcomeObservations", "attemptDuties", "attemptDutyReviews", "receiptCommitments", "obligations",
  "nonceReservationsByActor", "authorities", "recognizedRoots", "authorityUsage"];
const plain = (value) => {
  if (value instanceof Map) return Object.fromEntries([...value].map(([k, v]) => [k, plain(v)]));
  if (value instanceof Set) return [...value].sort();
  if (Array.isArray(value)) return value.map(plain);
  if (typeof value === "bigint") return `${value}n`;
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) if (key !== "credentialScheme") out[key] = plain(value[key]);
    return out;
  }
  return value;
};
/** Field-by-field comparison of every state map against the reference kernel. */
const assertSameState = (mine, reference, label) => {
  for (const name of STATE_MAPS) {
    const left = plain(mine[name]), right = plain(reference[name]);
    if (name === "reservedAgentIds") for (const key of Object.keys(right)) right[key] = [...right[key]].sort();
    assert.deepEqual(left, right, `${label}: ${name}`);
  }
  assert.deepEqual(mine.eventHistoryHashes, reference.eventHistoryHashes, `${label}: hashes`);
  assert.deepEqual(mine.head, reference.head, `${label}: head`);
  assert.equal(mine.events.map((e) => canonicalEncode(e)).join("\n"), reference.events.map((e) => core.canonicalEncode(e)).join("\n"), `${label}: events`);
  assert.equal(canonicalEncode(mine.genesis), core.canonicalEncode(reference.genesis));
};
/**
 * One deliberate departure from the reference kernel (SPEC-IRONTRELLIS-CORE-v2 §19: readers refuse unknown literals
 * rather than guess; parity with the Python verifier): a genesis whose `versions.eventSchemaVersion` is a string naming
 * no event format this engine implements is UNSUPPORTED_VERSION, where the reference fell back to the legacy schema
 * (UNSUPPORTED_EVENT_SCHEMA when the probe passed, EVENT_DATA_INVALID when a 0.1-era genesis failed it).
 */
const KNOWN_SCHEMA_VERSIONS = new Set(["continuity-event/0.2", "irontrellis-event/1", "irontrellis-event/2"]);
const unknownSchemaVersion = (history) => {
  const version = history[0]?.data?.versions?.eventSchemaVersion;
  return typeof version === "string" && !KNOWN_SCHEMA_VERSIONS.has(version);
};
const expectedCode = (history, ref) => (ref.eventPosition === 0 && (ref.code === "UNSUPPORTED_EVENT_SCHEMA" || ref.code === "EVENT_DATA_INVALID") && unknownSchemaVersion(history) ? "UNSUPPORTED_VERSION" : ref.code);
const assertSameOutcome = (history, label) => {
  const ref = refResult(history), mine = replay(history);
  assert.equal(mine.status, ref.status, `${label}: ${JSON.stringify({ ref: ref.code, mine: [mine.code, mine.reason, mine.position] })}`);
  if (ref.status === "ACCEPTED") {
    assert.deepEqual(mine.head, ref.head, label);
    assert.equal(mine.eventCount, ref.eventCount);
    assertSameState(mine.state, refState(history), label);
  } else {
    assert.equal(mine.code, expectedCode(history, ref), `${label}: ${mine.reason}`);
    assert.equal(mine.position, ref.eventPosition, `${label}: position`);
  }
  return mine;
};

test("conformance vectors: status and head equal the vector expectation and the reference", () => {
  const vectors = load(vectorsPath).filter((v) => v.kind === "replay");
  assert.equal(vectors.length, 11);
  for (const vector of vectors) {
    const mine = assertSameOutcome(vector.events, vector.id);
    assert.equal(mine.status, vector.expect.status, vector.id);
    if (vector.expect.head !== null) assert.deepEqual(mine.head, vector.expect.head, vector.id);
    assert.equal(detectFormat(vector.events), vector.events[0]?.type === "DEPLOYMENT_INITIALIZED" ? "continuity-event/0.2" : undefined);
  }
  assert.equal(REPLAY_VERSION, core.PORTABLE_REPLAY_VERSION);
});

test("fixture histories (JSON and JSONL) replay to the reference head and state", () => {
  for (const name of FIXTURES) assertSameOutcome(fixture(name), name);
  for (const path of JSONL) {
    const history = new PortableFileEventStore(path).readAll();
    const mine = assertSameOutcome(history, path);
    assert.equal(mine.status, "ACCEPTED");
    assert.deepEqual(mine.state.eventHistoryHashes, hashEventHistoryPrefixes(history, "continuity-event/0.2"));
  }
});

test("empty and malformed inputs", () => {
  assert.deepEqual(replay([]), { status: "REJECTED", code: "GENESIS_REQUIRED" });
  assert.equal(replay("nope").code, "INVALID_INPUT");
  assert.equal(replay([null]).code, "INVALID_INPUT");
  assert.equal(replay([fixture("handover-history.json")[1]]).code, "GENESIS_REQUIRED");
  const [genesis] = fixture("handover-history.json");
  assert.equal(replay([genesis, genesis]).code, "GENESIS_DUPLICATE");
  assert.equal(replay([genesis, { ...genesis, id: "other", data: { ...genesis.data, finality: "X" } }]).code, "EVENT_DATA_INVALID");
});

// ---------------------------------------------------------------- generated histories (core-0.3 on the reference engine)

const { generatePrivateKey, privateKeyToAccount } = viemAccounts;
const { createLocalOwner, createLocalReviewOwner, createLocalDomain, openLocalOwner } = await referenceCore03("local-owner.ts");
const { openLocalSimulation, commitTerms } = await referenceCore03("simulation.ts");
const { openLocalRuntime } = await referenceCore03("runtime.ts");
const { openLocalExecution } = await referenceCore03("execution.ts");
const { openLocalAttemptRecorder } = await referenceCore03("attempts.ts");
const { produceAdministrativeEvent } = await referenceCore02("administration/index.ts");
const credential = () => { const a = privateKeyToAccount(generatePrivateKey()); return { address: a.address, signHash: (hash) => a.signMessage({ message: { raw: hash } }) }; };
const workspace = (t) => { const dir = mkdtempSync(join(tmpdir(), "irontrellis-replay-")); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; };

/** Handover with a simulated execution, receipt, obligation, succession, reassignment and a recorded status. */
const handoverHistory = async (t) => {
  let tick = 100;
  const config = { historyFile: join(workspace(t), "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick };
  const owner = createLocalOwner(config), a = credential(), b = credential();
  for (const id of ["bea", "alex"]) owner.createAgent({ id });
  owner.createRole({ id: "reviewer" });
  owner.declareSuccession({ id: "handover", from: "bea", to: "alex", role: "reviewer" });
  owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  owner.admitRuntime({ session: "session:bea", agent: "bea", epoch: 1, key: "key:bea", address: a.address, expiresAt: 200 });
  owner.admitRuntime({ session: "session:alex", agent: "alex", epoch: 1, key: "key:alex", address: b.address, expiresAt: 200 });
  owner.grant({ id: "collect", to: "bea", actions: ["read", "OBLIGATE"], resources: ["incident:42"], expiresAt: 180 });
  owner.grant({ id: "review", to: "alex", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: 180 });
  const options = { ...config, session: "session:bea", signHash: a.signHash };
  const op = { id: "operation:42", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: "Synthetic incident review" }) };
  const sim = openLocalSimulation(options), runtime = openLocalRuntime(options);
  assert.equal((await sim.run(op)).invocation.status, "SUBMITTED");
  assert.equal((await sim.recordReceipt(op)).recording.status, "ADMITTED");
  await runtime.obligate({ id: "duty:42", operation: op.id, description: "Review the collected material.", deadline: 170, succession: "handover", reviewAuthority: "review" });
  tick = 110;
  owner.succeed({ id: "handover:42", rule: "handover", fromAgent: "bea", fromTenure: "shift:1", toAgent: "alex", toTenure: "shift:2", role: "reviewer", number: 2 });
  owner.grant({ id: "assign", to: "alex", actions: ["ASSIGN_PERFORMANCE"], resources: ["duty:42"], expiresAt: 180 });
  const replacement = openLocalRuntime({ ...options, session: "session:alex", signHash: b.signHash });
  await replacement.assign({ id: "assign:42", obligation: "duty:42" });
  tick = 120;
  const history = owner.exportHistory();
  const state = refState(history);
  const status = await produceAdministrativeEvent({
    events: history, expectedDomain: config.domain, expectedHistoryHead: state.head, runtimeSessionId: "session:alex",
    transition: { id: "status:42", type: "OBLIGATION_STATUS_RECORDED", timestamp: tick, data: {
      obligationId: "duty:42", fromStatus: "OPEN", toStatus: "OUTCOME_UNKNOWN", actorId: "alex", action: "record-collection-disposition",
      attesterId: "adapter:simulated", evidenceReference: { kind: "EXTERNAL", evidenceType: "note", reference: "ref", attesterId: "adapter:simulated" } } },
  }, { signHash: b.signHash });
  return [...history, status.event];
};

/** E6: a remote-service-report execution with attempt duty, observations, succession, assignment and a closed review. */
const reviewHistory = async (t) => {
  let at = 100;
  const config = { historyFile: join(workspace(t), "history.jsonl"), domain: createLocalDomain(), owner: "owner", controller: "controller", now: () => at };
  const owner = createLocalReviewOwner(config), first = credential(), second = credential();
  owner.createAgent({ id: "first" }); owner.createRole({ id: "operator" });
  owner.appoint({ agent: "first", role: "operator", tenure: "tenure:1", number: 1 });
  owner.admitRuntime({ agent: "first", session: "session:first", epoch: 1, key: "key:first", address: first.address, expiresAt: 2000 });
  owner.grant({ id: "execute", to: "first", actions: ["make-fixture"], resources: ["synthetic"], expiresAt: 1000, maxAmount: 50n, maxCumulativeAmount: 50n, maxTransactions: 1 });
  const options = { ...config, session: "session:first", signHash: first.signHash };
  const unknown = (input) => { const identity = core.derivePortableAdapterIdentity(input); return { status: "OUTCOME_UNKNOWN", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }; };
  const adapter = { adapterProfile: core.approvedPortableAdapterProfileForPolicy(core.PORTABLE_ADAPTER_POLICY_E6_HASH, core.REMOTE_SERVICE_REPORT_ADAPTER_ID), submit: unknown, reconcile: unknown };
  const execution = openLocalExecution(options, adapter, "REMOTE_REPORT");
  const result = await execution.run({ id: "job:1", action: "make-fixture", resource: "synthetic", role: "operator", tenure: "tenure:1", amount: 50n, counterparty: "synthetic:vendor", termsCommitment: commitTerms({ units: "SYNTHETIC" }) });
  assert.equal(result.invocation.status, "OUTCOME_UNKNOWN");
  const actions = ["OBSERVE_OUTCOME", "CREATE_ATTEMPT_DUTY", "ASSIGN_ATTEMPT_DUTY", "CLOSE_ATTEMPT_DUTY"];
  owner.grant({ id: "records:first", to: "first", actions, resources: ["job:1"], expiresAt: 1000 });
  const recorder = openLocalAttemptRecorder(options);
  await recorder.createDuty({ id: "investigate", intent: "job:1", description: "Investigate retained evidence", deadline: 2000 });
  const identity = () => refState(owner.exportHistory()).intentAdmissions.get("job:1").adapterIdentity;
  await recorder.observe({ id: "z", intent: "job:1", acknowledgment: core.createRemoteServiceReportAcknowledgment(identity(), `0x${"b".repeat(64)}`) });
  at = 110;
  owner.createAgent({ id: "second" });
  owner.declareSuccession({ id: "succession", from: "first", to: "second", role: "operator" });
  owner.succeed({ id: "handover", rule: "succession", fromAgent: "first", fromTenure: "tenure:1", toAgent: "second", toTenure: "tenure:2", role: "operator", number: 2 });
  owner.admitRuntime({ agent: "second", session: "session:second", epoch: 1, key: "key:second", address: second.address, expiresAt: 2000 });
  owner.grant({ id: "records:second", to: "second", actions, resources: ["job:1"], expiresAt: 1000 });
  const successor = openLocalAttemptRecorder({ ...options, session: "session:second", signHash: second.signHash });
  await successor.assignDuty({ id: "take", duty: "investigate" });
  await successor.observe({ id: "a", intent: "job:1", acknowledgment: core.createRemoteServiceReportAcknowledgment(identity(), `0x${"c".repeat(64)}`) });
  at = 120;
  await successor.reviewDuty({ id: "review:1", duty: "investigate", summaryDigest: `0x${"a".repeat(64)}` });
  return openLocalOwner(config).exportHistory();
};

test("core-0.3 generated histories: obligations, status records, attempt duties and reviews replay identically", async (t) => {
  const handover = await handoverHistory(t);
  const types = new Set(handover.map((e) => e.type));
  for (const type of ["OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED", "RECEIPT_RECORDED", "TRANSACTION_INTENT_CONSUMED"]) assert.ok(types.has(type), type);
  const mine = assertSameOutcome(handover, "generated handover");
  assert.equal(mine.state.obligations.get("duty:42").status, "OUTCOME_UNKNOWN");
  assert.equal(mine.state.obligations.get("duty:42").performanceAssigneeId, "alex");
  const review = await reviewHistory(t);
  const reviewTypes = new Set(review.map((e) => e.type));
  for (const type of ["OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED"]) assert.ok(reviewTypes.has(type), type);
  const reviewed = assertSameOutcome(review, "generated review");
  assert.equal(reviewed.state.attemptDutyReviews.get("investigate").length, 1);
  assert.equal(reviewed.state.outcomeObservations.get("job:1").length, 2);
  assert.equal(reviewed.state.authorityUsage.get("execute").admittedTransactionCount, 1);
  t.diagnostic(`generated histories: ${handover.length} + ${review.length} events`);
  generated.push(["handover", handover], ["review", review]);
});
const generated = [];

// ---------------------------------------------------------------- replay-level mutations

/** Transition-level mutations of every event of every type: same code and position as the reference. */
const replayMutations = (history, position) => {
  const event = history[position];
  const variants = [];
  const patch = (label, data) => variants.push([label, history.map((e, i) => (i === position ? { ...e, data } : e))]);
  const swap = (a, b) => history.map((e, i) => (i === a ? history[b] : i === b ? history[a] : e));
  if (position > 0) {
    variants.push(["transposed", swap(position - 1, position)]);
    variants.push(["duplicate id", history.map((e, i) => (i === position ? { ...e, id: history[position - 1].id } : e))]);
    variants.push(["rewound timestamp", history.map((e, i) => (i === position ? { ...e, timestamp: history[position - 1].timestamp - 1 } : e))]);
    variants.push(["duplicated", [...history.slice(0, position + 1), event, ...history.slice(position + 1)]]);
    variants.push(["removed", history.filter((_, i) => i !== position)]);
  }
  for (const [key, value] of Object.entries(event.data)) {
    if (typeof value === "string") patch(`${key}=unknown`, { ...event.data, [key]: value === "" ? "x" : "unknown:" + value.slice(0, 8) });
    if (typeof value === "number") patch(`${key}+1`, { ...event.data, [key]: value + 1 });
    if (typeof value === "boolean") patch(`!${key}`, { ...event.data, [key]: !value });
    if (Array.isArray(value)) patch(`${key}=[]`, { ...event.data, [key]: [] });
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      for (const [inner, innerValue] of Object.entries(value)) {
        if (typeof innerValue === "string") patch(`${key}.${inner}=other`, { ...event.data, [key]: { ...value, [inner]: "other" } });
        if (typeof innerValue === "number") patch(`${key}.${inner}+1`, { ...event.data, [key]: { ...value, [inner]: innerValue + 1 } });
        if (typeof innerValue === "bigint") patch(`${key}.${inner}*2`, { ...event.data, [key]: { ...value, [inner]: innerValue * 2n + 1n } });
      }
    }
  }
  return variants;
};

test("mutation differential: transposed, duplicated, removed, rewound and edited events reject like the reference", async () => {
  const histories = [["handover", fixture("handover-history.json")], ["mandate", fixture("mandate-history.json")], ["packet", fixture("original-core/cases/core02-packet-r1/export/history.json")], ...generated];
  const codes = new Map();
  let checked = 0;
  for (const [name, history] of histories) {
    for (let position = 0; position < history.length; position += 1) {
      for (const [label, variant] of replayMutations(history, position)) {
        const ref = refResult(variant), mine = replay(variant);
        const key = `${name}#${position} ${history[position].type} ${label}`;
        assert.equal(mine.status, ref.status, `${key}: ${JSON.stringify({ ref: ref.code, mine: [mine.code, mine.reason] })}`);
        if (ref.status === "REJECTED") {
          assert.equal(mine.code, expectedCode(variant, ref), `${key}: ${mine.reason}`);
          assert.equal(mine.position, ref.eventPosition, key);
          codes.set(`${history[position].type}:${ref.code}`, (codes.get(`${history[position].type}:${ref.code}`) ?? 0) + 1);
        } else {
          assert.deepEqual(mine.head, ref.head, key);
        }
        checked += 1;
      }
    }
  }
  const rejectedTypes = new Set([...codes.keys()].map((k) => k.split(":")[0]));
  for (const type of events.ADMINISTRATIVE_EVENT_TYPES) assert.ok(rejectedTypes.has(type), type);
  assert.ok(rejectedTypes.size >= 24, `types with a rejected mutation: ${[...rejectedTypes].sort().join(",")}`);
  assert.ok([...codes.keys()].some((k) => k.endsWith(":TRANSITION_INVALID")));
  assert.ok(checked > 800);
});

test("applyEvent is incremental: a rejected event leaves the state untouched and replayFrom continues", () => {
  const history = fixture("handover-history.json");
  const state = createReplayState("continuity-event/0.2");
  const prefix = replayFrom(state, history.slice(0, 13));
  assert.equal(prefix.status, "ACCEPTED");
  assert.deepEqual(prefix.head, refResult(history.slice(0, 13)).head);
  const before = canonicalEncode(plain(Object.fromEntries(STATE_MAPS.map((k) => [k, state[k]]))));
  const bad = applyEvent(state, { ...history[13], timestamp: 0 });
  assert.equal(bad.code, "EVENT_TIME_REGRESSION");
  assert.equal(applyEvent(state, history[3]).code, "EVENT_ID_DUPLICATE");
  assert.equal(applyEvent(state, { ...history[13], id: "fresh", data: { ...history[13].data, actorId: "nobody" } }).code, "TRANSITION_INVALID");
  assert.equal(canonicalEncode(plain(Object.fromEntries(STATE_MAPS.map((k) => [k, state[k]])))), before);
  assert.equal(state.events.length, 13);
  const rest = replayFrom(state, history.slice(13));
  assert.equal(rest.status, "ACCEPTED");
  assert.deepEqual(rest.head, refResult(history).head);
  assertSameState(state, refState(history), "incremental");
  const good = applyEvent(createReplayState("continuity-event/0.2"), history[0]);
  assert.equal(good.ok, true);
  assert.equal(good.head.hash, "0xe035299cb5520cc603d60273ae4c51ea1eaddad3cc9a47102edab60447d38397");
});

// ---------------------------------------------------------------- format 1

const TRELLIS = "irontrellis-event/1";
const keyPair = (id) => suites.generateKeyPair("ed25519", id);
const signer = (pair) => suites.signHashWith(pair);
/** Builds a signed format-1 history step by step, tracking the head so each control event binds its predecessor. */
const trellisBuilder = (owner) => {
  const domain = { protocol: "irontrellis", version: "1", deploymentId: "deployment:trellis" };
  const genesisData = {
    domain, versions: { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" },
    ownerKeys: [{ keyId: owner.keyId, scheme: "ed25519", credential: owner.credential }],
    adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:trellis", policyVersion: "policy:trellis/1",
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:trellis", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
  };
  const state = createReplayState(TRELLIS);
  const history = [];
  const add = async (raw, key = owner) => {
    const position = state.events.length;
    let data = raw.data;
    if (position > 0 && events.isControlEvent(raw.type)) {
      const hash = events.controlAuthorizationHash({ domain, eventId: raw.id, eventType: raw.type, timestamp: raw.timestamp,
        previousHead: { hash: state.head.hash, position: state.head.position }, effectHash: hashCanonical(raw.data, "sha256") }, "sha256");
      data = { ...raw.data, controlAuthorization: { keyId: key.keyId, signature: await signer(key)(hash) } };
    }
    const event = { ...raw, data };
    const result = applyEvent(state, event);
    assert.equal(result.ok, true, `${raw.id}: ${result.reason}`);
    history.push(event);
    return event;
  };
  return { state, history, add, domain, genesisData };
};

test("format 1: an ed25519-signed history replays; unsigned, foreign-key and moved control events are rejected", async () => {
  const owner = keyPair("owner:1"), runtime = keyPair("runtime:1");
  const b = trellisBuilder(owner);
  await b.add({ id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0, data: b.genesisData });
  await b.add({ id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } });
  await b.add({ id: "agent", type: "AGENT_CREATED", timestamp: 2, data: { agentId: "agent:1", principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
  await b.add({ id: "role", type: "ROLE_CREATED", timestamp: 3, data: { roleId: "role:1", principalId: "owner", exclusive: true } });
  await b.add({ id: "appoint", type: "AGENT_APPOINTED", timestamp: 4, data: { agentId: "agent:1", roleId: "role:1", roleTenureId: "tenure:1", tenureNumber: 1, principalId: "owner" } });
  await b.add({ id: "session", type: "RUNTIME_SESSION_ADMITTED", timestamp: 5, data: { sessionId: "session:1", agentId: "agent:1", controllerId: "controller", controlEpoch: 1, credentialKeyId: "key:1", credentialScheme: "ed25519", credentialPublicKey: runtime.credential, expiresAt: 100 } });
  await b.add({ id: "grant", type: "AUTHORITY_GRANTED", timestamp: 6, data: { grant: { kind: "PERMISSION", authorityId: "root:1", grantorId: "owner", granteeId: "agent:1", rootAuthorityId: "root:1", independent: true,
    constraints: { actions: ["read"], resources: ["doc:1"], quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [] } } } });
  await b.add({ id: "declare", type: "TRANSACTION_INTENT_DECLARED", timestamp: 7, data: { intentId: "intent:1", nonce: "nonce:1", actorId: "agent:1", action: "read", resource: "doc:1", roleId: "role:1", roleTenureId: "tenure:1",
    adapterProfile: editions.knownAdapterProfile("adapter:simulated") } });
  await b.add({ id: "anchor", type: "ANCHOR_RECORDED", timestamp: 8, data: { anchoredHead: b.state.head, anchor: "local-head-file", receipt: { file: "history.head" }, anchoredAt: 8 } });
  await b.add({ id: "epoch", type: "CONTROL_EPOCH_ADVANCED", timestamp: 9, data: { agentId: "agent:1", controllerId: "controller", fromEpoch: 1, toEpoch: 2 } });
  const { history, state } = b;
  assert.equal(state.signatureScheme, "ed25519");
  assert.equal(state.hashAlgorithm, "sha256");
  assert.equal(state.runtimeSessions.get("session:1").credentialScheme, "ed25519");
  assert.equal(state.runtimeSessions.get("session:1").credentialAddressKey, runtime.credential.toLowerCase());
  assert.equal(state.anchors.length, 1);
  assert.deepEqual(state.eventHistoryHashes, hashEventHistoryPrefixes(history, TRELLIS));
  const fresh = replay(history);
  assert.equal(fresh.status, "ACCEPTED");
  assert.deepEqual(fresh.head, state.head);
  assert.equal(detectFormat(history), TRELLIS);
  assertSameState(fresh.state, state, "format-1 rebuild");
  // Unsigned control event.
  const unsigned = history.map((e) => (e.id === "grant" ? { ...e, data: events.controlEffect(e.data) } : e));
  assert.deepEqual([replay(unsigned).code, replay(unsigned).position], ["CONTROL_AUTHORIZATION_INVALID", 6]);
  // Re-signed by a key the genesis does not declare, and a declared key with a wrong signature.
  const stranger = keyPair("owner:2");
  const resign = async (event, key, keyId = key.keyId) => {
    const previous = history[history.indexOf(event) - 1];
    const hash = events.controlAuthorizationHash({ domain: b.domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
      previousHead: { hash: hashEventHistoryPrefixes(history.slice(0, history.indexOf(event)), TRELLIS).at(-1), position: history.indexOf(previous) },
      effectHash: hashCanonical(events.controlEffect(event.data), "sha256") }, "sha256");
    return { ...event, data: { ...event.data, controlAuthorization: { keyId, signature: await signer(key)(hash) } } };
  };
  const foreign = history.map((e) => (e.id === "role" ? null : e));
  foreign[3] = await resign(history[3], stranger);
  assert.deepEqual([replay(foreign).code, replay(foreign).position], ["CONTROL_AUTHORIZATION_INVALID", 3]);
  const impostor = [...history];
  impostor[3] = await resign(history[3], stranger, owner.keyId);
  assert.equal(replay(impostor).code, "CONTROL_AUTHORIZATION_INVALID");
  // Moved: the declaration (not a control event) and the anchor swap; the anchor's signature bound the old previous head.
  const moved = [...history];
  [moved[7], moved[8]] = [{ ...moved[8], timestamp: 7 }, { ...moved[7], timestamp: 8 }];
  assert.deepEqual([replay(moved).code, replay(moved).position], ["CONTROL_AUTHORIZATION_INVALID", 7]);
  // Tampered effect after signing.
  const tampered = history.map((e) => (e.id === "epoch" ? { ...e, data: { ...e.data, toEpoch: 3 } } : e));
  assert.equal(replay(tampered).code, "CONTROL_AUTHORIZATION_INVALID");
  // A bad anchor is a transition failure, not a signature failure.
  const badAnchor = await (async () => {
    const c = trellisBuilder(owner);
    for (const e of history.slice(0, 8)) c.history.push(e), assert.equal(applyEvent(c.state, e).ok, true);
    const prior = c.state.head;
    const raw = { id: "anchor:bad", type: "ANCHOR_RECORDED", timestamp: 8, data: { anchoredHead: { ...prior, hash: `0x${"9".repeat(64)}` }, anchor: "custom", receipt: {}, anchoredAt: 8 } };
    const hash = events.controlAuthorizationHash({ domain: c.domain, eventId: raw.id, eventType: raw.type, timestamp: 8, previousHead: { hash: prior.hash, position: prior.position }, effectHash: hashCanonical(raw.data, "sha256") }, "sha256");
    return applyEvent(c.state, { ...raw, data: { ...raw.data, controlAuthorization: { keyId: owner.keyId, signature: await signer(owner)(hash) } } });
  })();
  assert.equal(badAnchor.code, "TRANSITION_INVALID");
  // A legacy history must not carry control authorizations, and a format-1 genesis is rejected under legacy rules.
  const legacy = fixture("handover-history.json");
  assert.equal(replay(legacy.map((e, i) => (i === 1 ? { ...e, data: { ...e.data, controlAuthorization: { keyId: "x", signature: `0x${"0".repeat(128)}` } } } : e))).code, "EVENT_DATA_INVALID");
  assert.equal(replayFrom(createReplayState("continuity-event/0.2"), [{ ...legacy[0], data: b.genesisData }]).code, "EVENT_DATA_INVALID");
  assert.equal(replay([{ ...legacy[0], data: b.genesisData }]).status, "ACCEPTED"); // autodetected as format 1
});

test("format 1: a runtime-signed admission verifies through the session's ed25519 suite", async () => {
  const authority = await import("../src/authority.ts");
  const owner = keyPair("owner:1"), runtime = keyPair("runtime:1");
  const b = trellisBuilder(owner);
  await b.add({ id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0, data: b.genesisData });
  await b.add({ id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } });
  await b.add({ id: "agent", type: "AGENT_CREATED", timestamp: 2, data: { agentId: "agent:1", principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
  await b.add({ id: "role", type: "ROLE_CREATED", timestamp: 3, data: { roleId: "role:1", principalId: "owner", exclusive: true } });
  await b.add({ id: "appoint", type: "AGENT_APPOINTED", timestamp: 4, data: { agentId: "agent:1", roleId: "role:1", roleTenureId: "tenure:1", tenureNumber: 1, principalId: "owner" } });
  await b.add({ id: "session", type: "RUNTIME_SESSION_ADMITTED", timestamp: 5, data: { sessionId: "session:1", agentId: "agent:1", controllerId: "controller", controlEpoch: 1, credentialKeyId: "key:1", credentialScheme: "ed25519", credentialPublicKey: runtime.credential } });
  await b.add({ id: "grant", type: "AUTHORITY_GRANTED", timestamp: 6, data: { grant: { kind: "PERMISSION", authorityId: "root:1", grantorId: "owner", granteeId: "agent:1", rootAuthorityId: "root:1", independent: true,
    constraints: { actions: ["read"], resources: ["doc:1"], quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [] } } } });
  const profile = editions.knownAdapterProfile("adapter:simulated");
  await b.add({ id: "declare", type: "TRANSACTION_INTENT_DECLARED", timestamp: 7, data: { intentId: "intent:1", nonce: "nonce:1", actorId: "agent:1", action: "read", resource: "doc:1", roleId: "role:1", roleTenureId: "tenure:1", adapterProfile: profile } });
  const { state } = b;
  const request = { actorId: "agent:1", action: "read", resource: "doc:1", claimedAt: 8 };
  const binding = { runtimeSessionId: "session:1", credentialKeyId: "key:1", controlEpoch: 1, roleId: "role:1", roleTenureId: "tenure:1", intentId: "intent:1", nonce: "nonce:1" };
  const challenge = authority.createRuntimeAuthorizationChallenge({ domain: b.domain, request, evaluationTime: 8, policyVersion: b.genesisData.policyVersion, historyHead: state.head, binding });
  const hash = authority.hashRuntimeAuthorizationChallenge(challenge, "sha256");
  const runtimeSignature = await signer(runtime)(hash);
  const result = authority.authorizeState(state, { expectedHistoryHead: state.head, domain: b.domain, policyVersion: b.genesisData.policyVersion, rootRecognitionPolicy: "declared-principal-root/0.2",
    request, evaluationTime: 8, consequential: true, binding: { ...binding, runtimeSignature } });
  assert.equal(result.decision, "ALLOW", JSON.stringify(result));
  const admission = { id: "admit", type: "TRANSACTION_INTENT_ADMITTED", timestamp: 8, data: { intentId: "intent:1", evaluationTime: 8, expectedHistoryHead: state.head, authorizationProof: result.proof, runtimeAuthorizationHash: hash, runtimeSignature } };
  const applied = applyEvent(state, admission);
  assert.equal(applied.ok, true, applied.reason);
  const record = state.intentAdmissions.get("intent:1");
  assert.equal(record.runtimeSessionId, "session:1");
  assert.equal(record.adapterIdentity.idempotencyKey, editions.deriveAdapterIdempotencyKey(b.domain, "intent:1"));
  assert.equal(state.nonceReservationsByActor.get("agent:1").get("nonce:1").intentId, "intent:1");
  // The same admission signed by another key does not verify.
  const other = keyPair("runtime:2");
  const forged = { ...admission, id: "admit:2", data: { ...admission.data, runtimeSignature: await signer(other)(hash) } };
  const c = trellisBuilder(owner);
  for (const e of b.history) assert.equal(applyEvent(c.state, e).ok, true);
  assert.equal(applyEvent(c.state, forged).code, "TRANSITION_INVALID");
  // A simulated consumption closes the loop with the format-1 adapter identity.
  const identity = record.adapterIdentity;
  const acknowledgment = editions.createAdapterAcknowledgment(identity);
  const consumption = { id: "consume", type: "TRANSACTION_INTENT_CONSUMED", timestamp: 9, data: { intentId: "intent:1", adapterId: "adapter:simulated", idempotencyKey: identity.idempotencyKey,
    submissionFingerprint: identity.submissionFingerprint, status: "SUBMITTED", transactionReference: identity.submissionFingerprint, acknowledgment,
    evidenceReference: editions.adapterAcknowledgmentEvidence(identity, acknowledgment) } };
  const consumed = applyEvent(state, consumption);
  assert.equal(consumed.ok, true, consumed.reason);
  assert.equal(replay([...b.history, admission, consumption]).status, "ACCEPTED");
});

// ---------------------------------------------------------------- migrated histories (DESIGN §8): the legacy shadow

test("a migrated handover history replays against the legacy shadow: runtime-signed events, recorded heads and answers equal the source", async () => {
  const { whyState, survivesState, publicQueryDisclosure } = await import("../src/queries.ts");
  const authority = await import("../src/authority.ts");
  const source = new PortableFileEventStore(fixturePath("handover-history.jsonl")).readAll();
  const S = refState(source), mine = replay(source);
  assert.equal(mine.status, "ACCEPTED");
  const owner = keyPair("owner:migration"), legacyGenesis = source[0];
  const domain = { protocol: "irontrellis", version: "1", deploymentId: legacyGenesis.data.domain.deploymentId };
  const genesis = { id: legacyGenesis.id, type: "DEPLOYMENT_INITIALIZED", timestamp: legacyGenesis.timestamp, data: {
    domain, adapterPolicyHash: legacyGenesis.data.adapterPolicyHash, canonicalLineageId: legacyGenesis.data.canonicalLineageId,
    versions: { ...events.TRELLIS_VERSIONS, signatureScheme: legacyGenesis.data.versions.signatureScheme }, policyVersion: legacyGenesis.data.policyVersion,
    rootRecognitionPolicy: legacyGenesis.data.rootRecognitionPolicy, globalPolicySourceId: legacyGenesis.data.globalPolicySourceId, timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
    ownerKeys: [{ keyId: owner.keyId, scheme: "ed25519", credential: owner.credential }],
    migratedFrom: { format: "continuity-event/0.2", historyHash: S.head.hash, position: S.head.position, recordHash: `0x${"5".repeat(64)}`,
      genesis: legacyGenesis.data, genesisEventId: legacyGenesis.id, genesisTimestamp: legacyGenesis.timestamp },
  } };
  // Re-record 1..n verbatim; control events gain an owner signature over the format-1 previous head, sessions gain their scheme.
  const state = createReplayState(TRELLIS);
  assert.equal(applyEvent(state, genesis).ok, true);
  const migrated = [genesis];
  for (let k = 1; k < source.length; k += 1) {
    const original = source[k];
    let data = original.type === "RUNTIME_SESSION_ADMITTED" ? { ...original.data, credentialScheme: "eip191-personal-sign-keccak256" } : original.data;
    if (events.isControlEvent(original.type)) {
      const hash = events.controlAuthorizationHash({ domain, eventId: original.id, eventType: original.type, timestamp: original.timestamp,
        previousHead: { hash: state.head.hash, position: state.head.position }, effectHash: hashCanonical(data, "sha256") }, "sha256");
      data = { ...data, controlAuthorization: { keyId: owner.keyId, signature: await signer(owner)(hash) } };
    }
    const event = { ...original, data };
    const applied = applyEvent(state, event);
    assert.equal(applied.ok, true, `${k} ${original.type}: ${applied.reason}`);
    assert.equal(state.shadowHashes[k], S.eventHistoryHashes[k], `shadow hash ${k}`);
    migrated.push(event);
  }
  const T = replay(migrated);
  assert.equal(T.status, "ACCEPTED", T.reason);
  assert.deepEqual(T.head, state.head);
  assert.deepEqual(T.state.shadowHashes, S.eventHistoryHashes);
  assert.deepEqual(T.state.eventHistoryHashes, hashEventHistoryPrefixes(migrated, TRELLIS));
  assert.notEqual(T.state.eventHistoryHashes[5], S.eventHistoryHashes[5]);
  // Every state map equals the reference kernel state of the source; recorded heads are the legacy heads.
  for (const name of STATE_MAPS) {
    const left = plain(T.state[name]), right = plain(S[name]);
    if (name === "reservedAgentIds") for (const key of Object.keys(right)) right[key] = [...right[key]].sort();
    assert.deepEqual(left, right, name);
  }
  assert.deepEqual(T.state.intentAdmissions.get("intent:first-look").admissionHead, S.intentAdmissions.get("intent:first-look").admissionHead);
  assert.deepEqual(T.state.obligations.get("obligation:first-look").creationHead, S.obligations.get("obligation:first-look").creationHead);
  // authorize / why / survives at head time: same answers after dropping the fields that name the history itself, except that
  // DENY / INDETERMINATE evidence may be narrower in format 1 (only the relevant events): decision, code, scopeAssurance and each
  // failure's code/subject/authority ids/path are equal, and each failure's evidence is a subset of the source's that still cites
  // the failing authority's grant event and the head (the rule is documented in test/decision-parity.mjs).
  const DROPPED = new Set(["hash", "historyHash", "domain", "authorizationDomain", "policyVersion", "proofVersion", "version", "operationVersion", "controlAuthorization", "credentialScheme", "eventHistoryHash", "versions"]);
  const strip = (value) => Array.isArray(value) ? value.map(strip)
    : value !== null && typeof value === "object" ? Object.fromEntries(Object.entries(value).filter(([k]) => !DROPPED.has(k)).map(([k, v]) => [k, strip(v)]))
    : typeof value === "bigint" ? `${value}n` : value;
  const legacyState = mine.state, at = S.head.canonicalTime;
  const requests = [];
  for (const actor of [...S.agents.keys(), "stranger"]) for (const { grant } of S.authorities.values()) for (const action of grant.constraints.actions) for (const resource of grant.constraints.resources) requests.push({ actorId: actor, action, resource, claimedAt: at });
  const answers = (st) => ({
    authorize: requests.map((request) => authority.authorizeState(st, { expectedHistoryHead: st.head, domain: st.genesis.domain, policyVersion: st.genesis.policyVersion, rootRecognitionPolicy: "declared-principal-root/0.2", request, evaluationTime: at, consequential: false })),
    why: requests.map((request) => whyState(st, st, { authorizationDomain: st.genesis.domain, evaluationTime: at, request, disclosure: publicQueryDisclosure("WHY") })),
    survives: [...S.agents.keys(), "stranger"].map((targetAgentId) => survivesState(st, { targetAgentId, evaluationTime: at, disclosure: publicQueryDisclosure("SURVIVES") })),
  });
  const expected = answers(legacyState), actual = answers(T.state);
  assert.ok(expected.authorize.some((r) => r.decision === "ALLOW"));
  for (const kind of ["authorize", "why", "survives"]) assertDecisionParity(actual[kind], expected[kind], { strip, state: T.state, message: kind });
  assert.ok(expected.authorize.some((r, i) => r.decision === "DENY" && r.failures.some((f, j) => f.evidence.length > actual.authorize[i].failures[j].evidence.length)),
    "the fixture exercises narrowed format-1 DENY evidence");
  // Tampering: a prefix that does not reproduce migratedFrom.historyHash, or a runtime-signed event moved out of its legacy head, is rejected.
  const wrongHash = [{ ...genesis, data: { ...genesis.data, migratedFrom: { ...genesis.data.migratedFrom, historyHash: `0x${"6".repeat(64)}` } } }, ...migrated.slice(1)];
  const rejected = replay(wrongHash);
  assert.equal(rejected.code, "CONTROL_AUTHORIZATION_INVALID"); // control events bound the original genesis head
  const shortened = { ...genesis, data: { ...genesis.data, migratedFrom: { ...genesis.data.migratedFrom, position: 13 } } };
  const short = replay([shortened, ...migrated.slice(1)]);
  assert.deepEqual([short.code, short.position], ["CONTROL_AUTHORIZATION_INVALID", 1]);
  // A completed replay must consume the whole declared prefix; incremental application of the prefix stays possible.
  const truncated = replay(migrated.slice(0, 10));
  assert.deepEqual([truncated.code, truncated.reason, truncated.position], ["TRANSITION_INVALID", "migrated prefix incomplete", 10]);
  const partial = createReplayState(TRELLIS);
  assert.equal(replayFrom(partial, migrated.slice(0, 10)).code, "TRANSITION_INVALID");
  assert.equal(partial.events.length, 10);
  assert.equal(replayFrom(partial, migrated.slice(10)).status, "ACCEPTED");
  assert.equal(replay(migrated.slice(0, S.head.position + 1)).status, "ACCEPTED");
  // The store's open path applies the same rule: a file holding only part of the prefix does not open.
  const { createHistoryStore, openHistoryStore } = await import("../src/store.ts");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-shadow-store-"));
  try {
    createHistoryStore(join(dir, "partial.jsonl"), migrated.slice(0, 10));
    assert.throws(() => openHistoryStore(join(dir, "partial.jsonl")).state(), (e) => e.code === "INVALID_HISTORY" && /migrated prefix incomplete/.test(e.message));
    // Created with the owner signer, so the pin carries the owner's attestation that every opener requires.
    const { signerFromKeyPair } = await import("../src/signer.ts");
    createHistoryStore(join(dir, "whole.jsonl"), migrated, { signer: signerFromKeyPair(owner) });
    assert.deepEqual(openHistoryStore(join(dir, "whole.jsonl")).state().head, T.head);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const s2 = createReplayState(TRELLIS);
  assert.equal(applyEvent(s2, shortened).ok, true);
  assert.equal(s2.shadow.until, 13);
  assert.equal(s2.shadow.view.head.hash, S.eventHistoryHashes[0]);
  assert.equal(s2.shadow.view.format, "continuity-event/0.2");
  assert.equal(s2.shadow.view.genesis.domain.chainId, legacyGenesis.data.domain.chainId);
});
