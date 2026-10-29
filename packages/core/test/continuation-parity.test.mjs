// T1 continuation parity (BUILD §4; LEFT-OUT-SWEEP §C, C1–C11): the 15 cases of reference-0.3's
// `tests/core-0.3/history.test.mjs`, each run on the same legacy history through the frozen continuation history profile
// (`core-0.3/src/history.ts` over `core-0.2/src/history/index.ts`) and through the IronTrellis state API per the C-row
// mapping — C1 `captureContinuationHistory` → `replay` + `sameHead`; C2 `continuationPrefix` → `replay(prefix)`; C3
// `appendContinuationEvent` → `withProspectiveEvent`; C4 `exportContinuationEvents` → `state.events`; C5 authorize /
// runtime challenge / admission → `authorizeState`, `createRuntimeAuthorizationChallenge`, `proposeIntentAdmissionState`;
// C6 administration → `prepare/attach/produceAdministrativeEventState`; C7 receipts → `createReceiptState`,
// `verifyReceiptState`, `proposeReceiptRecordState`; C8 queries → `whyState`, `responsibleState`, `survivesState`; C9
// observation / attempts → `observeState`, `inspectAttemptHistory`. Results are compared byte for byte after removing the
// `continuity-history-operation/1` envelope (C11). The profile limits of C10 (1,024 events, 6 MiB, 8 KiB per event, 32
// array members, depth 16, 128-event producer prefix) are demonstrated equivalents, not ported rules: where the reference
// refuses on a profile limit, the IronTrellis answer is recorded here as the format's own rule.
import test from "node:test";
import assert from "node:assert/strict";

const R = new URL("../../reference-0.3/", import.meta.url);
const refPath = (rel) => new URL(rel, R).href;
const ref = await import(refPath("packages/core-0.2/src/core/index.ts"));
const h = await import(refPath("packages/core-0.3/src/history.ts"));
const { prepareAdministrativeEvent: refPrepareAdministrative, produceAdministrativeEvent: refProduceAdministrative } = await import(refPath("packages/core-0.2/src/administration/index.ts"));
const { stateOf: refStateOf } = await import(refPath("packages/core-0.3/src/local-store.ts"));
const { captureHistory: refCaptureHistory } = await import(refPath("packages/core-0.3/src/observation.ts"));
const { fixture, capture, padded, authArgs, signHash } = await import(refPath("tests/core-0.3/fixtures/history-fixture.mjs"));
const { openLocalRuntime: refOpenRuntime } = await import(refPath("packages/core-0.3/src/runtime.ts"));

const core = await import("../src/index.ts");
const { canonicalEncode, replay, withProspectiveEvent, sameHead, authorizeState, whyState, responsibleState, survivesState, publicQueryDisclosure } = core;
const { createRuntimeAuthorizationChallenge, hashRuntimeAuthorizationChallenge, proposeIntentAdmissionState, INTENT_ADMISSION_VERSION } = core;
const { prepareAdministrativeEventState, produceAdministrativeEventState, prepareAdministrativeEvent, produceAdministrativeEvent } = core;
const { createReceiptState, verifyReceiptState, verifyReceipt, proposeReceiptRecordState, RECEIPT_VERIFICATION_VERSION, RECEIPT_RECORD_ADMISSION_VERSION } = core;

const code = (c) => (e) => e.code === c;
const plain = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { "$continuity.bigint": x.toString() } : x)));
/** Byte equality of two engine answers (bigint markers spelled the same way on both sides). */
const equal = (mine, theirs, message) => assert.equal(canonicalEncode(plain(mine)), canonicalEncode(plain(theirs)), message);
/** The reference envelope removed (C11): `{version, profile, historyHead, scope, executionCapability, result}` → `result`. */
const unwrap = (envelope) => { assert.equal(envelope.version, h.HISTORY_OPERATION_VERSION); assert.equal(envelope.scope, "CAPTURED_HISTORY_ONLY"); assert.equal(envelope.executionCapability, false); return envelope.result; };
const stateOf = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED", r.reason); return r.state; };
/** The IronTrellis counterpart of a captured continuation handle: the replayed state whose head the caller checked (C1). */
const handleOf = (events, expectedHead) => { const state = stateOf(events); assert.equal(sameHead(state.head, expectedHead), true); return state; };
const authBody = (state, args) => ({ expectedHistoryHead: state.head, domain: args.domain, policyVersion: args.policyVersion, rootRecognitionPolicy: args.rootRecognitionPolicy, request: args.request, evaluationTime: args.evaluationTime, consequential: args.consequential, ...(args.binding === undefined ? {} : { binding: args.binding }) });
let compared = 0;
const parity = (mine, theirs, message) => { equal(mine, theirs, message); compared += 1; };

test("T1-1 captured history is immutable, exact-head bound and preserves every prefix (C1, C2, C4)", async (t) => {
  const f = await fixture(t), events = padded(f.events, 320), view = capture(events);
  const state = handleOf(events, view.head);
  assert.equal(view.eventCount, 320); assert.equal(state.events.length, 320);
  assert.equal(state.head.hash, ref.hashEventHistory(events)); assert.equal(view.head.hash, state.head.hash);
  for (const position of [0, 1, f.events.length - 1, 95, 127, 255, 319]) {
    const prefix = h.continuationPrefix(view, position);
    parity(replay(events.slice(0, position + 1)).head, prefix.head, `prefix ${position}`);
    assert.equal(state.eventHistoryHashes[position], prefix.head.hash);
  }
  // C4: the captured events are frozen copies on both sides; a later mutation of the input never reaches them.
  events.at(-1).data.principalId = "changed";
  assert.equal(h.exportContinuationEvents(view).at(-1).data.principalId, "extra:319"); assert.equal(state.events.at(-1).data.principalId, "extra:319");
  assert.throws(() => h.exportContinuationEvents(view).push({}));
  assert.throws(() => core.observeHistory(events).head.hash = "x", "the observation's head is frozen (the state's own event array is engine-internal; the host API hands out copies)");
  // A wrong expected head: HEAD_MISMATCH on the reference, `sameHead` false on the state API.
  assert.throws(() => h.captureContinuationHistory({ operationVersion: h.CONTINUATION_HISTORY_VERSION, events: f.events, expectedHead: { ...f.handle.head, hash: `0x${"0".repeat(64)}` } }), code("HEAD_MISMATCH"));
  assert.equal(sameHead(stateOf(f.events).head, { ...f.handle.head, hash: `0x${"0".repeat(64)}` }), false);
  // C10: the reference's older 128-event observation capture refuses a 320-event history; IronTrellis histories are unbounded (`capacity` is declared per deployment).
  assert.throws(() => refCaptureHistory(h.exportContinuationEvents(view)), code("HISTORY_LIMIT"));
  assert.equal(core.observeHistory(events).eventCount, 320);
});

test("T1-2 copied, forged, foreign-module and serialized handles never acquire state authority (C1, C11)", async (t) => {
  const f = await fixture(t);
  let reads = 0;
  const hostile = new Proxy({}, { get() { reads++; throw new Error("read"); } });
  for (const fake of [{ ...f.handle }, JSON.parse(JSON.stringify(f.handle)), {}, null, hostile]) {
    assert.throws(() => h.authorizeContinuation(fake, hostile), code("INVALID_HISTORY_HANDLE"));
    await assert.rejects(h.produceContinuationAdministration(fake, hostile, hostile), code("INVALID_HISTORY_HANDLE"));
  }
  // The state API's handle is the replayed state itself: a copy of its head, a serialized handle, an empty record or null is no state and answers nothing.
  const state = stateOf(f.events);
  for (const fake of [{ ...f.handle }, JSON.parse(JSON.stringify(f.handle)), {}, null]) {
    let answer;
    try { answer = authorizeState(fake, authBody(state, authArgs(f.events))); } catch { answer = undefined; }
    assert.ok(answer === undefined || answer.decision === "INDETERMINATE", "a fake state never answers ALLOW or DENY");
    await assert.rejects(produceAdministrativeEventState(fake, hostile, hostile));
  }
  assert.equal(reads, 0);
  // Provenance on the reference is a WeakMap of minted handles; the IronTrellis equivalent is `replay` of the file's own bytes (the store's state) — no copy of a state carries the store's authority either.
  assert.equal(h.exportContinuationEvents(f.handle).length, state.events.length);
});

test("T1-3 one captured input preserves getter values, rejects omitted undefined and sparse histories (C1 capture)", async (t) => {
  const f = await fixture(t);
  let reads = 0;
  const events = [...f.events], original = events[2];
  events[2] = { ...original, get data() { reads++; return reads === 1 ? original.data : { agentId: "forged" }; } };
  const view = h.captureContinuationHistory({ operationVersion: h.CONTINUATION_HISTORY_VERSION, events, expectedHead: f.handle.head });
  assert.equal(reads, 1); assert.equal(view.head.hash, f.handle.head.hash);
  // IronTrellis refuses the accessor-backed event (the schema sees the getter's later value and the closed shape fails: SPEC §5 "envelope/capture");
  // the reference captured the first value once. Replay reads a raw in-process event more than once (the store's lines are parsed JSON, never
  // accessors): a capture-order difference, not a rule — noted for E5/G3 in E4-NOTES.
  reads = 0;
  const mine = replay(events);
  assert.equal(mine.status, "REJECTED"); assert.ok(["INVALID_INPUT", "EVENT_DATA_INVALID"].includes(mine.code), mine.code); assert.equal(mine.position, 2); assert.ok(reads >= 1);
  parity(stateOf(f.events).events[2], h.exportContinuationEvents(view)[2], "the captured event (from the plain history)");
  // An undefined-valued field is refused by both captures (an omitted key must not silently vanish).
  const bad = [...f.events]; bad[2] = { ...original, hidden: undefined };
  assert.throws(() => capture(bad), code("INVALID_INPUT"));
  const dropped = replay(bad);
  assert.equal(dropped.status, "REJECTED"); assert.equal(dropped.position, 2);
  // A sparse history is refused by both.
  const sparse = [...f.events]; delete sparse[2];
  assert.throws(() => h.captureContinuationHistory({ operationVersion: h.CONTINUATION_HISTORY_VERSION, events: sparse, expectedHead: f.handle.head }));
  assert.equal(replay(sparse).status, "REJECTED");
});

test("T1-4 authorization and all three queries preserve old results on common prefixes (C5, C8)", async (t) => {
  const f = await fixture(t), args = authArgs(f.events), state = handleOf(f.events, f.handle.head);
  parity(authorizeState(state, authBody(state, args)), unwrap(h.authorizeContinuation(f.handle, args)), "authorize");
  for (const kind of ["WHY", "RESPONSIBLE", "SURVIVES"]) {
    const extra = kind === "SURVIVES" ? { targetAgentId: "worker" } : { authorizationDomain: f.config.domain, request: args.request };
    const input = { ...extra, evaluationTime: 100, disclosure: ref.portablePublicQueryDisclosure(kind) };
    const theirs = unwrap(h.queryContinuation(kind, f.handle, f.handle, input));
    const mine = kind === "SURVIVES" ? survivesState(state, { ...input, disclosure: publicQueryDisclosure(kind) }) : (kind === "WHY" ? whyState : responsibleState)(state, state, { ...input, disclosure: publicQueryDisclosure(kind) });
    parity(mine, theirs, kind);
  }
});

test("T1-5 spent authority and revoked authority remain denied after a 1,024-event replay (C5; C10 limits)", async (t) => {
  const f = await fixture(t), events = padded(f.events, 1024), view = capture(events), state = handleOf(events, view.head);
  for (const action of ["inspect", "export"]) {
    const theirs = unwrap(h.authorizeContinuation(view, authArgs(events, action)));
    assert.equal(theirs.decision, "DENY");
    parity(authorizeState(state, authBody(state, authArgs(events, action))), theirs, action);
  }
  const copied = { ...events.at(-1), id: "new-event", data: { principalId: "another" } };
  // C10: the 1,024-event profile refuses the 1,025th on the reference; IronTrellis admits it (no fixed history length) and its head is the chain's.
  assert.throws(() => h.appendContinuationEvent(view, copied), code("HISTORY_LIMIT"));
  assert.throws(() => capture(padded(f.events, 1025)), code("HISTORY_LIMIT"));
  const next = withProspectiveEvent(state, copied);
  assert.equal(next.ok, true); assert.equal(next.head.position, 1024); assert.equal(next.head.hash, ref.hashEventHistory([...events, copied]));
});

test("T1-6 historical queries and recorded receipts remain independently verifiable beyond 256 (C7, C8)", async (t) => {
  const f = await fixture(t), laterEvents = padded(f.events, 320), later = capture(laterEvents);
  const artifact = f.receipt.artifact; assert.ok(artifact);
  const input = { artifact, expectedDomain: f.config.domain, verifierTime: 100 };
  const theirs = unwrap(h.verifyContinuationReceipt(f.handle, later, input));
  assert.equal(theirs.status, "EVALUATED"); assert.equal(theirs.historical, true);
  // Two histories (issuance, observed): the portable `verifyReceipt`; the state form `verifyReceiptState` is the one-history case (issuance = observed = state.events, spec 03 §G.3 "related" issuance).
  const observed = handleOf(laterEvents, later.head);
  parity(verifyReceipt({ operationVersion: RECEIPT_VERIFICATION_VERSION, issuanceEvents: f.events, observedEvents: laterEvents, ...input }), theirs, "verifyReceipt");
  parity(verifyReceiptState(handleOf(f.events, f.handle.head), { operationVersion: RECEIPT_VERIFICATION_VERSION, ...input }), unwrap(h.verifyContinuationReceipt(f.handle, f.handle, input)), "verifyReceiptState (one history)");
  const query = { authorizationDomain: f.config.domain, request: authArgs(f.events).request, evaluationTime: 100 };
  const why = unwrap(h.queryContinuation("WHY", f.handle, later, { ...query, disclosure: ref.portablePublicQueryDisclosure("WHY") }));
  assert.equal(why.scope.headRelationship, "STRICT_EXTENSION"); assert.equal(why.scope.freshness, "AT_EVALUATION");
  parity(whyState(handleOf(f.events, f.handle.head), observed, { ...query, disclosure: publicQueryDisclosure("WHY") }), why, "why");
});

test("T1-7 the administrative path signs duty observations after 256 (C6, C8; the 128-event producer prefix is C10)", async (t) => {
  const f = await fixture(t, { policy: "E5" }), events = padded(f.events, 320), view = capture(events), state = handleOf(events, view.head);
  const admission = f.events.find((e) => e.type === "TRANSACTION_INTENT_ADMITTED");
  const identity = refStateOf(f.events).intentAdmissions.get("job").adapterIdentity;
  const ack = ref.createRemoteServiceReportAcknowledgment(identity, `0x${"b".repeat(64)}`);
  const transition = { id: "late-report", type: "OUTCOME_OBSERVATION_RECORDED", timestamp: 100, data: { intentId: "job", sourceAdmissionEventId: admission.id, acknowledgment: ack, actorId: "worker" } };
  const input = { expectedDomain: f.config.domain, expectedHistoryHead: view.head, runtimeSessionId: "session", transition };
  // C10: the reference's portable producer caps its prefix at 128 events; IronTrellis' portable producer replays any prefix.
  assert.throws(() => refPrepareAdministrative({ ...input, events: h.exportContinuationEvents(view) }), (e) => e.code === "INPUT_LIMIT");
  const minePortable = prepareAdministrativeEvent({ ...input, events });
  const theirs = unwrap(await h.produceContinuationAdministration(view, input, { signHash }));
  const mine = await produceAdministrativeEventState(state, input, { signHash });
  parity(mine.event, theirs.event, "the produced event"); parity(mine.challenge, theirs.challenge, "challenge"); parity(mine.signingHash, theirs.signingHash, "signingHash");
  parity(minePortable.challenge, theirs.challenge, "portable prepare");
  const nextTheirs = h.appendContinuationEvent(view, theirs.event), nextMine = withProspectiveEvent(state, mine.event);
  assert.equal(nextTheirs.eventCount, 321); assert.equal(nextMine.ok, true); assert.equal(nextMine.head.hash, nextTheirs.head.hash);
  const q = { targetAgentId: "worker", evaluationTime: 100 };
  const answerTheirs = unwrap(h.queryContinuation("SURVIVES", nextTheirs, nextTheirs, { ...q, disclosure: ref.portablePublicQueryDisclosure("SURVIVES") }));
  assert.equal(answerTheirs.epistemicStatus, "ESTABLISHED"); assert.equal(answerTheirs.answer.attemptDuties[0].status, "OPEN");
  parity(survivesState(nextMine.state, { ...q, disclosure: publicQueryDisclosure("SURVIVES") }), answerTheirs, "survives after the observation");
});

test("T1-8 a fresh runtime admission after 256 binds the original domain, nonce and exact head (C3, C5)", async (t) => {
  const f = await fixture(t);
  f.owner.grant({ id: "followup", to: "worker", actions: ["followup"], resources: ["incident"], expiresAt: 10000, maxTransactions: 1 });
  const prior = f.owner.exportHistory(), declaration = prior.find((e) => e.type === "TRANSACTION_INTENT_DECLARED");
  const base = padded(prior, 320);
  const declared = { ...declaration, id: "declaration:followup", data: { ...declaration.data, intentId: "followup", nonce: "operation:followup", action: "followup" } };
  let view = capture(base); view = h.appendContinuationEvent(view, declared);
  const events = [...base, declared], state = handleOf(events, view.head);
  const binding = { runtimeSessionId: "session", credentialKeyId: "key", controlEpoch: 1, roleId: "role", roleTenureId: "tenure", intentId: "followup", nonce: "operation:followup" };
  const args = { domain: f.config.domain, request: { actorId: "worker", action: "followup", resource: "incident", claimedAt: 100, termsCommitment: f.op.termsCommitment }, evaluationTime: 100, policyVersion: prior[0].data.policyVersion, binding };
  const challenge = unwrap(h.continuationRuntimeChallenge(view, args));
  const mineChallenge = createRuntimeAuthorizationChallenge({ ...args, historyHead: state.head });
  parity(mineChallenge, challenge, "runtime challenge");
  const signature = await signHash(ref.hashPortableRuntimeAuthorizationChallenge(challenge));
  assert.equal(hashRuntimeAuthorizationChallenge(mineChallenge, "keccak256"), ref.hashPortableRuntimeAuthorizationChallenge(challenge));
  const input = { ...args, admissionEventId: "admit:followup", binding: { ...binding, runtimeSignature: signature } };
  const proposed = unwrap(h.proposeContinuationAdmission(view, input));
  assert.equal(proposed.status, "PROPOSED");
  const mine = proposeIntentAdmissionState(state, { operationVersion: INTENT_ADMISSION_VERSION, expectedHistoryHead: state.head, ...input });
  parity(mine, proposed, "proposal");
  const next = h.appendContinuationEvent(view, proposed.admissionEvent), nextMine = withProspectiveEvent(state, mine.admissionEvent);
  assert.equal(next.eventCount, 322); assert.equal(nextMine.ok, true); assert.equal(nextMine.head.hash, next.head.hash);
  const repeat = unwrap(h.proposeContinuationAdmission(next, input)), repeatMine = proposeIntentAdmissionState(nextMine.state, { operationVersion: INTENT_ADMISSION_VERSION, expectedHistoryHead: nextMine.state.head, ...input });
  assert.equal(repeat.status, "RETRY"); parity(repeatMine, repeat, "repeat");
  const changed = unwrap(h.proposeContinuationAdmission(view, { ...input, request: { ...args.request, resource: "elsewhere" } }));
  const changedMine = proposeIntentAdmissionState(state, { operationVersion: INTENT_ADMISSION_VERSION, expectedHistoryHead: state.head, ...input, request: { ...args.request, resource: "elsewhere" } });
  assert.notEqual(changed.status, "PROPOSED"); parity(changedMine, changed, "changed request");
  const intervening = { id: "intervening", type: "PRINCIPAL_CREATED", timestamp: 100, data: { principalId: "intervening" } };
  const drift = h.appendContinuationEvent(view, intervening), driftMine = withProspectiveEvent(state, intervening);
  const driftTheirs = unwrap(h.proposeContinuationAdmission(drift, input)), driftOurs = proposeIntentAdmissionState(driftMine.state, { operationVersion: INTENT_ADMISSION_VERSION, expectedHistoryHead: driftMine.state.head, ...input });
  assert.notEqual(driftTheirs.status, "PROPOSED"); parity(driftOurs, driftTheirs, "drifted head");
});

test("T1-9 create and record a new receipt above 256, then verify its original prefix (C7)", async (t) => {
  const f = await fixture(t, { recordReceipt: false }), events = padded(f.events, 320), view = capture(events), state = handleOf(events, view.head);
  let calls = 0;
  const signer = { keyId: "key", signHash: async (hash) => { calls++; return signHash(hash); } };
  const theirs = unwrap(await h.createContinuationReceipt(view, { intentId: "job", issuedAt: 100, externalOutcome: "SIMULATED" }, signer));
  assert.equal(calls, 1);
  const mine = await createReceiptState(state, { intentId: "job", issuedAt: 100, externalOutcome: "SIMULATED" }, signer);
  parity(mine, theirs, "receipt artifact");
  const input = { artifact: theirs, expectedDomain: f.config.domain, recordEventId: "receipt:late" };
  const proposal = unwrap(h.proposeContinuationReceiptRecord(view, input)), proposalMine = proposeReceiptRecordState(state, { operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, expectedHistoryHead: state.head, ...input });
  assert.equal(proposal.status, "PROPOSED"); parity(proposalMine, proposal, "record proposal");
  const next = h.appendContinuationEvent(view, proposal.recordEvent), nextMine = withProspectiveEvent(state, proposalMine.recordEvent);
  assert.equal(nextMine.head.hash, next.head.hash);
  const verification = { artifact: theirs, expectedDomain: f.config.domain, verifierTime: 100 };
  const current = unwrap(h.verifyContinuationReceipt(next, next, verification));
  assert.equal(current.current, true); parity(verifyReceiptState(nextMine.state, { operationVersion: RECEIPT_VERIFICATION_VERSION, ...verification }), current, "current verification");
  const laterEvent = { id: "later", type: "PRINCIPAL_CREATED", timestamp: 101, data: { principalId: "later" } };
  const later = h.appendContinuationEvent(next, laterEvent), laterMine = withProspectiveEvent(nextMine.state, laterEvent);
  const historical = unwrap(h.verifyContinuationReceipt(next, later, { ...verification, verifierTime: 101 }));
  assert.equal(historical.historical, true); assert.equal(historical.canonicalInclusion.status, "PASS");
  // Two histories again (issuance = the recorded prefix, observed = one event later): the portable form.
  parity(verifyReceipt({ operationVersion: RECEIPT_VERIFICATION_VERSION, issuanceEvents: [...events, proposalMine.recordEvent], observedEvents: [...events, proposalMine.recordEvent, laterEvent], ...verification, verifierTime: 101 }), historical, "historical verification");
});

test("T1-10 an E6 evidence review after 256 keeps the unresolved duty OPEN (C6, C8)", async (t) => {
  const f = await fixture(t, { policy: "E6" }), events = padded(f.events, 320), view = capture(events), state = handleOf(events, view.head);
  const input = { expectedDomain: f.config.domain, expectedHistoryHead: view.head, runtimeSessionId: "session", transition: { id: "review:late", type: "ATTEMPT_DUTY_REVIEW_CLOSED", timestamp: 100, data: { dutyId: "duty", actorId: "worker", observationEventIds: [], summaryDigest: `0x${"a".repeat(64)}` } } };
  const theirs = unwrap(await h.produceContinuationAdministration(view, input, { signHash })), mine = await produceAdministrativeEventState(state, input, { signHash });
  parity(mine.event, theirs.event, "review event");
  const next = h.appendContinuationEvent(view, theirs.event), nextMine = withProspectiveEvent(state, mine.event);
  const q = { targetAgentId: "worker", evaluationTime: 100 };
  const answer = unwrap(h.queryContinuation("SURVIVES", next, next, { ...q, disclosure: ref.portablePublicQueryDisclosure("SURVIVES") }));
  assert.equal(answer.epistemicStatus, "ESTABLISHED"); assert.equal(answer.answer.attemptDuties[0].status, "OPEN"); assert.equal(answer.answer.attemptDuties[0].reviewStatus, "REVIEW_CLOSED");
  parity(survivesState(nextMine.state, { ...q, disclosure: publicQueryDisclosure("SURVIVES") }), answer, "survives");
  parity(core.inspectAttemptHistory([...events, mine.event]).attempts, (await import(refPath("packages/core-0.3/src/attempts.ts"))).inspectContinuationAttempts(next).attempts, "inspectAttemptHistory (C9)");
});

test("T1-11 overfull and oversize signed events refuse before signer invocation (C6; C10 limits)", async (t) => {
  const f = await fixture(t, { policy: "E6" }), events = padded(f.events, 1024), view = capture(events), state = handleOf(events, view.head);
  let calls = 0;
  const input = { expectedDomain: f.config.domain, expectedHistoryHead: view.head, runtimeSessionId: "session", transition: { id: "review:late", type: "ATTEMPT_DUTY_REVIEW_CLOSED", timestamp: 100, data: { dutyId: "duty", actorId: "worker", observationEventIds: [], summaryDigest: `0x${"a".repeat(64)}` } } };
  // C10: at 1,024 events the profile refuses before the signer; IronTrellis has no fixed length and produces the event (the same callback, one signature).
  await assert.rejects(h.produceContinuationAdministration(view, input, { signHash: async (hash) => { calls++; return signHash(hash); } }), code("HISTORY_LIMIT")); assert.equal(calls, 0);
  const mine = await produceAdministrativeEventState(state, input, { signHash: async (hash) => { calls++; return signHash(hash); } });
  assert.equal(calls, 1); assert.equal(mine.event.id, "review:late");
  // An oversize event (a 9,000-character principalId): EVENT_LIMIT on the profile; EVENT_DATA_INVALID (identifier ≤ 256 bytes, spec 01) on the schema.
  const oversize = [...f.events, { id: "oversize", type: "PRINCIPAL_CREATED", timestamp: 100, data: { principalId: "x".repeat(9000) } }];
  assert.throws(() => h.captureContinuationHistory({ operationVersion: h.CONTINUATION_HISTORY_VERSION, events: oversize, expectedHead: f.handle.head }), code("EVENT_LIMIT"));
  const rejected = replay(oversize);
  assert.equal(rejected.status, "REJECTED"); assert.ok(["EVENT_DATA_INVALID", "INVALID_INPUT"].includes(rejected.code), rejected.code); assert.equal(rejected.position, oversize.length - 1);
});

test("T1-12 administrative parity on a common prefix and changing input during signing (C6)", async (t) => {
  const f = await fixture(t, { policy: "E6" }), state = handleOf(f.events, f.handle.head);
  const input = { expectedDomain: f.config.domain, expectedHistoryHead: f.handle.head, runtimeSessionId: "session", transition: { id: "review:common", type: "ATTEMPT_DUTY_REVIEW_CLOSED", timestamp: 100, data: { dutyId: "duty", actorId: "worker", observationEventIds: [], summaryDigest: `0x${"a".repeat(64)}` } } };
  const prepared = unwrap(h.prepareContinuationAdministration(f.handle, input));
  parity(prepared, refPrepareAdministrative({ ...input, events: f.events }), "reference portable = continuation");
  parity(prepareAdministrativeEventState(state, input), prepared, "prepare (state)");
  parity(prepareAdministrativeEvent({ ...input, events: f.events }), prepared, "prepare (portable)");
  const normal = await refProduceAdministrative({ ...input, events: f.events }, { signHash });
  parity(await produceAdministrativeEvent({ ...input, events: f.events }, { signHash }), normal, "produce (portable)");
  const original = input.transition.data.summaryDigest;
  const produced = unwrap(await h.produceContinuationAdministration(f.handle, input, { signHash: async (hash) => { input.transition.data.summaryDigest = `0x${"b".repeat(64)}`; return signHash(hash); } }));
  assert.deepEqual(plain(produced), plain(normal)); assert.equal(produced.event.data.summaryDigest, original);
  input.transition.data.summaryDigest = original;
  const mine = await produceAdministrativeEventState(state, input, { signHash: async (hash) => { input.transition.data.summaryDigest = `0x${"b".repeat(64)}`; return signHash(hash); } });
  parity(mine, produced, "produce with input mutation during signing");
  input.transition.data.summaryDigest = original;
});

test("T1-13 signed obligation and attempt duty creation fit at 1,023 events without resetting provenance (C6, C8)", async (t) => {
  const normal = await fixture(t);
  await refOpenRuntime(normal.options).obligate({ id: "obligation", operation: "job", description: "Complete investigation", deadline: 10000, succession: "succession", reviewAuthority: "record" });
  const obligation = normal.owner.exportHistory().at(-1);
  const attempt = await fixture(t, { policy: "E6" }), duty = attempt.events.at(-1);
  for (const [f, event, prior] of [[normal, obligation, normal.events], [attempt, duty, attempt.events.slice(0, -1)]]) {
    const events = padded(prior, 1023), view = capture(events), state = handleOf(events, view.head);
    const { administrativeAuthorization: _old, ...originalData } = event.data;
    const data = { ...originalData, record: { ...originalData.record, description: "Investigation ".padEnd(1024, "x") } };
    const input = { expectedDomain: f.config.domain, expectedHistoryHead: view.head, runtimeSessionId: "session", transition: { ...event, data } };
    const theirs = unwrap(await h.produceContinuationAdministration(view, input, { signHash })), mine = await produceAdministrativeEventState(state, input, { signHash });
    parity(mine.event, theirs.event, `${event.type} at 1,023`);
    const next = h.appendContinuationEvent(view, theirs.event), nextMine = withProspectiveEvent(state, mine.event);
    assert.equal(next.eventCount, 1024); assert.equal(nextMine.head.hash, next.head.hash);
    assert.equal(theirs.event.data.administrativeAuthorization.challenge.eventHistoryHash, view.head.hash);
    const q = { targetAgentId: "worker", evaluationTime: 100 };
    const answer = unwrap(h.queryContinuation("SURVIVES", next, next, { ...q, disclosure: ref.portablePublicQueryDisclosure("SURVIVES") }));
    assert.equal(answer.epistemicStatus, "ESTABLISHED");
    assert.equal(event.type === "OBLIGATION_CREATED" ? answer.answer.obligations[0].status : answer.answer.attemptDuties[0].status, "OPEN");
    parity(survivesState(nextMine.state, { ...q, disclosure: publicQueryDisclosure("SURVIVES") }), answer, `survives after ${event.type}`);
  }
});

test("T1-14 event shape and total byte budgets refuse before a handle is minted (C10 limits; C1 capture)", async (t) => {
  const f = await fixture(t);
  const base = { id: "shape", type: "PRINCIPAL_CREATED", timestamp: 100, data: { principalId: "shape" } };
  let nested = {}; for (let i = 0; i < 18; i++) nested = { next: nested };
  // The profile's per-event shape bounds (32 array members, depth 16, 8 KiB) refuse; IronTrellis refuses the same events by its closed schema (`extra` is not a PRINCIPAL_CREATED field: EVENT_DATA_INVALID).
  for (const extra of [{ members: Array(33).fill(0) }, nested, { members: Array(32).fill(Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`a${i}`, 0]))) }]) {
    const events = [...f.events, { ...base, data: { ...base.data, extra } }];
    assert.throws(() => h.captureContinuationHistory({ operationVersion: h.CONTINUATION_HISTORY_VERSION, events, expectedHead: f.handle.head }), code("EVENT_LIMIT"));
    const rejected = replay(events);
    assert.equal(rejected.status, "REJECTED"); assert.equal(rejected.position, events.length - 1);
  }
  // Individually bounded synthetic records exceeding the 6 MiB aggregate: HISTORY_LIMIT on the profile; IronTrellis has no aggregate bound (SPEC §4.5: 1 GiB per file) and rejects these records only on their schema (an 3,500-byte principalId exceeds the identifier bound).
  const fat = { ...base, data: { a: "a".repeat(3500), b: "b".repeat(3500) } };
  const fatHistory = Array.from({ length: 1000 }, (_, i) => ({ ...fat, id: `fat:${i}` }));
  assert.throws(() => h.captureContinuationHistory({ operationVersion: h.CONTINUATION_HISTORY_VERSION, events: fatHistory, expectedHead: f.handle.head }), code("HISTORY_LIMIT"));
  assert.equal(replay(fatHistory).status, "REJECTED");
  // A corrupted type: INVALID_HISTORY on the profile, UNSUPPORTED_EVENT_TYPE at the same position on replay.
  const corrupted = [...f.events]; corrupted[2] = { ...corrupted[2], type: "NOT_AN_EVENT" };
  assert.throws(() => h.captureContinuationHistory({ operationVersion: h.CONTINUATION_HISTORY_VERSION, events: corrupted, expectedHead: f.handle.head }), code("INVALID_HISTORY"));
  const bad = replay(corrupted);
  assert.equal(bad.status, "REJECTED"); assert.equal(bad.code, "UNSUPPORTED_EVENT_TYPE"); assert.equal(bad.position, 2);
});

test("T1-15 wide denial graphs retain explicit output exhaustion; they never become permission (C5)", async (t) => {
  const f = await fixture(t), events = padded(f.events, 96, { wide: true }), view = capture(events), state = handleOf(events, view.head);
  const theirs = unwrap(h.authorizeContinuation(view, authArgs(events)));
  assert.equal(theirs.decision, "INDETERMINATE"); assert.equal(theirs.code, "OUTPUT_LIMIT_EXCEEDED");
  parity(authorizeState(state, authBody(state, authArgs(events))), theirs, "wide graph");
  assert.deepEqual(plain(theirs), plain(ref.authorizePortable({ ...authArgs(events), operationVersion: ref.PORTABLE_AUTHORIZATION_VERSION, events, expectedHistoryHead: view.head })));
  t.diagnostic(`T1: ${compared} answers byte-equal after removing the envelope`);
});
