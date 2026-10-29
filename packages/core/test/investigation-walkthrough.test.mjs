// T7 (BUILD §4; LEFT-OUT-SWEEP B16): the eight-step investigation walkthrough of Continuity preview.10.2
// (`reference-0.3/examples/protected-evidence/investigation.mjs`: `investigateDuty` + `retryInvestigation`) on the
// IronTrellis API. The cooperating evidence service of the original is replaced by the per-call execution path
// (`openLocalExecution` with a REMOTE_REPORT adapter) for step 1 (the restriction request whose reply is lost),
// step 4 (the later service report, recorded as an outcome observation) and step 8 (a fresh host retries the recorded
// operations after permission expiry). The gateway itself is G3's. Asserted: the view sequence
// OPEN → COMPLETED_UNDER_POLICY → NEEDS_REVIEW → (COMPLETED_UNDER_POLICY →) CONTESTED, the original prefix and the
// spent allowance untouched, and that retries sign and append nothing.
import test from "node:test";
import assert from "node:assert/strict";
import { closeSync, constants, fstatSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { canonicalEncode, replay, openLocalOwner, openLocalDutyPolicy, openLocalAttemptRecorder, observeHistory, inspectAttemptHistory } = core;
const { fixture } = await import("./helpers/duty-fixture.mjs");

/** `investigation.mjs:12-22`: a host-owned document digest (regular file, one link, ≤ 64 KiB, unchanged while read). */
export function readDocumentDigest(path, expected) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || before.size > 65536) throw new Error("DOCUMENT_UNSUPPORTED");
    const bytes = readFileSync(fd), after = fstatSync(fd);
    if (before.size !== bytes.length || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error("DOCUMENT_CHANGED");
    const digest = { algorithm: "sha256", value: `0x${createHash("sha256").update(bytes).digest("hex")}` };
    if (expected && (expected.algorithm !== digest.algorithm || expected.value !== digest.value)) throw new Error("DOCUMENT_DIGEST_MISMATCH");
    return digest;
  } finally { closeSync(fd); }
}
const criteria = {
  SOURCE_REVIEWED: { state: "SATISFIED", reason: "Host read the selected incident bytes and verified their digest." },
  HISTORY_REVIEWED: { state: "SATISFIED", reason: "Host reviewed the full case and its uncertainty at the report head." },
  FINDING_RECORDED: { state: "SATISFIED", reason: "Local report states the result and remaining outside uncertainty." },
  CONTROL_REVIEWED: { state: "SATISFIED", reason: "Host checked current assignment, revoked and spent powers; restoration is separate." },
};
const stateOf = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED", r.reason); return r.state; };

/** `investigation.mjs:33-77` (`investigateDuty`) on the IronTrellis API: continue a real, already-created E5 case; never creates a case or dispatches a tool. */
async function investigateDuty({ local, dutyId, sourceFile, sourceDigest, reportDirectory, observeAgain, onStage = () => {} }) {
  if (typeof observeAgain !== "function") throw new Error("A real later observation callback is required for this walkthrough");
  const owner = openLocalOwner(local);
  const original = owner.exportHistory(), before = stateOf(original), duty = before.attemptDuties.get(dutyId);
  assert.ok(duty, "Existing duty required"); assert.equal(before.attemptDutyPolicies.has(dutyId), false, "Do not silently restart an investigation");
  const source = readDocumentDigest(sourceFile, sourceDigest);
  const actor = before.runtimeSessions.get(local.session).agentId; assert.equal(duty.currentAssigneeId, actor);
  const duties = openLocalDutyPolicy(local), selection = duties.describe({ duty: dutyId, incidentSourceDigest: source, attesterRole: duty.record.durableRoleId });
  const saved = { version: "irontrellis-investigation-example/1", dutyId, sourceFile, sourceDigest: source, operations: [], documents: [], views: [] };
  const emit = (stage, extra = {}) => onStage({ stage, ...extra });
  const view = () => duties.inspect(dutyId).policy;
  // Step 2: the activation grant names exactly the described resource; activation → OPEN.
  await owner.grant({ id: "investigation:activate", to: actor, actions: [selection.activationAction], resources: [selection.activationResource], expiresAt: 10000 });
  const activated = await duties.activate({ id: "investigation:rules", descriptor: selection.descriptor, activationAuthority: "investigation:activate" });
  assert.equal(activated.view.dutyDisposition, "OPEN"); saved.views.push("OPEN");
  const resource = `duty:${selection.descriptorHash}`;
  for (const [id, action] of [["investigation:attest", "ATTEST_DUTY_FINDING"], ["investigation:dispose", "RECORD_DUTY_DISPOSITION"]]) await owner.grant({ id, to: actor, actions: [action], resources: [resource], expiresAt: 10000 });
  const document = (name, body) => {
    const path = join(reportDirectory, name);
    writeFileSync(path, `${JSON.stringify(body, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    const digest = readDocumentDigest(path); saved.documents.push({ path, digest }); return digest;
  };
  let signs = 0;
  // Every signature re-reads the incident and every report written so far: a changed document aborts before the callback signs.
  const signHash = (hash) => { readDocumentDigest(sourceFile, source); for (const doc of saved.documents) readDocumentDigest(doc.path, doc.digest); signs++; return local.signHash(hash); };
  const writer = openLocalDutyPolicy({ ...local, signHash });
  const permission = { attestationAuthority: "investigation:attest", dispositionAuthority: "investigation:dispose" };
  const complete = async (id, note) => {
    const head = stateOf(owner.exportHistory()).head;
    const reportDigest = document(`${id}.json`, { purpose: "Local investigation report", sourceDigest: source, observedHead: head, note, externalOutcome: "NOT_PROVEN", restoration: "Requires its own permission; it cannot finish this investigation." });
    const input = { id, duty: dutyId, disposition: "COMPLETED_UNDER_POLICY", checklist: criteria, reportDigest, nextStep: null, ...permission };
    const result = await writer.dispose(input); saved.operations.push({ method: "dispose", input });
    assert.equal(result.view.dutyDisposition, "COMPLETED_UNDER_POLICY"); assert.equal(result.view.externalOutcome, "NOT_PROVEN");
    saved.views.push("COMPLETED_UNDER_POLICY");
    emit("investigation-completed", { eventId: result.eventId, reportDigest, head: result.head, externalOutcome: result.view.externalOutcome });
    return result;
  };
  // Step 3: the first completion.
  const first = await complete("investigation:first", "The original result was recovered without repeating restriction. No required local review remains; the outside result is still not proven.");
  // Step 4: a later service report (the per-call path records it) stales the completion.
  await observeAgain(); assert.equal(view().dutyDisposition, "NEEDS_REVIEW"); saved.views.push("NEEDS_REVIEW");
  emit("later-report-needs-review", { priorDisposition: first.eventId, current: "NEEDS_REVIEW" });
  // Step 5: the updated completion reviews the later report.
  const second = await complete("investigation:updated", "The later recorded service observation was reviewed. It adds an attributed report, not external proof.");
  // Step 6: an attributed challenge.
  const challengeDigest = document("investigation-challenge.json", { purpose: "Attributed challenge", target: second.eventId, reason: "Request another review of whether the source report fully describes the incident.", externalOutcome: "NOT_PROVEN" });
  const contest = { id: "investigation:challenge", duty: dutyId, targetDispositionId: second.eventId, reason: "Challenge the completeness of the incident description.", reportDigest: challengeDigest, ...permission };
  const challenged = await writer.contest(contest); saved.operations.push({ method: "contest", input: contest });
  assert.equal(challenged.view.dutyDisposition, "CONTESTED"); assert.equal(challenged.view.outstanding, true); saved.views.push("CONTESTED");
  assert.equal(challenged.view.lastRecordedDisposition.eventId, second.eventId);
  // Step 7: the original prefix and the spent allowance are untouched; the queries show the contest.
  const events = owner.exportHistory(), head = stateOf(events).head;
  assert.equal(canonicalEncode(events.slice(0, original.length)), canonicalEncode(original));
  assert.equal(canonicalEncode([...stateOf(events).authorityUsage]), canonicalEncode([...before.authorityUsage]));
  const query = observeHistory(events).survives(actor);
  assert.equal(query.answer.attemptDuties.find((row) => row.dutyId === dutyId).currentView.dutyDisposition, "CONTESTED");
  assert.equal(inspectAttemptHistory(events).attempts[0].duty.disposition.dutyDisposition, "CONTESTED");
  saved.head = head; saved.eventCount = events.length;
  const retryFile = join(reportDirectory, "investigation-retry.json");
  writeFileSync(retryFile, `${JSON.stringify(saved, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  emit("investigation-contested", { eventId: challenged.eventId, current: "CONTESTED", outstanding: true, originalCreation: duty.record.status, signatures: signs });
  return { retryFile, head, eventCount: events.length, sourceDigest: source, disposition: "CONTESTED", outstanding: true, externalOutcome: "NOT_PROVEN", signatures: signs, views: saved.views };
}

/** `investigation.mjs:80-89` (`retryInvestigation`): a fresh host retries the exact recorded operations after permission expiry; nothing is signed or appended. */
async function retryInvestigation(local, file) {
  const saved = JSON.parse(readFileSync(file, "utf8"));
  readDocumentDigest(saved.sourceFile, saved.sourceDigest); for (const doc of saved.documents) readDocumentDigest(doc.path, doc.digest);
  let signatures = 0;
  const duties = openLocalDutyPolicy({ ...local, now: () => 10001, signHash: async () => { signatures++; throw new Error("RETRY_MUST_NOT_SIGN"); } });
  const before = openLocalOwner(local).exportHistory();
  for (const operation of saved.operations) {
    const result = await duties[operation.method](operation.input);
    assert.equal(result.alreadyRecorded, true); assert.equal(result.view.dutyDisposition, "CONTESTED"); assert.equal(result.view.externalOutcome, "NOT_PROVEN");
  }
  const after = openLocalOwner(local).exportHistory();
  assert.equal(canonicalEncode(after), canonicalEncode(before));
  assert.equal(canonicalEncode(stateOf(after).head), canonicalEncode(saved.head));
  assert.equal(signatures, 0);
  return { signatures, appended: false, current: "CONTESTED", head: stateOf(after).head };
}

test("T7: the eight-step investigation walkthrough on the IronTrellis API — OPEN → COMPLETED_UNDER_POLICY → NEEDS_REVIEW → CONTESTED; retries sign and append nothing", async (t) => {
  // Step 1: a real E5 case — the worker's restriction request ran through the per-call execution path with an unknown outcome, and an investigation duty is open.
  const f = await fixture(t, { policy: "E5" });
  assert.equal(f.result.status, "EXECUTION_RESULT"); assert.equal(f.result.invocation.status, "OUTCOME_UNKNOWN");
  assert.equal(stateOf(f.events).attemptDuties.get("duty").record.status, "OPEN");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-walkthrough-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const sourceFile = join(dir, "incident"); writeFileSync(sourceFile, "incident report: unexpected reader of the restricted document\n");
  const stages = [];
  const identity = () => stateOf(f.events).intentAdmissions.get("job").adapterIdentity;
  // Step 4's later report: the service's signed report acknowledgment, recorded by the attempt recorder (the per-call mode's observation).
  const observeAgain = async () => {
    const acknowledgment = core.createRemoteServiceReportAcknowledgment(identity(), `0x${"d".repeat(64)}`);
    await openLocalAttemptRecorder(f.setupOptions).observe({ id: "later-service-report", intent: "job", acknowledgment });
  };
  const result = await investigateDuty({ local: f.setupOptions, dutyId: "duty", sourceFile, sourceDigest: readDocumentDigest(sourceFile), reportDirectory: dir, observeAgain, onStage: (stage) => stages.push(stage.stage) });
  assert.deepEqual(result.views, ["OPEN", "COMPLETED_UNDER_POLICY", "NEEDS_REVIEW", "COMPLETED_UNDER_POLICY", "CONTESTED"]);
  assert.deepEqual(stages, ["investigation-completed", "later-report-needs-review", "investigation-completed", "investigation-contested"]);
  assert.equal(result.disposition, "CONTESTED"); assert.equal(result.outstanding, true); assert.equal(result.externalOutcome, "NOT_PROVEN");
  assert.equal(result.signatures, 6, "three dual-signature operations: two completions and one contest");
  const events = f.events;
  assert.deepEqual(events.slice(-4).map((e) => e.type), ["ATTEMPT_DUTY_DISPOSITION_RECORDED", "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]);
  assert.equal(replay(events).status, "ACCEPTED");
  const final = stateOf(events);
  assert.equal(final.attemptDutyPolicies.get("duty").dispositionCount, 2); assert.equal(final.attemptDutyPolicies.get("duty").contestCount, 1);
  assert.equal(f.owner.capacity().dutyReserved, 3);
  // Step 8: the grants expire (clock 10001) and a fresh host retries every recorded operation: all alreadyRecorded, no signature, no append.
  const retried = await retryInvestigation(f.setupOptions, result.retryFile);
  assert.equal(retried.signatures, 0); assert.equal(retried.appended, false); assert.equal(retried.current, "CONTESTED");
  assert.equal(canonicalEncode(retried.head), canonicalEncode(result.head));
  assert.equal(f.events.length, result.eventCount);
  // A changed incident file aborts a new finding before its signature (the host's digest check runs inside the signer callback).
  writeFileSync(sourceFile, "tampered\n");
  const writer = openLocalDutyPolicy({ ...f.setupOptions, signHash: (hash) => { readDocumentDigest(sourceFile, result.sourceDigest); return f.setupOptions.signHash(hash); } });
  await assert.rejects(writer.dispose({ id: "investigation:after-tamper", duty: "duty", disposition: "ESCALATED", checklist: { ...criteria, SOURCE_REVIEWED: { state: "UNRESOLVED", reason: "The incident bytes changed." } }, reportDigest: result.sourceDigest, nextStep: "Re-obtain the incident bytes.", attestationAuthority: "investigation:attest", dispositionAuthority: "investigation:dispose" }), (e) => e.code === "SIGNER_FAILED");
  assert.equal(f.events.length, result.eventCount);
});
