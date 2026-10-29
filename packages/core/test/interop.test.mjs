/**
 * Cross-engine interoperability on legacy (`continuity-event/0.2`) histories.
 *
 * The same scenario is driven through (a) the reference Core 0.3 SDK on the
 * reference Core 0.2 engine and (b) this port on the IronTrellis engine, with
 * fixed clocks, the public dev keys 1001/1003 and a deterministic id
 * generator (`crypto.randomUUID` is replaced for the reference; the port takes
 * `ids`). With identical inputs the two files must be byte-identical
 * (signatures are RFC 6979 deterministic). Then each engine reads the other's
 * file and every query answer must be deep-equal across engines and files.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------- deterministic ids for both engines
const require = createRequire(import.meta.url);
const nodeCrypto = require("node:crypto");
const ids = { n: 0, next: () => `00000000-0000-4000-8000-${String(++ids.n).padStart(12, "0")}` };
nodeCrypto.randomUUID = ids.next;
syncBuiltinESMExports();

import { referenceCore as refCore, referenceCore03, viemAccounts } from "./reference.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling
const refOwner = await referenceCore03("local-owner.ts");
const refSimulation = await referenceCore03("simulation.ts");
const refRuntime = await referenceCore03("runtime.ts");
const refAttempts = await referenceCore03("attempts.ts");
const refExecution = await referenceCore03("execution.ts");
const refIndex = await referenceCore03("index.ts");
const { privateKeyToAccount } = viemAccounts;

const owner = await import("../src/owner.ts");
const simulation = await import("../src/simulation.ts");
const runtime = await import("../src/runtime.ts");
const attempts = await import("../src/attempts.ts");
const execution = await import("../src/execution.ts");
const observation = await import("../src/observation.ts");
const editions = await import("../src/adapter-editions.ts");
const admission = await import("../src/admission.ts");
const { keyPairFromPrivateKey, signHashWith } = await import("../src/crypto/suites.ts");
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { LEGACY_FORMAT } = await import("../src/events.ts");

const KEYS = {
  a: "0x00000000000000000000000000000000000000000000000000000000000003e9", // dev scalar 1001
  b: "0x00000000000000000000000000000000000000000000000000000000000003eb", // dev scalar 1003
};
const addressOf = (key) => privateKeyToAccount(key).address;
const norm = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x)));
const same = (actual, expected, message) => assert.deepEqual(norm(actual), norm(expected), message);
const DOMAIN = { protocol: "continuity", version: "0.2", deploymentId: "interop:core-0.3", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000000" };

// ---------------------------------------------------------------- the two engines behind one interface
/** The reference SDK: synchronous owner writes, viem EIP-191 signing. */
const theirs = {
  name: "reference",
  signer: (key) => { const account = privateKeyToAccount(key); return (hash) => account.signMessage({ message: { raw: hash } }); },
  createLocalOwner: (config) => refOwner.createLocalOwner(config),
  createLocalReviewOwner: (config) => refOwner.createLocalReviewOwner(config),
  openLocalOwner: (config) => refOwner.openLocalOwner(config),
  openLocalSimulation: (options) => refSimulation.openLocalSimulation(options),
  openLocalRuntime: (options) => refRuntime.openLocalRuntime(options),
  openLocalAttemptRecorder: (options) => refAttempts.openLocalAttemptRecorder(options),
  openLocalExecution: (options, adapter, mode) => refExecution.openLocalExecution(options, adapter, mode),
  inspectAttemptHistory: (events) => refAttempts.inspectAttemptHistory(events),
  commitTerms: (terms) => refSimulation.commitTerms(terms),
  observeHistory: (events, options) => refIndex.observeHistory(events, options),
  reportProfile: () => refCore.approvedPortableAdapterProfileForPolicy(refCore.PORTABLE_ADAPTER_POLICY_E6_HASH, refCore.REMOTE_SERVICE_REPORT_ADAPTER_ID),
  identity: (submission) => refCore.derivePortableAdapterIdentity(submission),
  reportAcknowledgment: (identity, digest) => refCore.createRemoteServiceReportAcknowledgment(identity, digest),
};
/** This port: async writes (awaited uniformly), the engine's own signer over the same dev keys. */
const mine = {
  name: "irontrellis",
  signer: (key) => signHashWith(keyPairFromPrivateKey("eip191-personal-sign-keccak256", "dev", key)),
  createLocalOwner: (config) => owner.createLocalOwner({ ...config, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true, ids: ids.next }),
  createLocalReviewOwner: (config) => owner.createLocalReviewOwner({ ...config, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true, ids: ids.next }),
  // The legacy writer by name: the port writes format 2 by default and opens legacy files read only (SPEC §16.1).
  openLocalOwner: (config) => owner.openLocalOwner({ ...config, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true, ids: ids.next }),
  openLocalSimulation: (options) => simulation.openLocalSimulation({ ...options, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true, ids: ids.next }),
  openLocalRuntime: (options) => runtime.openLocalRuntime({ ...options, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true, ids: ids.next }),
  openLocalAttemptRecorder: (options) => attempts.openLocalAttemptRecorder({ ...options, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true, ids: ids.next }),
  openLocalExecution: (options, adapter, mode) => execution.openLocalExecution({ ...options, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true, ids: ids.next }, adapter, mode),
  inspectAttemptHistory: (events) => attempts.inspectAttemptHistory(events),
  commitTerms: (terms) => simulation.commitTerms(terms),
  observeHistory: (events, options) => observation.observeHistory(events, options),
  reportProfile: () => editions.approvedAdapterProfileForPolicy(editions.ADAPTER_POLICY_E6_HASH, editions.REMOTE_SERVICE_REPORT_ADAPTER_ID),
  identity: (submission) => admission.deriveAdapterIdentity(submission),
  reportAcknowledgment: (identity, digest) => editions.createRemoteServiceReportAcknowledgment(identity, digest),
};

/** A remote-service-report adapter whose reply is lost (OUTCOME_UNKNOWN) but whose identity is retained for a later observation. */
const lostReplyAdapter = (E) => {
  const held = { identity: undefined };
  const unknown = (submission) => {
    held.identity = E.identity(submission);
    return { status: "OUTCOME_UNKNOWN", idempotencyKey: held.identity.idempotencyKey, submissionFingerprint: held.identity.submissionFingerprint };
  };
  const adapter = { adapterProfile: E.reportProfile(), submit: async (submission) => unknown(submission), reconcile: (submission) => unknown(submission) };
  Object.defineProperty(adapter, "adapterProfile", { value: adapter.adapterProfile, writable: false, configurable: false, enumerable: true });
  return { adapter, held };
};

// ---------------------------------------------------------------- one scenario, both engines
/**
 * Agents a, b, c; a reviewer role with a succession rule; sessions for a (key 1001) and b (key 1003);
 * unsorted grants, a quantitative grant, a simulated operation with receipt and duty, a revocation,
 * the handover a→b, the duty assignment by b, and (E6) a lost-reply remote report with attempt records.
 */
async function scenario(E, dir, review) {
  const trace = (m) => { if (process.env.TRACE) process.stderr.write(`${E.name}: ${m}\n`); };
  ids.n = 0;
  const clock = { t: 100 };
  const config = { historyFile: join(dir, "history.jsonl"), domain: DOMAIN, owner: "operations", controller: "operator", now: () => clock.t };
  const c = await (review ? E.createLocalReviewOwner(config) : E.createLocalOwner(config));
  for (const id of ["a", "b", "c"]) await c.createAgent({ id });
  await c.createRole({ id: "reviewer" });
  await c.declareSuccession({ id: "handover", from: "a", to: "b", role: "reviewer" });
  await c.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  await c.admitRuntime({ session: "session:a", agent: "a", epoch: 1, key: "key:a", address: addressOf(KEYS.a), expiresAt: 1000 });
  await c.admitRuntime({ session: "session:b", agent: "b", epoch: 1, key: "key:b", address: addressOf(KEYS.b), expiresAt: 1000 });
  clock.t = 101;
  // Unsorted actions/resources (the reference RESPONSIBLE crash case); no transaction cap here because a capped grant cannot back an administrative proof.
  await c.grant({ id: "collect", to: "a", actions: ["read", "OBLIGATE"], resources: ["incident:42", "incident:41"], expiresAt: 900, notBefore: 50 });
  await c.grant({ id: "count", to: "c", actions: ["ping"], resources: ["svc"], expiresAt: 900, maxTransactions: 2 });
  await c.grant({ id: "review", to: "b", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: 900 });
  await c.grant({ id: "quant", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 900, maxAmount: 2500n, maxCumulativeAmount: 5000n, maxTransactions: 3 });
  await c.grant({ id: "c-read", to: "c", actions: ["read"], resources: ["incident:42"], expiresAt: 150 });
  await c.grant({ id: "c-mixed", to: "c", actions: ["write", "read"], resources: ["doc:2", "doc:1"], expiresAt: 900 }); // unsorted and live at every later time
  const a = { ...config, session: "session:a", signHash: E.signer(KEYS.a) }, b = { ...config, session: "session:b", signHash: E.signer(KEYS.b) };
  clock.t = 102;
  const op = { id: "operation:42", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: E.commitTerms({ subject: "Synthetic incident review" }) };
  const sim = E.openLocalSimulation(a);
  const run = await sim.run(op);
  assert.equal(run.invocation.status, "SUBMITTED", E.name);
  clock.t = 103;
  assert.equal((await sim.recordReceipt(op)).recording.status, "ADMITTED", E.name);
  clock.t = 104;
  await E.openLocalRuntime(a).obligate({ id: "duty:42", operation: op.id, description: "Review the collected material.", deadline: 800, succession: "handover", reviewAuthority: "review" });
  clock.t = 105;
  trace("await c.revoke(quant);");
  await c.revoke("quant");
  if (review) {
    clock.t = 106;
    for (const [id, action] of [["a-duty", "CREATE_ATTEMPT_DUTY"], ["a-observe", "OBSERVE_OUTCOME"], ["a-close", "CLOSE_ATTEMPT_DUTY"], ["a-ticket", "create-ticket"]]) {
      await c.grant({ id, to: "a", actions: [action], resources: [action === "create-ticket" ? "queue:security" : "ticket:1"], expiresAt: 900 });
    }
    const { adapter, held } = lostReplyAdapter(E);
    const ticket = { id: "ticket:1", action: "create-ticket", resource: "queue:security", role: "reviewer", tenure: "shift:1", termsCommitment: E.commitTerms({ title: "Review this synthetic incident" }) };
    clock.t = 107;
    const attempt = await E.openLocalExecution(a, adapter, "REMOTE_REPORT").run(ticket);
    assert.equal(attempt.invocation.status, "OUTCOME_UNKNOWN", E.name);
    const recorder = E.openLocalAttemptRecorder(a);
    clock.t = 108;
    await recorder.createDuty({ id: "investigation", intent: "ticket:1", description: "Find out whether the ticket exists.", deadline: 800 });
    clock.t = 109;
    await recorder.observe({ id: "late-report", intent: "ticket:1", acknowledgment: E.reportAcknowledgment(held.identity, `0x${"ab".repeat(32)}`) });
    clock.t = 110;
    await recorder.reviewDuty({ id: "review-1", duty: "investigation", summaryDigest: `0x${"cd".repeat(32)}` });
  }
  clock.t = 120;
  trace("await c.succeed({ id: handove");
  await c.succeed({ id: "handover:1", rule: "handover", fromAgent: "a", fromTenure: "shift:1", toAgent: "b", toTenure: "shift:2", role: "reviewer", number: 2 });
  clock.t = 121;
  trace("await c.grant({ id: assign");
  await c.grant({ id: "assign", to: "b", actions: ["ASSIGN_PERFORMANCE"], resources: ["duty:42"], expiresAt: 900 });
  clock.t = 122;
  trace("await E.openLocalRuntime(b).as");
  await E.openLocalRuntime(b).assign({ id: "assign:42", obligation: "duty:42" });
  if (review) {
    clock.t = 123;
    await c.grant({ id: "b-assign", to: "b", actions: ["ASSIGN_ATTEMPT_DUTY"], resources: ["ticket:1"], expiresAt: 900 });
    clock.t = 124;
    await E.openLocalAttemptRecorder(b).assignDuty({ id: "reassign", duty: "investigation" });
  }
  clock.t = 125;
  trace("await c.advanceEpoch({ agent: ");
  await c.advanceEpoch({ agent: "c", from: 1, to: 2 });
  return { config, clock };
}

// ---------------------------------------------------------------- the questions every engine answers on every file
const QUESTIONS = [
  { actor: "a", action: "read", resource: "incident:42" }, { actor: "a", action: "OBLIGATE", resource: "incident:42" }, { actor: "a", action: "pay", resource: "vendor", amount: 100n },
  { actor: "b", action: "read", resource: "incident:42" }, { actor: "b", action: "ASSIGN_PERFORMANCE", resource: "duty:42" }, { actor: "c", action: "read", resource: "incident:42" },
  { actor: "c", action: "read", resource: "doc:1" }, { actor: "c", action: "ping", resource: "svc" }, { actor: "nobody", action: "read", resource: "incident:42" },
  { actor: "a", action: "read", resource: "incident:42", counterparty: "b" },
];
// The observation is over the whole history (head time 125); 1000 is past every expiry. Earlier times are CAUSAL_TIME_INVALID (checked once below).
const TIMES = [125, 1000];
/**
 * Every answer of one engine on one file. The reference RESPONSIBLE crashes on
 * an unsorted grant ("Inconsistent internal responsibility projection inputs");
 * that crash is recorded as `{ crashed: true }` so the port's deviation (it
 * answers as the sorted grant would) can be asserted explicitly.
 */
function answers(E, config, at) {
  const started = Date.now();
  const c = E.openLocalOwner({ ...config, now: () => at }), out = { events: c.exportHistory(), head: c.observe().head, at: {} };
  const responsible = (o, q) => { try { return o.responsible(q); } catch (error) { return { crashed: true, message: error.message }; } };
  for (const time of TIMES) {
    const o = c.observe({ at: time });
    out.at[time] = {
      authorize: QUESTIONS.map((q) => o.authorize(q).evidence), why: QUESTIONS.map((q) => o.why(q)), responsible: QUESTIONS.map((q) => responsible(o, q)),
      survives: ["a", "b", "c", "nobody"].map((agent) => o.survives(agent)),
    };
  }
  if (process.env.TRACE) process.stderr.write(`answers(${E.name}) ${Date.now() - started} ms\n`);
  return out;
}
const REFERENCE_CRASH = "Inconsistent internal responsibility projection inputs.";

for (const review of [false, true]) {
  test(`${review ? "E6 with attempts" : "E1"}: the reference SDK and the port write byte-identical legacy histories, and each engine answers identically on both files`, async (t) => {
    const dirs = { theirs: mkdtempSync(join(tmpdir(), "interop-ref-")), mine: mkdtempSync(join(tmpdir(), "interop-port-")) };
    t.after(() => { for (const dir of Object.values(dirs)) rmSync(dir, { recursive: true, force: true }); });
    const ref = await scenario(theirs, dirs.theirs, review), port = await scenario(mine, dirs.mine, review);
    const files = { theirs: readFileSync(ref.config.historyFile, "utf8"), mine: readFileSync(port.config.historyFile, "utf8") };
    assert.equal(files.mine.split("\n").length, files.theirs.split("\n").length);
    for (const [line, expected] of files.theirs.split("\n").entries()) assert.equal(files.mine.split("\n")[line], expected, `line ${line} differs`);
    assert.equal(files.mine, files.theirs);
    assert.equal(port.config.historyFile !== ref.config.historyFile, true);

    // Cross-read: the port opens the reference file, the reference opens the port's file; all four (engine × file) answer sets are deep-equal.
    const baseline = answers(theirs, ref.config, 125);
    const cases = [["reference engine on the port's file", answers(theirs, port.config, 125)], ["port on the reference file", answers(mine, ref.config, 125)], ["port on its own file", answers(mine, port.config, 125)]];
    let crashes = 0;
    for (const [label, answer] of cases) {
      same(answer.events, baseline.events, `${label}: events`);
      same(answer.head, baseline.head, `${label}: head`);
      for (const time of TIMES) {
        for (const kind of ["authorize", "why", "survives"]) same(answer.at[time][kind], baseline.at[time][kind], `${label}: ${kind} at ${time}`);
        for (const [index, expected] of baseline.at[time].responsible.entries()) {
          const actual = answer.at[time].responsible[index];
          if (!expected.crashed) { same(actual, expected, `${label}: responsible[${index}] at ${time}`); continue; }
          // Deviation (DESIGN §3): the reference crashes on the unsorted "collect" grant; the port answers, and its answer is the same on every file.
          assert.equal(expected.message, REFERENCE_CRASH);
          if (actual.crashed) assert.equal(actual.message, REFERENCE_CRASH, label);
          else { crashes += 1; assert.equal(actual.kind, "RESPONSIBLE"); assert.equal(actual.epistemicStatus, "ESTABLISHED", label); same(actual, cases[2][1].at[time].responsible[index], `${label}: responsible[${index}] at ${time} vs port on its own file`); }
        }
      }
    }
    assert.ok(crashes > 0, "the scenario must exercise the reference RESPONSIBLE crash");
    assert.equal(baseline.at[125].authorize[0].decision, "DENY"); // a was terminated by the handover
    for (const E of [theirs, mine]) assert.equal(E.openLocalOwner({ ...port.config, now: () => 104 }).authorize(QUESTIONS[0]).evidence.code, "CAUSAL_TIME_INVALID", E.name);
    assert.equal(baseline.at[125].authorize[4].decision, "ALLOW"); // b may assign
    assert.equal(baseline.at[125].authorize[5].decision, "ALLOW"); // c reads incident:42 until 150
    assert.equal(baseline.at[125].authorize[6].decision, "ALLOW"); // the unsorted grant works in both engines
    assert.equal(baseline.at[1000].authorize[6].decision, "DENY");
    assert.equal(baseline.at[125].survives[0].epistemicStatus, "ESTABLISHED");
    if (review) {
      const inspected = { theirs: theirs.inspectAttemptHistory(baseline.events), mine: mine.inspectAttemptHistory(baseline.events) };
      same(inspected.mine, inspected.theirs);
      assert.equal(inspected.mine.attempts[0].duty.reviewStatus, "NEEDS_REVIEW"); // the reassignment after the closed review reopens it
      assert.equal(inspected.mine.attempts[0].duty.currentAssigneeId, "b");
      assert.equal(inspected.mine.attempts[0].reportStatus, "REPORT_RECORDED");
    }
    // Both stores agree on the head of both files, and the pinned head the port wrote does not disturb the reference reader.
    assert.deepEqual(openHistoryStore(ref.config.historyFile).head(), openHistoryStore(port.config.historyFile).head());
    assert.deepEqual(norm(refIndex.observeHistory(port.config.historyFile ? mine.openLocalOwner({ ...port.config, now: () => 125 }).exportHistory() : []).head), norm(baseline.head));
  });

  test(`${review ? "E6 with attempts" : "E1"}: the reference runtime continues a port-written history and the port continues a reference-written one`, async (t) => {
    const dirs = { theirs: mkdtempSync(join(tmpdir(), "interop-ref-")), mine: mkdtempSync(join(tmpdir(), "interop-port-")) };
    t.after(() => { for (const dir of Object.values(dirs)) rmSync(dir, { recursive: true, force: true }); });
    const ref = await scenario(theirs, dirs.theirs, review), port = await scenario(mine, dirs.mine, review);
    // Swap engines for a continuation: b (now the reviewer, key 1003) runs a fresh operation and records a receipt on the other engine's file.
    const continuation = async (E, config) => {
      const clock = { t: 200 };
      const c = E.openLocalOwner({ ...config, now: () => clock.t });
      await c.grant({ id: "b-read", to: "b", actions: ["read"], resources: ["incident:42"], expiresAt: 900 });
      const sim = E.openLocalSimulation({ ...config, now: () => clock.t, session: "session:b", signHash: E.signer(KEYS.b) });
      const op = { id: "operation:43", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:2", termsCommitment: E.commitTerms({ subject: "Follow-up" }) };
      clock.t = 201;
      assert.equal((await sim.run(op)).invocation.status, "SUBMITTED", E.name);
      clock.t = 202;
      assert.equal((await sim.recordReceipt(op)).recording.status, "ADMITTED", E.name);
      return c.exportHistory();
    };
    ids.n = 1000;
    const byReference = await continuation(theirs, port.config);
    ids.n = 1000;
    const byPort = await continuation(mine, ref.config);
    same(byPort, byReference);
    assert.equal(readFileSync(ref.config.historyFile, "utf8"), readFileSync(port.config.historyFile, "utf8"));
    const [portAnswers, referenceAnswers] = [answers(mine, ref.config, 202), answers(theirs, port.config, 202)];
    for (const time of TIMES) for (const kind of ["authorize", "why", "survives"]) same(portAnswers.at[time][kind], referenceAnswers.at[time][kind], `${kind} at ${time}`);
  });
}
