// Format-2 histories built through the owner/runtime API for the E3 tests (T2 resume equivalence, the snapshot store,
// migration pins). Each builder returns `{ dir, config, events, store?, ... }`; the caller removes `dir`.
//
//  - `richHistory`: the interop scenario (agents, succession, sessions, unsorted and quantitative grants, a simulated
//    operation with consumption + outcome + receipt, an obligation, a revocation, a remote-report attempt with an
//    observation, an attempt duty with assignment and review, a handover with its checkpoint, an assignment by the
//    successor, an epoch advance) plus budgets, a counterparty with a signed receipt, effects, a CORE refusal, reconciliation
//    observations (A-71), a manual checkpoint, an owner-key rotation, a local anchor and a witness binding (then
//    unbinding): every §7.2 kind.
//  - `e2History`: budgets (declare, charge, update, close), refusals (automatic and manual), effects, counterparties
//    (register, receipt, retire, re-register), a handover (roleIds budget across it) — the E2 scenarios.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../../src/index.ts");
const { createLocalDomain, createLocalOwner, createLocalReviewOwner, openLocalOwner } = await import("../../src/owner.ts");
const { openLocalSimulation, commitTerms } = await import("../../src/simulation.ts");
const { openLocalRuntime } = await import("../../src/runtime.ts");
const { openLocalExecution } = await import("../../src/execution.ts");
const { openLocalAttemptRecorder } = await import("../../src/attempts.ts");
const editions = await import("../../src/adapter-editions.ts");
const admission = await import("../../src/admission.ts");
const { generateKeyPair, signHashWith } = await import("../../src/crypto/suites.ts");
const { envelopeDigest, envelopeSigningHash } = await import("../../src/session-auth.ts");
const { openHistoryStore } = await import("../../src/store.ts");
const signer = await import("../../src/signer.ts");
const anchor = await import("../../src/anchor.ts");

export const tempDir = (prefix = "irontrellis-f2-hist-") => mkdtempSync(join(tmpdir(), prefix));
const budget = (id, extra = {}) => ({ budgetId: id, subjects: { actorIds: null, roleIds: null, actions: ["pay"], resources: null }, metric: "amount", period: { kind: "NONE" }, amountCap: "10000", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null, ...extra });

/** A remote-service-report adapter whose reply is lost (OUTCOME_UNKNOWN); its identity is kept for a later observation. */
const lostReplyAdapter = () => {
  const held = { identity: undefined };
  const unknown = (submission) => {
    held.identity = admission.deriveAdapterIdentity(submission);
    return { status: "OUTCOME_UNKNOWN", idempotencyKey: held.identity.idempotencyKey, submissionFingerprint: held.identity.submissionFingerprint };
  };
  const adapter = { adapterProfile: editions.approvedAdapterProfileForPolicy(editions.ADAPTER_POLICY_E6_HASH, editions.REMOTE_SERVICE_REPORT_ADAPTER_ID), submit: async (s) => unknown(s), reconcile: (s) => unknown(s) };
  Object.defineProperty(adapter, "adapterProfile", { value: adapter.adapterProfile, writable: false, configurable: false, enumerable: true });
  return { adapter, held };
};

/** The simulated adapter of admission.test.mjs: a FAILED result (with a no-effect proof) for the named intents, SUBMITTED otherwise. */
const simulatedAdapter = (failIntentIds) => {
  const results = new Map(), profile = editions.approvedAdapterProfile(editions.SIMULATED_ADAPTER_ID);
  const retained = (identity) => {
    const prior = results.get(identity.idempotencyKey);
    if (prior === undefined) return undefined;
    const common = { status: "RETRY", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, retainedEvidence: prior.evidence };
    return prior.status === "SUBMITTED" ? { ...common, acknowledgment: prior.acknowledgment } : { ...common, noEffect: prior.noEffect };
  };
  return {
    adapterProfile: profile,
    reconcile(input) { const identity = admission.deriveAdapterIdentity(input); return retained(identity) ?? { status: "OUTCOME_UNKNOWN", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }; },
    async submit(input) {
      const identity = admission.deriveAdapterIdentity(input), prior = retained(identity);
      if (prior !== undefined) return prior;
      const { idempotencyKey, submissionFingerprint } = identity;
      let result;
      if (failIntentIds.includes(input.intentId)) { const noEffect = editions.createAdapterNoEffect(identity); result = { status: "FAILED", idempotencyKey, submissionFingerprint, evidence: editions.adapterNoEffectEvidence(identity, noEffect), noEffect }; }
      else { const acknowledgment = editions.createAdapterAcknowledgment(identity); result = { status: "SUBMITTED", idempotencyKey, submissionFingerprint, evidence: editions.adapterAcknowledgmentEvidence(identity, acknowledgment), acknowledgment }; }
      results.set(idempotencyKey, result);
      return result;
    },
  };
};

export async function richHistory(dir, options = {}) {
  const clock = { t: 100 };
  let n = 0;
  const config = { historyFile: join(dir, "rich.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => clock.t, ids: () => `e:${(n += 1)}`, witness: false, ...options };
  const c = await createLocalReviewOwner(config);
  const keys = { a: generateKeyPair("ed25519", "key:a"), b: generateKeyPair("ed25519", "key:b"), c: generateKeyPair("eip191-personal-sign-keccak256", "key:c") };
  for (const id of ["a", "b", "c"]) await c.createAgent({ id });
  await c.createRole({ id: "reviewer" });
  await c.declareSuccession({ id: "handover", from: "a", to: "b", role: "reviewer" });
  await c.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  await c.admitRuntime({ session: "session:a", agent: "a", epoch: 1, key: "key:a", credential: keys.a.credential, expiresAt: 1000 });
  await c.admitRuntime({ session: "session:b", agent: "b", epoch: 1, key: "key:b", credential: keys.b.credential, expiresAt: 1000 });
  await c.admitRuntime({ session: "session:c", agent: "c", epoch: 1, key: "key:c", address: keys.c.credential, expiresAt: 1000 });
  clock.t = 101;
  await c.grant({ id: "collect", to: "a", actions: ["read", "OBLIGATE"], resources: ["incident:42", "incident:41"], expiresAt: 900, notBefore: 50 });
  await c.grant({ id: "count", to: "c", actions: ["ping"], resources: ["svc"], expiresAt: 900, maxTransactions: 2 });
  await c.grant({ id: "review", to: "b", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: 900 });
  await c.grant({ id: "quant", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 900, maxAmount: 2500n, maxCumulativeAmount: 5000n, maxTransactions: 3 });
  await c.grant({ id: "c-read", to: "c", actions: ["read"], resources: ["incident:42"], expiresAt: 150 });
  await c.grant({ id: "c-mixed", to: "c", actions: ["write", "read"], resources: ["doc:2", "doc:1"], expiresAt: 900 });
  await c.declareBudget(budget("b-pay", { period: { kind: "FIXED_WINDOW", lengthMs: 1000, originMs: 0, carryUnused: true, carryCap: "500" }, amountCap: "4000" }));
  await c.declareBudget(budget("b-role", { subjects: { actorIds: null, roleIds: ["reviewer"], actions: null, resources: null }, countCap: 50 }));
  const acme = generateKeyPair("ed25519", "acme:1");
  await c.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "acme:1", scheme: "ed25519", credential: acme.credential }] });
  const a = { ...config, session: "session:a", signHash: signHashWith(keys.a) }, b = { ...config, session: "session:b", signHash: signHashWith(keys.b) };
  clock.t = 102;
  const op = { id: "operation:42", intentId: "operation:42", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: "Synthetic incident review" }) };
  const sim = openLocalSimulation(a);
  if ((await sim.run(op)).invocation.status !== "SUBMITTED") throw new Error("run");
  clock.t = 103;
  if ((await sim.recordReceipt(op)).recording.status !== "ADMITTED") throw new Error("receipt");
  // A paid operation: charges the budgets, carries a counterparty, gets a counterparty receipt and effects.
  const pay = { id: "pay:1", intentId: "pay:1", action: "pay", resource: "vendor", role: "reviewer", tenure: "shift:1", amount: 1200n, counterparty: "acme", termsCommitment: commitTerms({ invoice: 1 }) };
  if ((await sim.run(pay)).invocation.status !== "SUBMITTED") throw new Error("pay");
  // A simulated operation whose adapter retains a FAILED result: a terminal TRANSACTION_OUTCOME_RECORDED with a no-effect proof.
  const failed = await openLocalExecution(a, simulatedAdapter(["op:fail"]), "SIMULATION").run({ id: "op:fail", intentId: "op:fail", action: "read", resource: "incident:41", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: "fails" }) });
  if (failed.invocation.status !== "FAILED") throw new Error(`failed run: ${failed.invocation.status}`);
  clock.t = 104;
  const runtimeA = openLocalRuntime(a);
  await runtimeA.obligate({ id: "duty:42", operation: op.id, description: "Review the collected material.", deadline: 800, succession: "handover", reviewAuthority: "review" });
  const stateNow = () => core.replay(c.exportHistory()).state;
  const historyId = stateNow().eventHistoryHashes[0], intentDigest = stateNow().intentDeclarations.get("pay:1").declarationDigest;
  const body = { version: "irontrellis-counterparty-receipt/2", historyId, counterpartyId: "acme", keyId: "acme:1", logicalId: "pay:1", intentDigest, payloadDigest: `0x${"ab".repeat(32)}`, amount: "1200", outcome: "DELIVERED", observedAt: 104, previousReceiptDigest: null };
  const envelope = { ...body, signature: await signHashWith(acme)(envelopeSigningHash(body)) };
  await runtimeA.recordCounterpartyReceipt({ intentId: "pay:1", envelope });
  await runtimeA.recordEffect({ effectId: "effect:1", intentId: "pay:1", measurer: { kind: "SESSION", id: "a" }, metric: "amount", unit: "cent", amount: 1200n, observedAt: 103 });
  // A-36.1: a COUNTERPARTY effect cites the recorded envelope (detailDigest) and carries its amount.
  await runtimeA.recordEffect({ effectId: "effect:2", intentId: "pay:1", measurer: { kind: "COUNTERPARTY", id: "acme" }, metric: "amount", unit: "cent", amount: 1200n, observedAt: 104, detailDigest: envelopeDigest(envelope) });
  // A CORE refusal recorded by hand (a wants to pay a resource it has no grant for).
  await runtimeA.recordRefusal({ refusalId: "refusal:1", request: { actorId: "a", action: "pay", resource: "nowhere", claimedAt: 104, amount: 1n } });
  // A-71: reconciliation observations by c's (EIP-191) session — matched to the admission and to the refusal, unmatched, an equivocation.
  const reconciler = openLocalRuntime({ ...config, session: "session:c", signHash: signHashWith(keys.c) });
  const provider = (eventRef, d) => ({ streamId: "psp", eventRef, eventDigest: `0x${d.repeat(64)}` });
  await reconciler.recordObservation({ source: provider("ch_1", "1"), call: { actorId: "a", action: "pay", resource: "vendor", amount: 1200n }, decision: { intentId: "pay:1" } });
  await reconciler.recordObservation({ source: provider("ch_2", "2"), call: { actorId: "a", observedAt: 90 }, decision: { refusalId: "refusal:1" } });
  await reconciler.recordObservation({ source: provider("ch_3", "3"), call: { actorId: "a" } });
  await reconciler.recordObservation({ source: provider("ch_3", "4"), call: { actorId: "a", resource: "vendor" } });
  clock.t = 105;
  await c.revoke("quant");
  clock.t = 106;
  for (const [id, action] of [["a-duty", "CREATE_ATTEMPT_DUTY"], ["a-observe", "OBSERVE_OUTCOME"], ["a-close", "CLOSE_ATTEMPT_DUTY"], ["a-ticket", "create-ticket"]]) {
    await c.grant({ id, to: "a", actions: [action], resources: [action === "create-ticket" ? "queue:security" : "ticket:1"], expiresAt: 900 });
  }
  const { adapter, held } = lostReplyAdapter();
  const ticket = { id: "ticket:1", intentId: "ticket:1", action: "create-ticket", resource: "queue:security", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ title: "Review this synthetic incident" }) };
  clock.t = 107;
  if ((await openLocalExecution(a, adapter, "REMOTE_REPORT").run(ticket)).invocation.status !== "OUTCOME_UNKNOWN") throw new Error("attempt");
  const recorder = openLocalAttemptRecorder(a);
  clock.t = 108;
  await recorder.createDuty({ id: "investigation", intent: "ticket:1", description: "Find out whether the ticket exists.", deadline: 800 });
  clock.t = 109;
  await recorder.observe({ id: "late-report", intent: "ticket:1", acknowledgment: editions.createRemoteServiceReportAcknowledgment(held.identity, `0x${"ab".repeat(32)}`) });
  clock.t = 110;
  await recorder.reviewDuty({ id: "review-1", duty: "investigation", summaryDigest: `0x${"cd".repeat(32)}` });
  await c.checkpoint({ checkpointId: "cp:manual" });
  clock.t = 111;
  await c.updateBudget({ budgetId: "b-pay", subjects: { actorIds: null, roleIds: null, actions: ["pay"], resources: null }, amountCap: "3000", countCap: 10, perOperationCap: "2000", expiresAt: null });
  clock.t = 120;
  await c.succeed({ id: "handover:1", rule: "handover", fromAgent: "a", fromTenure: "shift:1", toAgent: "b", toTenure: "shift:2", role: "reviewer", number: 2 });
  clock.t = 121;
  await c.grant({ id: "assign", to: "b", actions: ["ASSIGN_PERFORMANCE"], resources: ["duty:42"], expiresAt: 900 });
  clock.t = 122;
  await openLocalRuntime(b).assign({ id: "assign:42", obligation: "duty:42" });
  clock.t = 123;
  await c.grant({ id: "b-assign", to: "b", actions: ["ASSIGN_ATTEMPT_DUTY"], resources: ["ticket:1"], expiresAt: 900 });
  clock.t = 124;
  await openLocalAttemptRecorder(b).assignDuty({ id: "reassign", duty: "investigation" });
  clock.t = 125;
  await c.advanceEpoch({ agent: "c", from: 1, to: 2 });
  await c.closeBudget({ budgetId: "b-role" });
  await c.retireCounterparty({ counterpartyId: "acme" });
  clock.t = 126;
  await c.rotateOwnerKey();
  await c.createAgent({ id: "d" }); // the head moves into the new epoch (the rotation's own head is attested by the retired set)
  // An anchor in the local log and a witness binding, then its unbinding (the final state keeps the witnessPolicy record).
  clock.t = 127;
  const ownerSigner = signer.loadOwnerKeyFile(signer.ownerKeyPathFor(config.historyFile));
  const store = openHistoryStore(config.historyFile, { signer: ownerSigner, witness: false });
  await anchor.anchorHead(store, ownerSigner, anchor.localAnchorLog(`${config.historyFile}.anchors`), { id: "anchor:1", anchoredAt: 127 });
  const state = store.state();
  const policy = { quorum: 1, requireOnOpen: false, maxUnwitnessedEvents: 1000 };
  const witnesses = [
    { url: "https://witness-a.example.org", verifierKey: "witness-a.example.org+07c49b56+AcBQxWN6RPqGKf/zzMziMAyzYqY9mdlfxUFFJm9DMkRa", name: "witness-a" },
    { url: "https://witness-b.example.org", verifierKey: "witness-b.example.org+8708f444+ASASy5DKYOjl2Nr2biJy0iM+BIbVV+jGYUHtiSAXfX63" },
  ];
  store.append(await signer.signControlEvent(ownerSigner, { id: "bind:1", type: "WITNESSES_BOUND", timestamp: 127, data: { witnesses, policy } }, state.genesis.domain, store.head(), "sha256"));
  store.append(await signer.signControlEvent(ownerSigner, { id: "unbind:1", type: "WITNESSES_UNBOUND", timestamp: 128, data: { verifierKeys: [witnesses[1].verifierKey], policy } }, state.genesis.domain, store.head(), "sha256"));
  const events = store.readAll();
  store.close();
  return { config, events, clock, keys, grid: richGrid() };
}
const richGrid = () => ({
  requests: [
    { actor: "a", action: "read", resource: "incident:42" }, { actor: "a", action: "OBLIGATE", resource: "incident:42" }, { actor: "a", action: "pay", resource: "vendor", amount: 100n },
    { actor: "b", action: "read", resource: "incident:42" }, { actor: "b", action: "ASSIGN_PERFORMANCE", resource: "duty:42" }, { actor: "c", action: "read", resource: "incident:42" },
    { actor: "c", action: "read", resource: "doc:1" }, { actor: "c", action: "ping", resource: "svc" }, { actor: "nobody", action: "read", resource: "incident:42" },
    { actor: "a", action: "read", resource: "incident:42", counterparty: "b" }, { actor: "a", action: "create-ticket", resource: "queue:security" }, { actor: "b", action: "ASSIGN_ATTEMPT_DUTY", resource: "ticket:1" },
  ],
  agents: ["a", "b", "c", "nobody"], budgets: ["b-pay", "b-role", "none"], times: [128, 1000],
});

export async function e2History(dir, options = {}) {
  const clock = { t: 100 };
  let n = 0;
  const config = { historyFile: join(dir, "e2.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => clock.t, ids: () => `e:${(n += 1)}`, witness: false, ...options };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createAgent({ id: "alex" });
  await owner.createRole({ id: "reviewer" });
  await owner.declareSuccession({ id: "handover", from: "bea", to: "alex", role: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  const pair = generateKeyPair("ed25519", "key:1"), pair2 = generateKeyPair("ed25519", "key:2");
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: pair.credential, expiresAt: 10_000_000 });
  await owner.admitRuntime({ session: "session:2", agent: "alex", epoch: 1, key: "key:2", credential: pair2.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: "read", to: "bea", actions: ["read", "spend"], resources: ["incident:42", "petty-cash"], expiresAt: 10_000_000 });
  await owner.grant({ id: "spend2", to: "alex", actions: ["spend"], resources: ["petty-cash"], expiresAt: 10_000_000 });
  const spend = (id, extra = {}) => ({ budgetId: id, subjects: { actorIds: null, roleIds: null, actions: ["spend"], resources: null }, metric: "amount", period: { kind: "NONE" }, amountCap: "100", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null, ...extra });
  await owner.declareBudget(spend("b-amount", { period: { kind: "FIXED_WINDOW", lengthMs: 1000, originMs: 0, carryUnused: true, carryCap: "50" }, amountCap: "100" }));
  await owner.declareBudget(spend("b-role", { subjects: { actorIds: null, roleIds: ["reviewer"], actions: null, resources: null }, countCap: 5 }));
  await owner.declareBudget(spend("b-closed"));
  const options1 = { ...config, session: "session:1", signHash: signHashWith(pair) };
  const runtime = openLocalSimulation(options1);
  const op = (id, extra = {}) => ({ id, intentId: id, action: "spend", resource: "petty-cash", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: id }), ...extra });
  clock.t = 150;
  await runtime.run(op("op:1", { amount: 40n }));
  await runtime.run(op("op:2", { amount: 30n }));
  // Over the cap: an automatic BUDGET refusal (recorded), then a manual CORE refusal.
  await runtime.run(op("op:3", { amount: 50n }));
  const rt = openLocalRuntime(options1);
  await rt.recordRefusal({ refusalId: "refusal:manual", request: { actorId: "bea", action: "write", resource: "incident:42", claimedAt: 150 } });
  await rt.recordEffect({ effectId: "effect:1", intentId: "op:1", measurer: { kind: "SESSION", id: "bea" }, metric: "amount", unit: "cent", amount: 40n, observedAt: 150 });
  const acme = generateKeyPair("ed25519", "acme:1");
  await owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "acme:1", scheme: "ed25519", credential: acme.credential }] });
  const state = () => core.replay(owner.exportHistory()).state;
  const historyId = state().eventHistoryHashes[0], intentDigest = state().intentDeclarations.get("op:1").declarationDigest;
  const body = { version: "irontrellis-counterparty-receipt/2", historyId, counterpartyId: "acme", keyId: "acme:1", logicalId: "op:1", intentDigest, payloadDigest: `0x${"ab".repeat(32)}`, amount: "40", outcome: "DELIVERED", observedAt: 150, previousReceiptDigest: null };
  await rt.recordCounterpartyReceipt({ intentId: "op:1", envelope: { ...body, signature: await signHashWith(acme)(envelopeSigningHash(body)) } });
  await owner.retireCounterparty({ counterpartyId: "acme" });
  const acme2 = generateKeyPair("ed25519", "acme:2");
  await owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "acme:2", scheme: "ed25519", credential: acme2.credential }] });
  clock.t = 1200;
  await owner.updateBudget({ budgetId: "b-amount", subjects: { actorIds: null, roleIds: null, actions: ["spend"], resources: null }, amountCap: "120", countCap: null, perOperationCap: "60", expiresAt: null });
  await owner.closeBudget({ budgetId: "b-closed" });
  clock.t = 1300;
  await owner.succeed({ id: "handover:1", rule: "handover", fromAgent: "bea", fromTenure: "shift:1", toAgent: "alex", toTenure: "shift:2", role: "reviewer", number: 2 });
  await openLocalSimulation({ ...config, session: "session:2", signHash: signHashWith(pair2) }).run({ id: "op:4", intentId: "op:4", action: "spend", resource: "petty-cash", role: "reviewer", tenure: "shift:2", amount: 10n, termsCommitment: commitTerms({ subject: "op:4" }) });
  const events = owner.exportHistory();
  return {
    config, events, clock,
    grid: {
      requests: [{ actor: "bea", action: "spend", resource: "petty-cash", amount: 10n }, { actor: "alex", action: "spend", resource: "petty-cash", amount: 10n }, { actor: "alex", action: "spend", resource: "petty-cash", amount: 70n },
        { actor: "bea", action: "read", resource: "incident:42" }, { actor: "alex", action: "read", resource: "incident:42" }, { actor: "nobody", action: "spend", resource: "petty-cash" }],
      agents: ["bea", "alex", "nobody"], budgets: ["b-amount", "b-role", "b-closed", "none"], times: [1300, 2500],
    },
  };
}

export { openLocalOwner };
