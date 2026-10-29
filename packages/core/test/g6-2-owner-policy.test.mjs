// G6.2 round 2 (ADDENDA-G6.2) for the owner-policy group: `prEffective` row by row (A-106.2), `M_eff` with power
// reduction by effect (A-92.1 as amended, A-92.2 step 0), A-91.2 rules 10 and 11 (A-106.3, A-106.2), the writer's
// `required`. A-108 (per-key proof under G(e, p)) and A-110.2–3 (foreign credentials) are pinned by the vectors of
// conformance/v2-owner-policy; their guard (nothing changes without a policy) is checked here as well.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { prEffective, controlThreshold, effectiveThreshold, ownerPolicyFailure, PR_TYPES, LOW_TYPES } = await import("../src/owner-policy.ts");
const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");

const seed = (n) => `0x${n.toString(16).padStart(64, "0")}`;
const pair = (keyId, n) => keyPairFromPrivateKey("ed25519", keyId, seed(n));
const pub = (p) => ({ keyId: p.keyId, scheme: "ed25519", credential: p.credential });
const O1 = pair("owner:1", 0x6001), O2 = pair("owner:2", 0x6002), O3 = pair("owner:3", 0x6003), A1 = pair("agent:1", 0x6101);

// ---------------------------------------------------------------- PR_eff (A-106.2), one assertion per table row and direction

const NO_SUBJECTS = Object.freeze({ actorIds: null, roleIds: null, actions: null, resources: null });
const budget = (fields = {}) => Object.freeze({ budgetId: "b", subjects: { ...NO_SUBJECTS, actions: ["pay"] }, metric: "amount", period: { kind: "NONE" }, amountCap: "1000", countCap: 10, perOperationCap: "100", notBefore: null, expiresAt: 5000, status: "ACTIVE", ...fields });
const state = ({ budgets = [], authorities = [] } = {}) => ({ budgets: new Map(budgets.map((b) => [b.budgetId, b])), authorities: new Map(authorities.map((a) => [a.grant.authorityId, a])), agents: new Map(), runtimeSessions: new Map(), runtimeSessionIdsByAgent: new Map(), counterparties: new Map() });
const event = (type, data) => ({ id: `event:${type}`, type, timestamp: 200, data });
const update = (b, changes) => event("BUDGET_UPDATED", { budgetId: b.budgetId, subjects: b.subjects, amountCap: b.amountCap, countCap: b.countCap, perOperationCap: b.perOperationCap, expiresAt: b.expiresAt, ...changes });

test("A-106.2 PR_eff: AUTHORITY_REVOKED only of an unrevoked PERMISSION (the G6.3 rows are in g6-3-owner-policy.test.mjs)", () => {
  const permission = { grant: { authorityId: "p", kind: "PERMISSION" }, grantEventId: "g", grantEventPosition: 1 };
  const revoked = { ...permission, grant: { ...permission.grant, authorityId: "r" }, revocationEventId: "x" };
  const rootBan = { grant: { authorityId: "ban", kind: "PROHIBITION", scope: "ROOT" }, grantEventId: "g", grantEventPosition: 2 };
  const globalBan = { grant: { authorityId: "global", kind: "PROHIBITION", scope: "GLOBAL" }, grantEventId: "g", grantEventPosition: 3 };
  const s = state({ authorities: [permission, revoked, rootBan, globalBan] });
  const revoke = (authorityId) => prEffective(event("AUTHORITY_REVOKED", { authorityId, revokerId: "operations" }), s);
  assert.deepEqual(["p", "r", "ban", "global", "dangling"].map(revoke), [true, false, false, false, false]);
});

test("A-106.2 PR_eff: AGENT_UNAPPOINTED unless an ACTIVE budget selects the role", () => {
  const unappoint = event("AGENT_UNAPPOINTED", { agentId: "bea", roleId: "treasury", roleTenureId: "treasury:1", principalId: "operations" });
  assert.equal(prEffective(unappoint, state()), true);
  assert.equal(prEffective(unappoint, state({ budgets: [budget({ subjects: { ...NO_SUBJECTS, roleIds: ["treasury"] } })] })), false);
  assert.equal(prEffective(unappoint, state({ budgets: [budget({ subjects: { ...NO_SUBJECTS, roleIds: ["treasury"] }, status: "CLOSED" })] })), true);
  assert.equal(prEffective(unappoint, state({ budgets: [budget({ subjects: { ...NO_SUBJECTS, roleIds: ["other"] } })] })), true);
  assert.equal(prEffective(unappoint, state({ budgets: [budget()] })), true); // roleIds null: the budget does not select by role
});

test("A-106.2 PR_eff: BUDGET_UPDATED caps (no cap rises), subjects (none narrows) and expiry (not earlier); a budget is a stop rule", () => {
  const b = budget(), s = state({ budgets: [b] });
  const pr = (changes) => prEffective(update(b, changes), s);
  assert.equal(pr({}), true); // restating the budget changes nothing
  for (const cap of ["amountCap", "perOperationCap"]) {
    assert.equal(pr({ [cap]: "1" }), true, `${cap} lowered`);
    assert.equal(pr({ [cap]: "100000" }), false, `${cap} raised`);
    assert.equal(pr({ [cap]: null }), false, `${cap} removed`);
  }
  assert.deepEqual([pr({ countCap: 9 }), pr({ countCap: 11 }), pr({ countCap: null })], [true, false, false]);
  const uncapped = budget({ amountCap: null, countCap: null, perOperationCap: null });
  assert.equal(prEffective(update(uncapped, { amountCap: "5", countCap: 1, perOperationCap: "5" }), state({ budgets: [uncapped] })), true); // adding a cap
  assert.equal(prEffective(update(uncapped, {}), state({ budgets: [uncapped] })), true);
  assert.equal(pr({ subjects: NO_SUBJECTS }), true);                                          // widened to null
  assert.equal(pr({ subjects: { ...b.subjects, actions: ["pay", "refund"] } }), true);         // superset
  assert.equal(pr({ subjects: { ...b.subjects, actions: ["refund"] } }), false);               // not a superset
  assert.equal(pr({ subjects: { ...b.subjects, actorIds: ["bea"] } }), false);                 // null narrowed to a list
  assert.deepEqual([pr({ expiresAt: 6000 }), pr({ expiresAt: 4000 }), pr({ expiresAt: null })], [true, false, true]);
  const open = budget({ expiresAt: null });
  assert.equal(prEffective(update(open, { expiresAt: 9000 }), state({ budgets: [open] })), false); // an end where there was none
  assert.equal(prEffective(update(b, { amountCap: "1" }), state()), false);                        // unknown budget
  assert.equal(prEffective(update(b, { amountCap: "1" }), state({ budgets: [budget({ status: "CLOSED" })] })), false);
});

test("A-116.1 PR_eff: every other type never (BUDGET_CLOSED, WITNESSES_UNBOUND, OWNER_KEYS_ROTATED, …)", () => {
  for (const type of ["BUDGET_CLOSED", "WITNESSES_UNBOUND", "OWNER_KEYS_ROTATED", "PRINCIPAL_CREATED", "STATE_CHECKPOINT", "AUTHORITY_GRANTED", "ANCHOR_RECORDED"]) {
    assert.equal(prEffective(event(type, { budgetId: "b" }), state({ budgets: [budget()] })), false, type);
  }
  assert.deepEqual([...PR_TYPES].sort(), ["AGENT_TERMINATED", "AGENT_UNAPPOINTED", "AUTHORITY_REVOKED", "BUDGET_DECLARED", "BUDGET_UPDATED", "CONTROL_EPOCH_ADVANCED", "COUNTERPARTY_RETIRED"]);
  assert.deepEqual([...LOW_TYPES].filter((t) => !PR_TYPES.has(t)).sort(), ["STATE_CHECKPOINT"]); // A-116.2: ANCHOR_RECORDED left LOW_types
});

test("A-92.1 / A-106.2 M_eff: a lowered PR_types value applies only to a power-reducing event; other values as written; no policy: 1", () => {
  const policy = { threshold: 2, byType: { BUDGET_UPDATED: 1, STATE_CHECKPOINT: 1, ROLE_CREATED: 3, AGENT_TERMINATED: 2 } };
  const b = budget(), s = state({ budgets: [b] });
  assert.equal(controlThreshold(policy, update(b, { amountCap: "1" }), s), 1);
  assert.equal(controlThreshold(policy, update(b, { amountCap: "9999" }), s), 2);
  assert.equal(controlThreshold(policy, event("STATE_CHECKPOINT", {}), s), 1);
  assert.equal(controlThreshold(policy, event("ROLE_CREATED", {}), s), 3);
  assert.equal(controlThreshold(policy, event("AGENT_TERMINATED", {}), s), 2);
  assert.equal(controlThreshold(policy, event("PRINCIPAL_CREATED", {}), s), 2);
  assert.equal(controlThreshold(undefined, update(b, { amountCap: "9999" }), s), 1);
  assert.equal(effectiveThreshold(policy, "BUDGET_UPDATED"), 1); // the type-level value; controlThreshold decides per event
});

test("A-91.2 rules 10 and 11 (A-106.3, A-106.2): EVENT_DATA_INVALID at the setting event", () => {
  const keys = [pub(O1), pub(O2), pub(A1)], agent = { "agent:1": "AGENT" };
  assert.match(ownerPolicyFailure({ threshold: 1, byType: { AUTHORITY_REVOKED: 3 }, keyClasses: agent }, keys), /rule 10/);
  assert.equal(ownerPolicyFailure({ threshold: 1, byType: { AUTHORITY_REVOKED: 2 }, keyClasses: agent }, keys), undefined);
  assert.equal(ownerPolicyFailure({ threshold: 1, byType: { ROLE_CREATED: 3 }, keyClasses: agent }, keys), undefined); // rule 10 is about PR_types only
  for (const type of [...LOW_TYPES]) assert.equal(ownerPolicyFailure({ threshold: 2, byType: { [type]: 1 } }, [pub(O1), pub(O2), pub(O3)]), undefined, type);
  for (const type of ["BUDGET_CLOSED", "WITNESSES_UNBOUND", "PRINCIPAL_CREATED", "AUTHORITY_GRANTED", "RUNTIME_SESSION_ADMITTED"]) {
    assert.match(ownerPolicyFailure({ threshold: 2, byType: { [type]: 1 } }, [pub(O1), pub(O2), pub(O3)]), /rule 11/, type);
  }
  assert.match(ownerPolicyFailure({ threshold: 2, byType: { OWNER_KEYS_ROTATED: 1 } }, [pub(O1), pub(O2)]), /rule 4/); // rule 4 first
});

// ---------------------------------------------------------------- the writer: `required` and the single-signer pre-check follow M_eff

test("writer: under {threshold 2, byType.BUDGET_UPDATED 1} a lowering update is signed alone; a raise needs the co-signature (required 2)", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g62-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 1000;
  const handle = await core.createLocalOwner({ historyFile: join(dir, "history.jsonl"), domain: core.createLocalDomain(), owner: "operations", controller: "operator", now: () => (tick += 1), signer: signerFromKeyPair(O1), witness: false, coOwnerKeys: [pub(O2), pub(O3)] });
  const declared = { budgetId: "b-pay", subjects: { actorIds: null, roleIds: null, actions: ["pay"], resources: null }, metric: "amount", period: { kind: "NONE" }, amountCap: "1000", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null };
  await handle.declareBudget(declared);
  await handle.rotateOwnerPolicy({ ownerPolicy: { threshold: 2, byType: { BUDGET_UPDATED: 1 } } });
  const restate = { budgetId: "b-pay", subjects: declared.subjects, countCap: null, perOperationCap: null, expiresAt: null };
  await handle.updateBudget({ ...restate, amountCap: "500" });
  await assert.rejects(handle.updateBudget({ ...restate, amountCap: "800" }), (e) => e.code === "CONTROL_AUTHORIZATION_INVALID" && e.detail.required === 2 && e.detail.present === 1);
  const lowering = await handle.prepareControlEvent({ type: "BUDGET_UPDATED", data: { ...restate, amountCap: "400" } });
  assert.equal(lowering.required, 1);
  const raising = await handle.prepareControlEvent({ type: "BUDGET_UPDATED", data: { ...restate, amountCap: "800" } });
  assert.equal(raising.required, 2);
  const entries = await Promise.all([O1, O2].map((p) => core.authorizeControlEvent(signerFromKeyPair(p), raising)));
  await handle.submitControlEvent(raising, entries);
  assert.equal(handle.exportHistory().at(-1).data.additionalControlAuthorizations.length, 1);
  assert.equal(handle.verify().ok, true);
});

test("creation: the hint for a policy the creation cannot satisfy no longer suggests a lowered byType (rule 11)", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g62-create-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = { historyFile: join(dir, "h.jsonl"), domain: core.createLocalDomain(), owner: "operations", controller: "operator", now: () => 1000, signer: signerFromKeyPair(O1), witness: false, coOwnerKeys: [pub(O2)], ownerPolicy: { threshold: 2 } };
  await assert.rejects(core.createLocalOwner(config), (e) => e.code === "INVALID_INPUT" && e.detail.reason === "POLICY_UNSATISFIABLE_AT_CREATION" && !/byType/.test(e.message));
});
