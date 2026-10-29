// G6.3 round 3 (ADDENDA-G6.3) for the owner-policy group: the A-116.1 `PR_eff` table, one test per row and its
// sub-conditions; `PR_types` and `LOW_types` (A-116.2). Credential separation (A-117) is pinned by the vectors of
// conformance/v2-owner-policy; its pure parts are checked here.
import test from "node:test";
import assert from "node:assert/strict";

const { prEffective, controlThreshold, ownerPolicyFailure, PR_TYPES, LOW_TYPES } = await import("../src/owner-policy.ts");

const NO_SUBJECTS = Object.freeze({ actorIds: null, roleIds: null, actions: null, resources: null });
const budget = (fields = {}) => Object.freeze({ budgetId: "b", subjects: { ...NO_SUBJECTS, actions: ["pay"] }, metric: "amount", period: { kind: "NONE" }, amountCap: "1000", countCap: 10, perOperationCap: "100", notBefore: null, expiresAt: 5000, status: "ACTIVE", ...fields });
const permission = (authorityId, extra = {}) => ({ grant: { kind: "PERMISSION", authorityId, grantorId: "operations", granteeId: "bea", rootAuthorityId: "root", ...extra }, grantEventId: `g:${authorityId}`, grantEventPosition: 1 });
const prohibition = (authorityId, extra = {}) => ({ grant: { kind: "PROHIBITION", scope: "ROOT", authorityId, grantorId: "bea", rootAuthorityId: "root", ...extra }, grantEventId: `g:${authorityId}`, grantEventPosition: 2 });
const revoked = (record) => ({ ...record, revocationEventId: "x" });
const agentRecord = (id, extra = {}) => ({ id, principalId: "operations", controllerId: "operator", currentControlEpoch: 1, terminated: false, ...extra });
/** A replay state as far as `prEffective` reads it (the records of A-116.1). */
const state = ({ budgets = [], authorities = [], agents = [], sessions = [], counterparties = [] } = {}) => {
  const byAgent = new Map();
  for (const s of sessions) byAgent.set(s.agentId, [...(byAgent.get(s.agentId) ?? []), s.id]);
  return {
    budgets: new Map(budgets.map((b) => [b.budgetId, b])), authorities: new Map(authorities.map((a) => [a.grant.authorityId, a])),
    agents: new Map(agents.map((a) => [a.id, a])), runtimeSessions: new Map(sessions.map((s) => [s.id, s])), runtimeSessionIdsByAgent: byAgent,
    counterparties: new Map(counterparties.map((c) => [c.counterpartyId, c])),
  };
};
const event = (type, data, timestamp = 200) => ({ id: `event:${type}`, type, timestamp, data });

test("A-116.1 AUTHORITY_REVOKED: an unrevoked PERMISSION under which no live PROHIBITION is delegated", () => {
  const revoke = (s, authorityId = "root") => prEffective(event("AUTHORITY_REVOKED", { authorityId, revokerId: "operations" }), s);
  assert.equal(revoke(state({ authorities: [permission("root")] })), true);
  const child = permission("child", { parentAuthorityId: "root", grantorId: "bea" });
  const ban = prohibition("ban", { parentAuthorityId: "child" });
  assert.equal(revoke(state({ authorities: [permission("root"), child, ban] })), false, "a live prohibition two levels under the permission");
  assert.equal(revoke(state({ authorities: [permission("root"), child, ban] }), "child"), false, "directly under it");
  assert.equal(revoke(state({ authorities: [permission("root"), child, revoked(ban)] })), true, "a revoked prohibition does not block");
  assert.equal(revoke(state({ authorities: [permission("root"), child, prohibition("other", { parentAuthorityId: "elsewhere" })] })), true, "a dangling ancestry stops");
  assert.equal(revoke(state({ authorities: [permission("root"), { grant: { kind: "PROHIBITION", scope: "GLOBAL", authorityId: "g", grantorId: "policy" }, grantEventId: "g", grantEventPosition: 3 }] })), true, "GLOBAL has no ancestry");
  assert.equal(revoke(state({ authorities: [revoked(permission("root"))] })), false, "already revoked");
  assert.equal(revoke(state({ authorities: [prohibition("root")] })), false, "a PROHIBITION is never PR_eff to revoke");
  assert.equal(revoke(state()), false, "a dangling id");
  const cycle = [permission("root"), prohibition("ban", { parentAuthorityId: "p1" }), permission("p1", { parentAuthorityId: "p2" }), permission("p2", { parentAuthorityId: "p1" })];
  assert.equal(revoke(state({ authorities: cycle })), true, "a parent cycle terminates");
});

test("A-116.1 CONTROL_EPOCH_ADVANCED: ACTIVE agent at fromEpoch, a later toEpoch, no session of the agent at toEpoch", () => {
  const fence = (s, from = 1, to = 2, agentId = "bea") => prEffective(event("CONTROL_EPOCH_ADVANCED", { agentId, controllerId: "operator", fromEpoch: from, toEpoch: to }), s);
  const s = state({ agents: [agentRecord("bea")] });
  assert.equal(fence(s), true);
  assert.equal(fence(s, 2, 3), false, "fromEpoch is not the agent's epoch");
  assert.equal(fence(s, 1, 1), false, "toEpoch is not later");
  assert.equal(fence(s, 1, 2, "cal"), false, "unknown agent");
  assert.equal(fence(state({ agents: [agentRecord("bea", { terminated: true })] })), false, "terminated agent");
  const at = (controlEpoch) => ({ id: `s${controlEpoch}`, agentId: "bea", controlEpoch });
  assert.equal(fence(state({ agents: [agentRecord("bea")], sessions: [at(1)] })), true, "a session at fromEpoch is fenced, not revived");
  // Unreachable in a replayed history (sessions are admitted at the agent's current epoch only; DEVIATIONS), decided as written:
  assert.equal(fence(state({ agents: [agentRecord("bea")], sessions: [at(2)] })), false, "a session at toEpoch would be revived");
});

test("A-116.1 AGENT_TERMINATED: ACTIVE agent that granted no live PROHIBITION (ASM-2)", () => {
  const terminate = (s) => prEffective(event("AGENT_TERMINATED", { agentId: "bea", principalId: "operations", successionRuleId: "r", roleId: "t", roleTenureId: "t:1" }), s);
  assert.equal(terminate(state({ agents: [agentRecord("bea")] })), true);
  assert.equal(terminate(state({ agents: [agentRecord("bea")], authorities: [prohibition("ban")] })), false);
  assert.equal(terminate(state({ agents: [agentRecord("bea")], authorities: [revoked(prohibition("ban"))] })), true);
  assert.equal(terminate(state({ agents: [agentRecord("bea")], authorities: [prohibition("ban", { grantorId: "cal" })] })), true, "another grantor");
  assert.equal(terminate(state({ agents: [agentRecord("bea")], authorities: [permission("root", { grantorId: "bea" })] })), true, "a permission granted by the agent does not block");
  assert.equal(terminate(state({ agents: [agentRecord("bea", { terminated: true })] })), false);
  assert.equal(terminate(state()), false);
});

test("A-116.1 AGENT_UNAPPOINTED: no budget that can still match the agent through the role", () => {
  const unappoint = (s, timestamp = 200) => prEffective(event("AGENT_UNAPPOINTED", { agentId: "bea", roleId: "treasury", roleTenureId: "treasury:1", principalId: "operations" }, timestamp), s);
  const role = (fields = {}) => budget({ subjects: { ...NO_SUBJECTS, roleIds: ["treasury"] }, ...fields });
  assert.equal(unappoint(state()), true);
  assert.equal(unappoint(state({ budgets: [role()] })), false);
  assert.equal(unappoint(state({ budgets: [role({ status: "CLOSED" })] })), true, "closed");
  assert.equal(unappoint(state({ budgets: [budget({ subjects: { ...NO_SUBJECTS, roleIds: ["other"] } })] })), true, "another role");
  assert.equal(unappoint(state({ budgets: [budget()] })), true, "roleIds null: not by role");
  assert.equal(unappoint(state({ budgets: [role({ subjects: { ...NO_SUBJECTS, roleIds: ["treasury"], actorIds: ["cal"] } })] })), true, "names another actor");
  assert.equal(unappoint(state({ budgets: [role({ subjects: { ...NO_SUBJECTS, roleIds: ["treasury"], actorIds: ["cal", "bea"] } })] })), false, "names the agent");
  assert.equal(unappoint(state({ budgets: [role({ expiresAt: 200 })] })), true, "expired at t (expiresAt <= t)");
  assert.equal(unappoint(state({ budgets: [role({ expiresAt: 201 })] })), false, "still live at t");
  assert.equal(unappoint(state({ budgets: [role({ expiresAt: null })] })), false, "never expires");
});

test("A-116.1 BUDGET_DECLARED: always PR_eff (a new stop rule only denies)", () => {
  assert.equal(prEffective(event("BUDGET_DECLARED", budget()), state()), true);
  assert.equal(prEffective(event("BUDGET_DECLARED", budget({ period: { kind: "FIXED_WINDOW", lengthMs: 10, originMs: 0, carryUnused: true, carryCap: null } })), state()), true);
});

test("A-116.1 BUDGET_UPDATED: ACTIVE, not rolling over, no cap rises, no subject narrows, expiry not earlier", () => {
  const update = (b, changes) => event("BUDGET_UPDATED", { budgetId: b.budgetId, subjects: b.subjects, amountCap: b.amountCap, countCap: b.countCap, perOperationCap: b.perOperationCap, expiresAt: b.expiresAt, ...changes });
  const b = budget();
  assert.equal(prEffective(update(b, { amountCap: "1" }), state({ budgets: [b] })), true);
  assert.equal(prEffective(update(b, { amountCap: "9999" }), state({ budgets: [b] })), false);
  const window = (carryUnused) => budget({ period: { kind: "FIXED_WINDOW", lengthMs: 100, originMs: 1000, carryUnused, carryCap: null } });
  assert.equal(prEffective(update(window(true), { amountCap: "1" }), state({ budgets: [window(true)] })), false, "rollsOver(B): never PR_eff");
  assert.equal(prEffective(update(window(true), {}), state({ budgets: [window(true)] })), false, "even restated unchanged (X-1)");
  assert.equal(prEffective(update(window(false), { amountCap: "1" }), state({ budgets: [window(false)] })), true, "a window without carry");
  assert.equal(prEffective(update(b, { amountCap: "1" }), state({ budgets: [budget({ status: "CLOSED" })] })), false);
  assert.equal(prEffective(update(b, { amountCap: "1" }), state()), false);
});

test("A-116.1 COUNTERPARTY_RETIRED: the counterparty is ACTIVE", () => {
  const retire = (s) => prEffective(event("COUNTERPARTY_RETIRED", { counterpartyId: "acme" }), s);
  assert.equal(retire(state({ counterparties: [{ counterpartyId: "acme", status: "ACTIVE", keys: [] }] })), true);
  assert.equal(retire(state({ counterparties: [{ counterpartyId: "acme", status: "RETIRED", keys: [] }] })), false);
  assert.equal(retire(state()), false);
});

test("A-116.2: seven PR_types, LOW_types = PR_types ∪ {STATE_CHECKPOINT}; rule 11 refuses ANCHOR_RECORDED below threshold", () => {
  assert.equal(PR_TYPES.size, 7);
  assert.equal(PR_TYPES.has("BUDGET_DECLARED"), true);
  assert.deepEqual([...LOW_TYPES].filter((t) => !PR_TYPES.has(t)), ["STATE_CHECKPOINT"]);
  const keys = [1, 2, 3].map((n) => ({ keyId: `owner:${n}`, scheme: "ed25519", credential: `0x${String(n).repeat(64)}` }));
  assert.match(ownerPolicyFailure({ threshold: 2, byType: { ANCHOR_RECORDED: 1 } }, keys), /rule 11/);
  assert.equal(ownerPolicyFailure({ threshold: 2, byType: { BUDGET_DECLARED: 1 } }, keys), undefined);
  assert.equal(controlThreshold({ threshold: 2, byType: { BUDGET_DECLARED: 1 } }, event("BUDGET_DECLARED", budget()), state()), 1);
});

test("A-97.2 adm(e) and A-110.1 isRecovery: structural, from the data and the epoch record", async () => {
  const { admissibleKeys, isRecoveryRotation, ownerKeyDigest } = await import("../src/owner-keys.ts");
  const key = (n) => ({ keyId: `k:${n}`, scheme: "ed25519", credential: `0x${String(n).repeat(64)}` });
  const epoch = (policy) => ({ fromPosition: 0, keys: [key(1)], nextKeyDigests: [ownerKeyDigest(key(2))], ...(policy === undefined ? {} : { policy }) });
  const rotation = (keys, signer) => ({ id: "r", type: "OWNER_KEYS_ROTATED", timestamp: 1, data: { ownerKeys: keys, controlAuthorization: { keyId: signer, signature: "0x" } } });
  const recovery = { threshold: 1, recovery: "COMMITTED_NEXT_KEYS" };
  assert.deepEqual(admissibleKeys(epoch(recovery), rotation([key(2)], "k:2")).map((k) => k.keyId), ["k:1", "k:2"]);
  assert.deepEqual(admissibleKeys(epoch({ threshold: 1 }), rotation([key(2)], "k:2")).map((k) => k.keyId), ["k:1"], "no recovery option");
  assert.deepEqual(admissibleKeys(epoch(recovery), rotation([key(3)], "k:3")).map((k) => k.keyId), ["k:1"], "an uncommitted revealed key");
  assert.deepEqual(admissibleKeys(epoch(recovery), { ...rotation([key(2)], "k:2"), type: "PRINCIPAL_CREATED" }).map((k) => k.keyId), ["k:1"], "only on a rotation");
  assert.equal(isRecoveryRotation(epoch(recovery), rotation([key(2)], "k:2")), true);
  assert.equal(isRecoveryRotation(epoch(recovery), rotation([key(1), key(2)], "k:1")), false, "the committed key is revealed but does not sign");
});
