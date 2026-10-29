// A-116.3: the five assumptions invariant 31 relies on, tested against this engine's authority procedure. ASM-1 and
// ASM-3 over random authority forests on the raw path (`evaluateAuthorityPath`); ASM-2, ASM-4 and ASM-5 over a replayed
// format-2 history and every request of a small grid (`authorizeState`). Builder tests (A-116.6), not conformance vectors.
import test from "node:test";
import assert from "node:assert/strict";

const core = await import("../src/index.ts");
const A = await import("../src/authority.ts");
const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");

/** mulberry32: a small seeded PRNG so every run checks the same forests. */
const prng = (seed) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const ACTORS = ["a", "b", "c", "d"], ACTIONS = ["pay", "read"], RESOURCES = ["r1", "r2"];
const subsetOf = (rand, items) => { const out = items.filter(() => rand() < 0.6); return out.length > 0 ? out : [items[0]]; };

// ---------------------------------------------------------------- raw path (ASM-1, ASM-3)

const HEAD = { hash: `0x${"ab".repeat(32)}`, position: 7, canonicalTime: 100 };
const DOMAIN_02 = { protocol: "continuity", version: "0.2", deploymentId: "asm", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000003002" };
/** A random valid forest: roots granted by P, attenuated delegations, intersections between roots, ROOT and GLOBAL prohibitions. */
const forest = (rand) => {
  const permissions = [], prohibitions = [];
  const roots = 1 + Math.floor(rand() * 3);
  for (let i = 0; i < roots; i += 1) {
    const required = i > 0 && rand() < 0.3 ? [`root${Math.floor(rand() * i)}`] : [];
    permissions.push({ kind: "PERMISSION", authorityId: `root${i}`, grantorId: "P", granteeId: ACTORS[Math.floor(rand() * ACTORS.length)], rootAuthorityId: `root${i}`, independent: rand() < 0.7,
      constraints: { actions: subsetOf(rand, ACTIONS), resources: subsetOf(rand, RESOURCES), quantitative: false, maxDelegationDepth: 3, requiredIntersectionIds: required } });
  }
  for (let i = 0; i < 4; i += 1) {
    const parent = permissions[Math.floor(rand() * permissions.length)];
    if (parent.constraints.maxDelegationDepth === 0) continue;
    permissions.push({ kind: "PERMISSION", authorityId: `p${i}`, grantorId: parent.granteeId, granteeId: ACTORS[Math.floor(rand() * ACTORS.length)], rootAuthorityId: parent.rootAuthorityId, parentAuthorityId: parent.authorityId, independent: rand() < 0.5,
      constraints: { actions: subsetOf(rand, parent.constraints.actions), resources: subsetOf(rand, parent.constraints.resources), quantitative: false, maxDelegationDepth: parent.constraints.maxDelegationDepth - 1, requiredIntersectionIds: parent.constraints.requiredIntersectionIds } });
  }
  for (let i = 0; i < 2; i += 1) {
    if (rand() < 0.5) continue;
    const constraints = { actions: subsetOf(rand, ACTIONS), resources: subsetOf(rand, RESOURCES), quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [] };
    if (rand() < 0.3) prohibitions.push({ kind: "PROHIBITION", scope: "GLOBAL", authorityId: `g${i}`, grantorId: "policy", constraints });
    else {
      const parent = permissions[Math.floor(rand() * permissions.length)];
      prohibitions.push({ kind: "PROHIBITION", scope: "ROOT", authorityId: `x${i}`, grantorId: parent.granteeId, rootAuthorityId: parent.rootAuthorityId, parentAuthorityId: parent.authorityId,
        ...(rand() < 0.5 ? { subjectActorId: ACTORS[Math.floor(rand() * ACTORS.length)] } : {}), constraints: { ...constraints, actions: subsetOf(rand, parent.constraints.actions), resources: subsetOf(rand, parent.constraints.resources) } });
    }
  }
  return { permissions, prohibitions };
};
/**
 * G6.5 A-133.2: `allow` is the pre-preflight verdict (the §4 algebra yields a successful candidate). Returns it with the
 * final result, observed through the test-only `observeAlgebraForTests` hook.
 */
const evaluateScoped = (corpus, revoked, request) => {
  let algebra;
  A.observeAlgebraForTests((found) => { algebra = found; });
  try {
    const result = evaluateRaw(corpus, revoked, request);
    return { allow: algebra === true, result };
  } finally {
    A.observeAlgebraForTests(undefined);
  }
};
/** A-133.7: the final decision differs from the pre-preflight verdict only by OUTPUT_LIMIT_EXCEEDED. */
const assertOnlyPreflightDiffers = ({ allow, result }, what) => {
  if (allow) assert.ok(result.decision === "ALLOW" || (result.decision === "INDETERMINATE" && result.code === "OUTPUT_LIMIT_EXCEEDED"), `${what}: a successful candidate ended ${result.decision} ${result.code}`);
  else assert.notEqual(result.decision, "ALLOW", `${what}: ALLOW without a successful candidate`);
};
const evaluate = (corpus, revoked, request) => evaluateRaw(corpus, revoked, request).decision === "ALLOW";
const evaluateRaw = ({ permissions, prohibitions }, revoked, request) => A.evaluateAuthorityPath({
  operationVersion: A.AUTHORITY_EVALUATION_VERSION,
  scope: { domain: DOMAIN_02, policyVersion: "asm/0.2", rootRecognitionPolicy: A.ROOT_RECOGNITION_POLICY, historyHead: HEAD, evaluationTime: 100,
    recognizedRoots: permissions.filter((p) => p.parentAuthorityId === undefined).map((p) => ({ rootAuthorityId: p.authorityId, principalId: "P", principalRecognitionEventId: "ev-p", rootGrantEventId: `ev-${p.authorityId}` })), globalPolicySourceId: "policy" },
  request, permissions, prohibitions, authorityEvidence: [...permissions, ...prohibitions].map((p, i) => ({ authorityId: p.authorityId, grantEventId: `ev-${p.authorityId}`, grantEventPosition: i + 1 })), revokedAuthorityIds: [...revoked], usage: [],
});
const requests = ACTORS.flatMap((actorId) => ACTIONS.flatMap((action) => RESOURCES.map((resource) => ({ actorId, action, resource, claimedAt: 100 }))));
/** A-116 `anc`: the permission ids above `grant` (parentAuthorityId chain). */
const ancestry = (grants, grant) => { const out = []; for (let id = grant.parentAuthorityId; id !== undefined; id = grants.find((g) => g.authorityId === id)?.parentAuthorityId) out.push(id); return out; };

test("ASM-1 (revocation is monotone; `allow` re-scoped to the pre-preflight verdict by G6.5 A-133.2): revoking a PERMISSION no live prohibition depends on never creates a successful candidate", () => {
  const rand = prng(116_1);
  let checked = 0, allows = 0, prohibited = 0;
  for (let trial = 0; trial < 300; trial += 1) {
    const f = forest(rand);
    for (const permission of f.permissions) {
      if (f.prohibitions.some((x) => ancestry(f.permissions, x).includes(permission.authorityId))) continue;
      for (const request of requests) {
        const before = evaluateScoped(f, [], request), after = evaluateScoped(f, [permission.authorityId], request);
        assertOnlyPreflightDiffers(before, `trial ${trial} before`);
        assertOnlyPreflightDiffers(after, `trial ${trial} after revoking ${permission.authorityId}`);
        allows += before.allow ? 1 : 0;
        prohibited += before.result.code === "PROHIBITED" ? 1 : 0;
        checked += 1;
        assert.ok(!after.allow || before.allow, `trial ${trial}: revoking ${permission.authorityId} allowed ${JSON.stringify(request)}`);
      }
    }
  }
  assert.ok(checked > 5000 && allows > 500, `the forests exercise the procedure (${checked} comparisons, ${allows} allows)`);
  assert.ok(prohibited > 100, `prohibitions are exercised, not refused as INVALID_DELEGATION (${prohibited} PROHIBITED)`);
});

// G6.5 A-133 / A-135: Programme 3's three ASM-1 reachability families, each with an oversized or overflowing winner
// a-main and a byte-later independent fallback z-fallback, both held by actor A. Under the re-scoped `allow` none is an
// expansion; (a) and (b) keep their final INDETERMINATE / OUTPUT_LIMIT_EXCEEDED (the preflight, outside ASM-1, E-31),
// (c) is ALLOW before and after since AMOUNT_OVERFLOW is a candidate failure (A-135).
const P3 = { actorId: "A", action: "pay", resource: "r1", claimedAt: 100 };
const p3Root = (authorityId, extra = {}) => ({ kind: "PERMISSION", authorityId, grantorId: "P", granteeId: "A", rootAuthorityId: authorityId, independent: true,
  constraints: { actions: ["pay"], resources: ["r1"], quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [] }, ...extra });
const nnn = (i) => String(i).padStart(3, "0");

test("ASM-1 family (a), A-133: 257 revoked ROOT prohibitions on the winner: INDETERMINATE / OUTPUT_LIMIT_EXCEEDED before, ALLOW on the fallback after revoking a-main; the pre-preflight verdict is allow in both", () => {
  const prohibitions = Array.from({ length: 257 }, (_, i) => ({ kind: "PROHIBITION", scope: "ROOT", authorityId: `x-${nnn(i)}`, grantorId: "A", rootAuthorityId: "a-main", parentAuthorityId: "a-main", subjectActorId: "A",
    constraints: { actions: ["pay"], resources: ["r1"], quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [] } }));
  const main = p3Root("a-main");
  const f = { permissions: [{ ...main, constraints: { ...main.constraints, maxDelegationDepth: 1 } }, p3Root("z-fallback")], prohibitions };
  const revokedProhibitions = prohibitions.map((x) => x.authorityId);
  const before = evaluateScoped(f, revokedProhibitions, P3), after = evaluateScoped(f, [...revokedProhibitions, "a-main"], P3);
  assert.deepEqual([before.result.decision, before.result.code], ["INDETERMINATE", "OUTPUT_LIMIT_EXCEEDED"]);
  assert.equal(after.result.decision, "ALLOW");
  assert.equal(after.result.proof.recognizedRoot.rootAuthorityId, "z-fallback");
  assert.deepEqual(after.result.proof.checkedProhibitionIds, []);
  for (const [r, what] of [[before, "before"], [after, "after"]]) assertOnlyPreflightDiffers(r, what);
  assert.ok(before.allow && after.allow, "the pre-preflight verdict is allow on both sides: no expansion");
});

test("ASM-1 family (b), A-133: 256 dependent partner paths plus main (257 controlling ids), zero prohibitions: OUTPUT_LIMIT_EXCEEDED before, ALLOW after; the pre-preflight verdict is allow in both", () => {
  // a-main requires d-000…d-031; d-000…d-006 each require 32 more (d-032…d-255): 256 dependent roots held by A.
  const required = (i) => (i === -1 ? Array.from({ length: 32 }, (_, k) => `d-${nnn(k)}`) : i < 7 ? Array.from({ length: 32 }, (_, k) => `d-${nnn(32 + 32 * i + k)}`) : []);
  const withRequired = (grant, ids) => ({ ...grant, constraints: { ...grant.constraints, requiredIntersectionIds: ids } });
  const partners = Array.from({ length: 256 }, (_, i) => withRequired(p3Root(`d-${nnn(i)}`, { independent: false }), required(i)));
  const f = { permissions: [withRequired(p3Root("a-main"), required(-1)), ...partners, p3Root("z-fallback")], prohibitions: [] };
  const before = evaluateScoped(f, [], P3), after = evaluateScoped(f, ["a-main"], P3);
  assert.deepEqual([before.result.decision, before.result.code], ["INDETERMINATE", "OUTPUT_LIMIT_EXCEEDED"]);
  assert.equal(after.result.decision, "ALLOW");
  assert.equal(after.result.proof.recognizedRoot.rootAuthorityId, "z-fallback");
  for (const [r, what] of [[before, "before"], [after, "after"]]) assertOnlyPreflightDiffers(r, what);
  assert.ok(before.allow && after.allow, "the pre-preflight verdict is allow on both sides: no expansion");
});

test("ASM-3 (intersections fail closed): a revoked required-intersection member fails the path that requires it", () => {
  const rand = prng(116_3);
  let gatedChecks = 0;
  for (let trial = 0; trial < 400; trial += 1) {
    const f = forest(rand);
    for (const gated of f.permissions.filter((p) => p.constraints.requiredIntersectionIds.length > 0)) {
      for (const member of gated.constraints.requiredIntersectionIds) {
        // Only the gated path: drop every other permission whose grantee could be the actor, then revoke the member.
        const only = { permissions: f.permissions.filter((p) => p === gated || p.authorityId === member || ancestry(f.permissions, gated).includes(p.authorityId)), prohibitions: [] };
        for (const request of requests.filter((r) => r.actorId === gated.granteeId)) {
          if (!evaluate(only, [], request)) continue;
          gatedChecks += 1;
          if (only.permissions.some((p) => p !== gated && p.granteeId === request.actorId && p.constraints.requiredIntersectionIds.length === 0 && p.independent)) continue;
          assert.equal(evaluate(only, [member], request), false, `trial ${trial}: ${gated.authorityId} allowed with its member ${member} revoked`);
        }
      }
    }
  }
  assert.ok(gatedChecks > 20, `gated paths were exercised (${gatedChecks})`);
});

// ---------------------------------------------------------------- replayed history (ASM-2, ASM-4, ASM-5)

const O1 = keyPairFromPrivateKey("ed25519", "owner:1", `0x${"0".repeat(60)}6301`);
const DOMAIN = { protocol: "irontrellis", version: "2", deploymentId: "asm-history" };
const genesis = {
  id: "event:genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 100,
  data: { adapterPolicyHash: core.ADAPTER_POLICY_HASH, canonicalLineageId: "lineage:asm", domain: DOMAIN, finality: "LOCAL_ONLY", globalPolicySourceId: "policy:asm", ownerKeys: [{ keyId: "owner:1", scheme: "ed25519", credential: O1.credential }],
    policyVersion: "irontrellis-local-owner/2", rootRecognitionPolicy: "declared-principal-root/0.2", timeSource: "EVENT_TIMESTAMP", versions: { ...core.FORMAT2_VERSIONS, signatureScheme: "ed25519" } },
};
const append = (events, type, data) => {
  const head = core.replay(events).head, event = { id: `event:${events.length}`, type, timestamp: 100 + events.length, data };
  const hash = core.controlAuthorizationHash({ domain: DOMAIN, eventId: event.id, eventType: type, timestamp: event.timestamp, previousHead: { hash: head.hash, position: head.position }, effectHash: core.controlEffectHash(event, "sha256") }, "sha256");
  const next = [...events, { ...event, data: { ...data, controlAuthorization: { keyId: "owner:1", signature: signerFromKeyPair(O1).signHashSync(hash) } } }];
  const r = core.replay(next);
  assert.equal(r.status, "ACCEPTED", `${type}: ${r.reason}`);
  return next;
};
const C = (actions, depth) => ({ actions, maxDelegationDepth: depth, quantitative: false, requiredIntersectionIds: [], resources: ["vendor"] });
let base = [genesis];
base = append(base, "PRINCIPAL_CREATED", { principalId: "ops" });
for (const agentId of ["bea", "cal", "dan"]) base = append(base, "AGENT_CREATED", { agentId, principalId: "ops", controllerId: "operator", initialControlEpoch: 1 });
base = append(base, "AUTHORITY_GRANTED", { grant: { authorityId: "root", constraints: C(["pay", "read"], 3), granteeId: "bea", grantorId: "ops", independent: true, kind: "PERMISSION", rootAuthorityId: "root" } });
base = append(base, "AUTHORITY_GRANTED", { grant: { authorityId: "g-cal", constraints: C(["pay", "read"], 2), granteeId: "cal", grantorId: "bea", independent: true, kind: "PERMISSION", parentAuthorityId: "root", rootAuthorityId: "root" } });
base = append(base, "AUTHORITY_GRANTED", { grant: { authorityId: "g-dan", constraints: C(["pay", "read"], 1), granteeId: "dan", grantorId: "cal", independent: true, kind: "PERMISSION", parentAuthorityId: "g-cal", rootAuthorityId: "root" } });
base = append(base, "AUTHORITY_GRANTED", { grant: { authorityId: "g-stop", constraints: C(["pay"], 0), grantorId: "cal", kind: "PROHIBITION", parentAuthorityId: "g-cal", rootAuthorityId: "root", scope: "ROOT", subjectActorId: "dan" } });
base = append(base, "ROLE_CREATED", { roleId: "desk", principalId: "ops", exclusive: true });
base = append(base, "AGENT_APPOINTED", { agentId: "cal", principalId: "ops", roleId: "desk", roleTenureId: "desk:1", tenureNumber: 1 });
base = append(base, "SUCCESSION_RULE_DECLARED", { permittedEventTypes: ["AGENT_TERMINATED"], predecessorAgentId: "cal", principalId: "ops", roleId: "desk", ruleId: "rule:cal", successorAgentId: "bea", trigger: "AGENT_TERMINATED" });

const decisions = (events) => {
  const r = core.replay(events);
  const grid = ["bea", "cal", "dan"].flatMap((actorId) => ["pay", "read"].map((action) => ({ actorId, action, resource: "vendor", claimedAt: 500 })));
  return new Map(grid.map((request) => [`${request.actorId}/${request.action}`, A.authorizeState(r.state, {
    domain: DOMAIN, expectedHistoryHead: r.head, policyVersion: genesis.data.policyVersion, rootRecognitionPolicy: genesis.data.rootRecognitionPolicy, request, consequential: false, evaluationTime: 500,
  }).decision === "ALLOW"]));
};
/** allow(after, r, t) ⇒ allow(before, r, t) for every request of the grid (the non-expansion direction). */
const neverWidens = (before, after, what) => { for (const [request, allowed] of after) assert.ok(!allowed || before.get(request), `${what} allowed ${request}`); };

test("ASM-2 as restated by A-127.1 (prohibitions persist with their path): terminating an actor on a live PROHIBITION's anchor path ends it with every permission on that path, so nothing widens; such a termination is never PR_eff (A-127.2)", () => {
  const before = decisions(base);
  assert.equal(before.get("dan/pay"), false, "g-stop denies dan's pay");
  assert.equal(before.get("dan/read"), true, "dan reads under g-dan");
  const terminate = { agentId: "cal", principalId: "ops", roleId: "desk", roleTenureId: "desk:1", successionRuleId: "rule:cal" };
  const terminated = append(base, "AGENT_TERMINATED", terminate);
  const after = decisions(terminated);
  assert.equal(after.get("dan/pay"), false, "the prohibition's path (g-cal, g-dan) ends with it: dan still cannot pay");
  assert.equal(after.get("dan/read"), false, "g-dan's path through cal ends too");
  neverWidens(before, after, "terminating cal");
  // A-127.2: cal (the prohibition's grantor) and bea (grantee of root, grantor of g-cal: both in anc(g-stop)) are on the
  // anchor path, so terminating either is not PR_eff; dan is on no prohibition's path.
  const state = core.replay(base).state;
  const termination = (agentId) => ({ id: "event:t", type: "AGENT_TERMINATED", timestamp: 999, data: { ...terminate, agentId } });
  assert.deepEqual(["cal", "bea", "dan"].map((agentId) => core.prEffective(termination(agentId), state)), [false, false, true]);
});

test("ASM-4 (lifecycle is conjunctive): a fence or a termination only causes denial", () => {
  const before = decisions(base);
  neverWidens(before, decisions(append(base, "CONTROL_EPOCH_ADVANCED", { agentId: "bea", controllerId: "operator", fromEpoch: 1, toEpoch: 2 })), "fencing bea");
  neverWidens(before, decisions(append(base, "CONTROL_EPOCH_ADVANCED", { agentId: "cal", controllerId: "operator", fromEpoch: 1, toEpoch: 2 })), "fencing cal");
  neverWidens(before, decisions(append(base, "AGENT_TERMINATED", { agentId: "cal", principalId: "ops", roleId: "desk", roleTenureId: "desk:1", successionRuleId: "rule:cal" })), "terminating cal");
});

test("ASM-5 (budgets deny only): declaring a budget never turns a denial into ALLOW", () => {
  const before = decisions(base);
  const zero = append(base, "BUDGET_DECLARED", { budgetId: "b-zero", subjects: { actorIds: ["dan"], roleIds: null, actions: null, resources: null }, metric: null, period: { kind: "NONE" }, amountCap: null, countCap: 0, perOperationCap: null, notBefore: null, expiresAt: null });
  const after = decisions(zero);
  neverWidens(before, after, "a zero-count budget on dan");
  assert.equal(after.get("dan/read"), false, "the budget denies what g-dan allowed");
  assert.equal(after.get("bea/read"), before.get("bea/read"), "an unselected actor is untouched");
});

test("ASM-1 family (c), A-135: admitted usage at MAX on the winner a-main, then a request of 1, zero prohibitions: AMOUNT_OVERFLOW is a candidate failure, so z-fallback wins and the decision is ALLOW both before and after revoking a-main", () => {
  const MAX = (1n << 256n) - 1n;
  const Q = { actions: ["pay"], maxDelegationDepth: 0, quantitative: true, requiredIntersectionIds: [], resources: ["vendor"] };
  let events = append([genesis, ...base.slice(1, 3)], "AUTHORITY_GRANTED", { grant: { authorityId: "a-main", constraints: Q, granteeId: "bea", grantorId: "ops", independent: true, kind: "PERMISSION", rootAuthorityId: "a-main" } });
  events = append(events, "AUTHORITY_GRANTED", { grant: { authorityId: "z-fallback", constraints: Q, granteeId: "bea", grantorId: "ops", independent: true, kind: "PERMISSION", rootAuthorityId: "z-fallback" } });
  const decide = (list) => {
    const r = core.replay(list);
    // Admitted usage at MAX on a-main (injected: the vectors authorization/v2r/allow-*-overflow reach it by admission).
    r.state.usageCounters.set("a-main", Object.freeze({ authorityId: "a-main", admittedTransactionCount: 1, admittedCumulativeAmount: MAX }));
    let algebra;
    A.observeAlgebraForTests((found) => { algebra = found; });
    try {
      const result = A.authorizeState(r.state, { domain: DOMAIN, expectedHistoryHead: r.head, policyVersion: genesis.data.policyVersion, rootRecognitionPolicy: genesis.data.rootRecognitionPolicy,
        request: { actorId: "bea", action: "pay", resource: "vendor", claimedAt: 500, amount: "1" }, consequential: false, evaluationTime: 500 });
      return { allow: algebra === true, result };
    } finally {
      A.observeAlgebraForTests(undefined);
    }
  };
  const before = decide(events), after = decide(append(events, "AUTHORITY_REVOKED", { authorityId: "a-main", revokerId: "ops" }));
  for (const [r, what] of [[before, "before"], [after, "after"]]) {
    assert.equal(r.result.decision, "ALLOW", `${what}: ${r.result.code}`);
    assert.equal(r.result.proof.recognizedRoot.rootAuthorityId, "z-fallback", what);
    assertOnlyPreflightDiffers(r, what);
  }
  assert.ok(before.allow && after.allow, "the pre-preflight verdict is allow on both sides: no expansion");
  // Only a-main: the candidate itself fails AMOUNT_OVERFLOW (DENY, source CORE, no budget).
  const alone = core.replay(events.slice(0, -1)).state;
  alone.usageCounters.set("a-main", Object.freeze({ authorityId: "a-main", admittedTransactionCount: 1, admittedCumulativeAmount: MAX }));
  const denied = A.authorizeState(alone, { domain: DOMAIN, expectedHistoryHead: core.replay(events.slice(0, -1)).head, policyVersion: genesis.data.policyVersion, rootRecognitionPolicy: genesis.data.rootRecognitionPolicy,
    request: { actorId: "bea", action: "pay", resource: "vendor", claimedAt: 500, amount: "1" }, consequential: false, evaluationTime: 500 });
  assert.deepEqual([denied.decision, denied.code, denied.failures.map((f) => [f.code, f.failingAuthorityId])], ["DENY", "AMOUNT_OVERFLOW", [["AMOUNT_OVERFLOW", "a-main"]]]);
});
