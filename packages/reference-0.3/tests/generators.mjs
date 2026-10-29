/**
 * Deterministic history generators for property-based testing.
 *
 * Every history produced here is built from real, schema-valid events and is checked by
 * Core's own replay before a property is asserted against it — so input validity is checked separately. A failed assertion still requires
 * diagnosis of the property, fixture, harness and engine.
 *
 * Everything is seeded. A failing property prints its seed, and
 * `generateHistory(seed)` reproduces the exact history that failed.
 */
import { core } from './helpers.mjs';

/** mulberry32 — small, fast, fully deterministic. */
export function makeRng(seed) {
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
    pick: list => list[Math.floor(next() * list.length)],
    /** A non-empty subset, preserving order so constraint lists stay canonical. */
    subset(list, { min = 1, max = list.length } = {}) {
      const size = Math.max(min, Math.min(max, 1 + Math.floor(next() * list.length)));
      const chosen = [];
      const pool = [...list];
      for (let taken = 0; taken < size && pool.length > 0; taken += 1) {
        chosen.push(pool.splice(Math.floor(next() * pool.length), 1)[0]);
      }
      return chosen.sort();
    },
    bool: (probability = 0.5) => next() < probability,
  };
}

const GENESIS_VERSIONS = Object.freeze({
  administrativeAuthorizationVersion: 'continuity-administrative-authorization/0.2',
  authorizationProofVersion: 'continuity-authorization-proof/0.2',
  eventSchemaVersion: 'continuity-event/0.2',
  queryEnvelopeVersion: 'continuity-query-envelope/0.2',
  receiptSchemaVersion: 'continuity-receipt/0.2',
  runtimeAuthorizationVersion: 'continuity-runtime-authorization/0.2',
  signatureScheme: 'eip191-personal-sign-keccak256',
});

const ACTION_POOL = ['read', 'write', 'review', 'collect', 'escalate', 'archive'];
const RESOURCE_POOL = ['alpha', 'beta', 'gamma', 'delta'];

const event = (timestamp, type, id, data) => ({ data, id, timestamp, type });

const constraints = ({ actions, resources, expiresAt, maxDelegationDepth, requiredIntersectionIds = [], notBefore }) => {
  const record = {
    actions: [...actions].sort(),
    expiresAt,
    maxDelegationDepth,
    quantitative: false,
    requiredIntersectionIds: [...requiredIntersectionIds].sort(),
    resources: [...resources].sort(),
  };
  if (notBefore !== undefined) record.notBefore = notBefore;
  return record;
};

/**
 * Build a random but valid history.
 *
 * Shape: a principal, several agents, a role with a succession rule, root grants from
 * the principal, optional attenuated delegations, optional required intersections,
 * optional revocations, and optionally a full handover (epoch advance, termination,
 * role transfer).
 */
export function generateHistory(seed) {
  const rng = makeRng(seed);
  const id = `s${seed}`;
  const qualify = name => `${name}:${id}`;

  const domain = Object.freeze({
    chainId: '31337',
    deploymentId: `generated:${id}`,
    protocol: 'continuity',
    verifyingContract: '0x0000000000000000000000000000000000003002',
    version: '0.2',
  });
  const policyVersion = `generated-policy:${id}/0.2`;

  const events = [];
  let clock = 0;
  const emit = (type, name, data) => { events.push(event(clock, type, qualify(name), data)); clock += 1; };

  emit('DEPLOYMENT_INITIALIZED', 'genesis', {
    adapterPolicyHash: core.PORTABLE_ADAPTER_POLICY_HASH,
    canonicalLineageId: qualify('lineage'),
    domain,
    finality: 'LOCAL_ONLY',
    globalPolicySourceId: qualify('policy-source'),
    policyVersion,
    rootRecognitionPolicy: core.PORTABLE_ROOT_RECOGNITION_POLICY,
    timeSource: 'EVENT_TIMESTAMP',
    versions: GENESIS_VERSIONS,
  });

  const principalId = qualify('principal');
  const controllerId = qualify('controller');
  emit('PRINCIPAL_CREATED', 'principal', { principalId });

  const agentCount = rng.int(2, 4);
  const agents = [];
  for (let index = 0; index < agentCount; index += 1) {
    const agentId = qualify(`agent${index}`);
    agents.push(agentId);
    emit('AGENT_CREATED', `agent${index}`, { agentId, controllerId, initialControlEpoch: 1, principalId });
  }

  const roleId = qualify('role');
  const successionRuleId = qualify('succession');
  emit('ROLE_CREATED', 'role', { exclusive: true, principalId, roleId });
  emit('SUCCESSION_RULE_DECLARED', 'succession', {
    permittedEventTypes: ['AGENT_TERMINATED', 'ROLE_TRANSFERRED', 'OBLIGATION_PERFORMANCE_ASSIGNED'],
    predecessorAgentId: agents[0], principalId, roleId, ruleId: successionRuleId,
    successorAgentId: agents[1], trigger: 'AGENT_TERMINATED',
  });
  emit('AGENT_APPOINTED', 'appointment', {
    agentId: agents[0], principalId, roleId, roleTenureId: qualify('tenure0'),
    successionRuleId, tenureNumber: 1,
  });

  const actions = rng.subset(ACTION_POOL, { min: 2 });
  const resources = rng.subset(RESOURCE_POOL, { min: 1 }).map(qualify);
  const EXPIRY = 10_000;

  // Root grants, direct from the principal. Each is its own recognized root.
  const roots = [];
  const grantCount = rng.int(1, Math.min(3, agents.length));
  for (let index = 0; index < grantCount; index += 1) {
    const authorityId = qualify(`root${index}`);
    const granteeId = agents[index % agents.length];
    const grant = {
      authorityId,
      constraints: constraints({
        actions: rng.subset(actions, { min: 1 }),
        resources: rng.subset(resources, { min: 1 }),
        expiresAt: EXPIRY,
        // Mostly delegable, so multi-step permission paths actually occur. A corpus
        // where every root has depth 0 would leave "delegation narrows" untested.
        maxDelegationDepth: rng.int(1, 3),
      }),
      granteeId, grantorId: principalId, independent: true, kind: 'PERMISSION',
      rootAuthorityId: authorityId,
    };
    roots.push(grant);
    emit('AUTHORITY_GRANTED', `root${index}`, { grant });
  }

  // Attenuated delegations. Constructed to satisfy constraintsAreAttenuated by
  // construction — the point of the test is that the engine ALSO enforces it.
  const delegations = [];
  for (const parent of roots) {
    if (parent.constraints.maxDelegationDepth === 0 || !rng.bool(0.85)) continue;
    const granteeId = rng.pick(agents.filter(agent => agent !== parent.granteeId));
    if (granteeId === undefined) continue;
    const authorityId = qualify(`deleg${delegations.length}`);
    const grant = {
      authorityId,
      constraints: constraints({
        actions: rng.subset(parent.constraints.actions, { min: 1 }),
        resources: rng.subset(parent.constraints.resources, { min: 1 }),
        expiresAt: rng.bool(0.5) ? parent.constraints.expiresAt : parent.constraints.expiresAt - 100,
        maxDelegationDepth: Math.max(0, parent.constraints.maxDelegationDepth - 1),
        requiredIntersectionIds: parent.constraints.requiredIntersectionIds,
      }),
      granteeId, grantorId: parent.granteeId,
      // `independent: true` means this authority can be exercised on its own, producing
      // a multi-step permission path (root → delegation) whose effective constraints
      // are the intersection of every step. An `independent: false` authority cannot
      // stand alone and is only reachable as an intersection partner — which would make
      // the "delegation narrows" invariant untestable, since no path would ever form.
      independent: true,
      kind: 'PERMISSION',
      parentAuthorityId: parent.authorityId, rootAuthorityId: parent.rootAuthorityId,
    };
    delegations.push(grant);
    emit('AUTHORITY_GRANTED', `deleg${delegations.length - 1}`, { grant });
  }

  // A grant that is exercisable only in intersection with another authority the same
  // agent holds. This is the "intersection, never union" semantic: holding two
  // authorities must narrow what is permitted, not widen it.
  const intersecting = [];
  let gatedAction;
  if (roots.length > 0 && rng.bool(0.6)) {
    const base = roots[0];
    const partnerId = qualify('partner');
    const partnerActions = rng.subset(actions, { min: 1 });
    const partner = {
      authorityId: partnerId,
      constraints: constraints({
        actions: partnerActions, resources: [...resources],
        expiresAt: EXPIRY, maxDelegationDepth: 0,
      }),
      granteeId: base.granteeId, grantorId: principalId, independent: true,
      kind: 'PERMISSION', rootAuthorityId: partnerId,
    };
    emit('AUTHORITY_GRANTED', 'partner', { grant: partner });
    intersecting.push(partner);

    // The gated authority is the ONLY grant covering this action. Without that, a
    // broader ungated path always covers the same request and the engine selects it,
    // so the requirement is never load-bearing and the invariant goes untested.
    gatedAction = `gate-only-${id}`;
    const gatedId = qualify('gated');
    const gated = {
      authorityId: gatedId,
      constraints: constraints({
        actions: [gatedAction],
        resources: [...resources],
        expiresAt: EXPIRY, maxDelegationDepth: 0, requiredIntersectionIds: [partnerId],
      }),
      granteeId: base.granteeId, grantorId: principalId, independent: true,
      kind: 'PERMISSION', rootAuthorityId: gatedId,
    };
    emit('AUTHORITY_GRANTED', 'gated', { grant: gated });
    intersecting.push(gated);
  }

  const allGrants = [...roots, ...delegations, ...intersecting];

  // A handover: the predecessor's epoch advances, it is terminated, the role transfers.
  let handoverAt;
  if (rng.bool(0.5)) {
    handoverAt = events.length;
    emit('CONTROL_EPOCH_ADVANCED', 'epoch', { agentId: agents[0], controllerId, fromEpoch: 1, toEpoch: 2 });
    emit('AGENT_TERMINATED', 'terminate', {
      agentId: agents[0], principalId, roleId, roleTenureId: qualify('tenure0'), successionRuleId,
    });
    emit('ROLE_TRANSFERRED', 'transfer', {
      fromAgentId: agents[0], fromRoleTenureId: qualify('tenure0'), principalId, roleId,
      successionRuleId, toAgentId: agents[1], toRoleTenureId: qualify('tenure1'),
      toTenureNumber: 2, transferKind: 'SUCCESSION',
    });
  }

  // Revocations, always last so a prefix without them is also a valid history.
  const revokedAt = events.length;
  const revoked = [];
  for (const grant of allGrants) {
    if (!rng.bool(0.35)) continue;
    const revokerId = grant.parentAuthorityId === undefined ? principalId : grant.grantorId;
    revoked.push(grant.authorityId);
    emit('AUTHORITY_REVOKED', `revoke${revoked.length}`, { authorityId: grant.authorityId, revokerId });
  }

  return {
    seed, id, events, domain, policyVersion, principalId, controllerId,
    agents, roleId,
    // The gate-only action is included so the request grid actually asks for it.
    actions: gatedAction === undefined ? actions : [...actions, gatedAction],
    gatedAction,
    resources: [...resources],
    grants: allGrants, roots, delegations, intersecting, revoked,
    handoverAt, revokedAt,
  };
}

/**
 * Replay and decision memoization.
 *
 * Authorizing one request costs tens of milliseconds, because the engine captures and
 * replays the history for every call — correctly, since a decision is meaningless
 * without the head it was evaluated at. Property tests ask the same question of the
 * same event array many times over, so the results are cached by ARRAY IDENTITY. Build
 * each prefix once and reuse the reference; a fresh `.slice()` is a cache miss.
 */
const replayCache = new WeakMap();
const decisionCache = new WeakMap();

/** Replay a history. Callers assert ACCEPTED before testing any property against it. */
export function replayOf(events) {
  const cached = replayCache.get(events);
  if (cached !== undefined) return cached;
  const result = core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events });
  replayCache.set(events, result);
  return result;
}

/** Authorize one request against a history (or a prefix of one). */
export function decide(history, events, request) {
  let perEvents = decisionCache.get(events);
  if (perEvents === undefined) { perEvents = new Map(); decisionCache.set(events, perEvents); }
  const cacheKey = JSON.stringify([request.actor, request.action, request.resource, request.at ?? null]);
  const cached = perEvents.get(cacheKey);
  if (cached !== undefined) return cached;
  const computed = decideUncached(history, events, request);
  perEvents.set(cacheKey, computed);
  return computed;
}

function decideUncached(history, events, { actor, action, resource, at }) {
  const replay = replayOf(events);
  if (replay.status !== 'ACCEPTED') return { decision: 'INDETERMINATE', code: 'STATE_NOT_AUTHORITATIVE' };
  const time = at ?? replay.head.canonicalTime;
  return core.authorizePortable({
    operationVersion: core.PORTABLE_AUTHORIZATION_VERSION,
    events, expectedHistoryHead: replay.head,
    domain: history.domain, policyVersion: history.policyVersion,
    rootRecognitionPolicy: core.PORTABLE_ROOT_RECOGNITION_POLICY,
    request: { actorId: actor, action, resource, claimedAt: time },
    evaluationTime: time, authoritative: true, consequential: false,
  });
}

/** Every (actor, action, resource) worth asking about in this history. */
export function requestGrid(history, { cap = 16 } = {}) {
  const grid = [];
  for (const actor of history.agents) {
    for (const action of history.actions) {
      for (const resource of history.resources) {
        grid.push({ actor, action, resource });
        if (grid.length >= cap) return grid;
      }
    }
  }
  return grid;
}

export const key = request => `${request.actor}|${request.action}|${request.resource}`;

/** The set of requests a history currently permits. The central object of these tests. */
export function allowSet(history, events, grid) {
  const allowed = new Set();
  for (const request of grid) {
    if (decide(history, events, request).decision === 'ALLOW') allowed.add(key(request));
  }
  return allowed;
}
