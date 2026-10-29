/** Shared, offline, deterministic test scaffolding. No network, no signer, no executor. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

export const FIXTURES = fileURLToPath(new URL('./fixtures/', import.meta.url));
export const core = await import('../packages/core-0.2/src/core/index.ts');

/** Amounts are written as {"$continuity.bigint":"…"} because JSON has no BigInt. Core wants real ones. */
const reviveBigints = (_key, value) =>
  (value !== null && typeof value === 'object' && typeof value['$continuity.bigint'] === 'string' ? BigInt(value['$continuity.bigint']) : value);

const load = name => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'), reviveBigints);

/** The handover history: A collects, is replaced by B, loses its grant; the duty stays OPEN. */
export const handover = Object.freeze({
  events: load('handover-history.json'),
  config: load('handover-case.json'),
  caseId: 'first-look',
  jsonl: join(FIXTURES, 'handover-history.jsonl'),
});

/** The same handover, with B's review permission revoked as well. */
export const handoverDenied = Object.freeze({
  events: load('handover-denied-history.json'),
  config: load('handover-denied-case.json'),
  caseId: 'no-review-power',
});

/**
 * A quantitative mandate: 2500 per purchase, 5000 cumulative, 3 purchases, plus a
 * narrower delegation and a non-quantitative grant to contrast against. Every other
 * fixture is `quantitative: false`, so without this one amounts go untested.
 */
export const mandate = Object.freeze({
  events: load('mandate-history.json'),
  config: load('mandate-case.json'),
  caseId: 'mandate',
});

export const MANDATE = Object.freeze({
  principal: 'principal:mandate',
  buyer: 'buyer:mandate',
  researcher: 'researcher:mandate',
  plush: 'plush:mandate',
  mandateAuthority: 'mandate-authority:mandate',
  researchAuthority: 'research-authority:mandate',
  reportAuthority: 'report-authority:mandate',
  perPurchase: 2500n,
  cumulative: 5000n,
  purchases: 3,
});

export const replay = events => core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events });

/** The head of a history, or a placeholder when the history does not replay. */
const headOf = events => replay(events).head ?? { hash: `0x${'0'.repeat(64)}`, position: 0, canonicalTime: 0 };

export function authorize(fixture, { actor, action, resource, at, amount, consequential = false, domain, policyVersion } = {}) {
  const head = replay(fixture.events).head;
  const time = at ?? head.canonicalTime;
  const request = { actorId: actor, action, resource, claimedAt: time };
  if (amount !== undefined) request.amount = amount;
  return core.authorizePortable({
    operationVersion: core.PORTABLE_AUTHORIZATION_VERSION,
    events: fixture.events,
    expectedHistoryHead: head,
    domain: domain ?? fixture.config.domain,
    policyVersion: policyVersion ?? fixture.config.policyVersion ?? `local-evidence-intake-policy:${fixture.caseId}/0.2`,
    rootRecognitionPolicy: core.PORTABLE_ROOT_RECOGNITION_POLICY,
    request,
    evaluationTime: time,
    authoritative: true,
    consequential,
  });
}

export function survives(fixture, agent, at) {
  const head = headOf(fixture.events);
  return core.survivesPortable({
    operationVersion: core.PORTABLE_QUERY_VERSION,
    observedEvents: fixture.events,
    targetAgentId: agent,
    evaluationTime: at ?? head.canonicalTime,
    disclosure: core.portablePublicQueryDisclosure('SURVIVES'),
  });
}

export function why(fixture, { actor, action, resource, at } = {}) {
  const head = headOf(fixture.events);
  const time = at ?? head.canonicalTime;
  return core.whyPortable({
    operationVersion: core.PORTABLE_QUERY_VERSION,
    evaluationEvents: fixture.events, observedEvents: fixture.events,
    authorizationDomain: fixture.config.domain,
    request: { actorId: actor, action, resource, claimedAt: time },
    evaluationTime: time,
    disclosure: core.portablePublicQueryDisclosure('WHY'),
  });
}

export function responsible(fixture, { actor, action, resource, at } = {}) {
  const head = headOf(fixture.events);
  const time = at ?? head.canonicalTime;
  return core.responsiblePortable({
    operationVersion: core.PORTABLE_QUERY_VERSION,
    evaluationEvents: fixture.events, observedEvents: fixture.events,
    authorizationDomain: fixture.config.domain,
    request: { actorId: actor, action, resource, claimedAt: time },
    evaluationTime: time,
    disclosure: core.portablePublicQueryDisclosure('RESPONSIBLE'),
  });
}

/** Structured clone that keeps the fixture immutable across tests. */
export const clone = value => structuredClone(value);

/** The identifiers used throughout the handover fixture. */
export const ID = Object.freeze({
  a: 'a:first-look',
  b: 'b:first-look',
  principal: 'principal:first-look',
  obligation: 'obligation:first-look',
  resource: 'resource:first-look',
  role: 'role:first-look',
  succession: 'succession:first-look',
  collectAuthority: 'collect-authority:first-look',
  reviewAuthorityB: 'progress-b-authority:first-look',
  reviewAuthorityA: 'progress-a-authority:first-look',
});
