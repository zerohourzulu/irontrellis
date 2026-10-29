/** Adapted contributed Lens: one captured context supplies every field. No
 * signing, append, admission, preparation or executor API is exposed here. */
import * as core from '../packages/core-0.2/src/core/index.ts';
import { readBoundedFile, decodeHistory } from './history-source.mjs';
import { LIMITS, NOTE, fail, validateOptions, boundedResult } from './reader-contract.mjs';

export function openObservation(path, { source = 'local-file', disclosure = 'evidence', configHash = null } = {}) {
  if (!['summary', 'evidence'].includes(disclosure)) fail('CONFIG_INVALID');
  const events = decodeHistory(readBoundedFile(path));
  const replay = core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events });
  // Do not relay replay errors containing values derived from hidden records.
  const head = replay.status === 'ACCEPTED' ? replay.head : null;
  // Keep prior disclosure unchanged; explicitly request current duty semantics
  // only after replay recognizes the activated extension.
  const extensions = head !== null && events.some(event => event.type === 'ATTEMPT_DUTY_POLICY_ACTIVATED')
    ? ['continuity-attempt-disposition/1'] : [];
  const domain = events[0]?.data?.domain;
  const policyVersion = events[0]?.data?.policyVersion;
  const agentIds = head === null ? [] : [...new Set(events.filter(e => e.type === 'AGENT_CREATED').map(e => e.data.agentId))].sort();
  const context = time => ({ source, head, evaluationTime: time, configHash,
    disclosure, assurance: 'LOCAL_REPLAY_ONLY', scopeNote: NOTE });
  function query(kind, args, time) {
    const common = { operationVersion: core.PORTABLE_QUERY_VERSION, observedEvents: events,
      evaluationTime: time, disclosure: core.portablePublicQueryDisclosure(kind, extensions) };
    if (kind === 'SURVIVES') return core.survivesPortable({ ...common, targetAgentId: args.agent });
    return core[kind === 'WHY' ? 'whyPortable' : 'responsiblePortable']({ ...common,
      evaluationEvents: events, authorizationDomain: domain, request: request(args, time) });
  }
  function request(args, time) {
    return { actorId: args.actor, action: args.action, resource: args.resource, claimedAt: time,
      ...(Object.hasOwn(args, 'amount') ? { amount: BigInt(args.amount) } : {}) };
  }
  function report(time) {
    if (agentIds.length > LIMITS.agents) fail('AGENT_LIMIT_EXCEEDED');
    return agentIds.map(agent => ({ agent, result: query('SURVIVES', { agent }, time) }));
  }
  // The only handle contains observation methods. It cannot be fabricated from
  // serialized events/head metadata and conveys no execution authority.
  return Object.freeze({
    observe(operation, args = {}) {
      validateOptions(operation, args);
      if (disclosure === 'summary' && !['verify', 'status', 'check'].includes(operation)) fail('DISCLOSURE_DENIED');
      const time = Object.hasOwn(args, 'at') ? Number(args.at) : head?.canonicalTime ?? null;
      const base = { kind: operation, ...context(time), replayStatus: replay.status, eventCount: events.length };
      if (operation === 'verify') return boundedResult(base);
      if (head === null) fail('HISTORY_REJECTED');
      if (operation === 'status' || operation === 'handover_report') {
        return boundedResult({ ...base, ...(disclosure === 'evidence' ? { agents: report(time) } : {}) });
      }
      if (operation === 'check') {
        const result = core.authorizePortable({ operationVersion: core.PORTABLE_AUTHORIZATION_VERSION,
          events, expectedHistoryHead: head, domain, policyVersion,
          rootRecognitionPolicy: core.PORTABLE_ROOT_RECOGNITION_POLICY,
          request: request(args, time), evaluationTime: time, authoritative: true, consequential: false });
        return boundedResult({ ...base, request: args, decision: result.decision, code: result.code ?? null,
          ...(disclosure === 'evidence' ? { evidence: result } : {}) });
      }
      return boundedResult({ ...base, request: args, result: query(operation.toUpperCase(), args, time) });
    },
  });
}
