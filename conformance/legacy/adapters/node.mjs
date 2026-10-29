#!/usr/bin/env node
/**
 * Reference conformance adapter for this implementation.
 *
 * The adapter contract (conformance/ADAPTER.md) is deliberately tiny so that a
 * second implementation in any language can satisfy it: read one JSON request per
 * line on stdin, write one JSON response per line on stdout. Nothing else.
 *
 * This file is what an external implementer replaces. Everything else in
 * conformance/ stays the same.
 *
 * IronTrellis: this is the LEGACY adapter, kept verbatim except for the import below,
 * which now points at the frozen reference package (packages/reference-0.2).
 */
import { createInterface } from 'node:readline';

const core = await import('../../../packages/reference-0.2/core-0.2/src/core/index.ts');

// Amounts arrive as {"$continuity.bigint":"…"} and must go back out the same way. Any conforming
// implementation has to decode this envelope; it is part of the wire format, not a
// JavaScript detail.
const revive = value => {
  if (value === null || typeof value !== 'object') return value;
  if (Object.hasOwn(value, '$continuity.bigint')) {
    if (Object.keys(value).length !== 1 || typeof value['$continuity.bigint'] !== 'string' ||
        !/^(0|-?[1-9][0-9]{0,77})$/.test(value['$continuity.bigint'])) {
      throw new Error('INVALID_QUANTITY_ENCODING');
    }
    const amount = BigInt(value['$continuity.bigint']);
    const max = (1n << 256n) - 1n;
    if (amount < -max || amount > max) throw new Error('INVALID_QUANTITY_ENCODING');
    return amount;
  }
  if (Array.isArray(value)) return value.map(revive);
  const out = Object.create(null); // a __proto__ key must become a field, not a prototype
  for (const [key, inner] of Object.entries(value)) out[key] = revive(inner);
  return out;
};
const encode = (_key, value) => (typeof value === 'bigint' ? { '$continuity.bigint': value.toString() } : value);
const plain = value => JSON.parse(JSON.stringify(value, encode));

function handle(request) {
  const { op } = request;

  if (op === 'describe') {
    return {
      implementation: 'continuity-core-0.2-reference',
      language: 'javascript',
      coreVersion: '0.2.2',
      levels: ['verifier', 'evaluator'],
      operations: ['replay', 'authorize', 'survives'],
    };
  }

  if (op === 'replay') {
    const result = core.replayPortable({ operationVersion: request.operationVersion, events: revive(request.events) });
    return { status: result.status, head: plain(result.head ?? null) };
  }

  if (op === 'authorize') {
    const result = core.authorizePortable({
      operationVersion: request.operationVersion,
      events: revive(request.events),
      expectedHistoryHead: request.expectedHistoryHead,
      domain: request.domain,
      policyVersion: request.policyVersion,
      rootRecognitionPolicy: request.rootRecognitionPolicy,
      request: revive(request.request),
      evaluationTime: request.evaluationTime,
      authoritative: request.authoritative,
      consequential: request.consequential,
    });
    return {
      decision: result.decision,
      code: result.code ?? null,
      scopeAssurance: result.scopeAssurance ?? null,
      controllingAuthorityIds: plain(result.proof?.controllingAuthorityIds ?? null),
      failureCodes: (result.failures ?? []).map(failure => failure.code),
    };
  }

  if (op === 'survives') {
    const result = core.survivesPortable({
      operationVersion: request.operationVersion,
      observedEvents: revive(request.events),
      targetAgentId: request.targetAgentId,
      evaluationTime: request.evaluationTime,
      disclosure: core.portablePublicQueryDisclosure('SURVIVES'),
    });
    if (!Object.hasOwn(result, 'answer')) {
      return { established: false, code: result.code, epistemicStatus: result.epistemicStatus };
    }
    const answer = result.answer;
    return {
      established: true,
      exists: answer.exists,
      lifecycleStatus: answer.lifecycleStatus,
      obligationIds: answer.obligations.map(row => row.obligationId ?? row.record?.obligationId ?? null).filter(Boolean).sort(),
      currentAssignments: answer.currentPerformanceAssignments.map(row => ({
        obligationId: row.obligationId, assigneeId: row.assigneeId, successionRuleId: row.successionRuleId ?? null,
      })),
      currentRoleTenureCount: answer.currentRoleTenures.length,
      transferredRoleTenureCount: answer.transferredRoleTenures.length,
      invalidatedAuthorityIds: answer.invalidatedAuthorityDependencies.map(row => row.authorityId ?? row.subjectId ?? null).filter(Boolean).sort(),
      unresolvedIntentIds: answer.unresolvedIntents.map(row => row.intentId ?? null).filter(Boolean).sort(),
    };
  }

  throw new Error(`unsupported op: ${op}`);
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (line.trim() === '') continue;
  let response;
  try { response = { ok: true, result: handle(JSON.parse(line)) }; }
  catch (error) { response = { ok: false, error: error.message }; }
  process.stdout.write(`${JSON.stringify(response)}\n`);
}
