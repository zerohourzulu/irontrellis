import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { setup } from '../fixture.mjs';
import { cedarPolicy } from '../cedar.mjs';
import { policyJournal } from '../journal.mjs';
import { openLocalEvidenceTool } from "@ramex-labs/irontrellis/evidence";
const permit = 'permit(principal == Agent::"bea", action == Action::"collect-evidence-packet", resource == Resource::"incident:42");';
async function configured(t, source = permit) {
  const f = await setup(t), journal = join(f.options.outputDirectory, '..', 'policy.jsonl');
  const policy = cedarPolicy(source, policyJournal(journal));
  return { ...f, journal, policy, tool: openLocalEvidenceTool({ ...f.options, additionalPolicy: policy }) };
}
test('actual Cedar allows the exact Core request and records it before one real effect', async t => {
  const f = await configured(t), answer = await f.tool.collect(f.request);
  assert.equal(answer.packet.status, 'PACKET_VERIFIED');
  const evidence = JSON.parse(readFileSync(f.journal, 'utf8'));
  assert.equal(evidence.request.actor, 'bea'); assert.equal(evidence.request.resource, f.request.resource);
  assert.equal(evidence.request.operationId, f.request.operationId);
  assert.equal(evidence.result.identity, f.policy.identity); assert.equal(evidence.result.decision, 'ALLOW');
  assert.equal((await f.tool.collect(f.request)).result.status, 'RECONCILIATION_ONLY');
  assert.equal(readFileSync(f.journal, 'utf8').trim().split('\n').length, 1);
});
for (const [name, source, reason] of [
  ['deny', 'forbid(principal, action, resource);', 'DENY'],
  ['syntax error', 'invalid cedar', 'ERROR'],
  ['permit plus skipped evaluation error', permit + 'permit(principal, action, resource) when { context.missing };', 'ERROR'],
]) test(`Cedar ${name} leaves no protected effect`, async t => {
  const f = await configured(t, source), answer = await f.tool.collect(f.request);
  assert.equal(answer.result.status, 'POLICY_REFUSED'); assert.equal(answer.result.reason, reason);
  assert.deepEqual(readdirSync(f.options.outputDirectory), []);
  assert.equal(JSON.parse(readFileSync(f.journal, 'utf8')).result.decision, reason);
});
test('Core denial cannot be overridden by Cedar permit', async t => {
  const f = await configured(t); await f.owner.revoke('collect');
  assert.equal((await f.tool.collect(f.request)).result.status, 'NOT_AUTHORIZED');
  assert.deepEqual(readdirSync(f.options.outputDirectory), []);
});
test('changing policy identity cannot reinterpret a previously declared operation', async t => {
  const f = await configured(t, 'forbid(principal, action, resource);'); await f.tool.collect(f.request);
  const changed = openLocalEvidenceTool({ ...f.options, additionalPolicy: cedarPolicy(permit, policyJournal(f.journal)) });
  await assert.rejects(changed.collect(f.request), e => e.code === 'OPERATION_CONFLICT');
});
for (const flaw of ['identity', 'requestHash', 'exception', 'audit']) {
  test(`policy ${flaw} failure refuses the effect`, async t => {
    const f = await configured(t), original = f.policy;
    const additionalPolicy = { ...original, evaluate: async request => {
      if (flaw === 'exception') throw Error('private details');
      const answer = original.evaluate(request);
      if (flaw === 'identity' || flaw === 'requestHash') return { ...answer, [flaw]: 'substituted' };
      return answer;
    }, record: flaw === 'audit' ? () => { throw Error('full'); } : original.record };
    const call = openLocalEvidenceTool({ ...f.options, additionalPolicy }).collect(f.request);
    if (flaw === 'audit') await assert.rejects(call, e => e.code === 'POLICY_EVIDENCE_UNAVAILABLE');
    else assert.equal((await call).result.status, 'POLICY_REFUSED');
    assert.deepEqual(readdirSync(f.options.outputDirectory), []);
  });
}
test('retirement during a delayed policy answer cannot authorize a new effect', async t => {
  const f = await configured(t), original = f.policy;
  const additionalPolicy = { ...original, evaluate: async request => {
    await f.owner.advanceEpoch({ agent: 'bea', from: 1, to: 2 }); return original.evaluate(request);
  } };
  await assert.rejects(openLocalEvidenceTool({ ...f.options, additionalPolicy }).collect(f.request), e => e.code === 'HISTORY_CONFLICT');
  assert.deepEqual(readdirSync(f.options.outputDirectory), []);
});
test('expiry during durable policy recording is rechecked before admission', async t => {
  const f = await configured(t); let at = 100;
  const policy = { ...f.policy, record: evidence => { f.policy.record(evidence); at = 200; } };
  await assert.rejects(openLocalEvidenceTool({ ...f.options, now: () => at, additionalPolicy: policy }).collect(f.request), e => e.code === 'RUNTIME_NOT_CURRENT');
  assert.deepEqual(readdirSync(f.options.outputDirectory), []);
});
test('a nonresponsive policy reaches its deadline and records refusal without effect', async t => {
  const f = await configured(t); let aborted = false;
  const policy = { ...f.policy, evaluate: (_request, signal) => new Promise(() => {
    signal.addEventListener('abort', () => { aborted = true; });
  }) };
  const result = await openLocalEvidenceTool({ ...f.options, additionalPolicy: policy }).collect(f.request);
  assert.equal(result.result.status, 'POLICY_REFUSED'); assert.equal(aborted, true);
  assert.equal(JSON.parse(readFileSync(f.journal, 'utf8')).result.decision, 'ERROR');
  assert.deepEqual(readdirSync(f.options.outputDirectory), []);
});
test('a caller cannot mutate the selected policy after opening the tool', async t => {
  const f = await configured(t), mutable = { ...f.policy };
  const tool = openLocalEvidenceTool({ ...f.options, additionalPolicy: mutable });
  mutable.identity = 'replacement'; mutable.evaluate = () => { throw Error('mutated'); };
  assert.equal((await tool.collect(f.request)).packet.status, 'PACKET_VERIFIED');
  assert.equal(JSON.parse(readFileSync(f.journal, 'utf8')).result.identity, f.policy.identity);
});
