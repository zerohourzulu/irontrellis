import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { OpenFgaClient } from '@openfga/sdk';
import { setup } from '../fixture.mjs';
import { openFgaPolicy, fgaObject } from '../openfga.mjs';
import { policyJournal } from '../journal.mjs';
import { openLocalEvidenceTool } from "@ramex-labs/irontrellis/evidence";
const apiUrl = process.env.IRONTRELLIS_TEST_FGA_URL;
if (!apiUrl) throw Error('Start the disposable server and set IRONTRELLIS_TEST_FGA_URL; these tests never substitute a mock.');
const model = JSON.parse(readFileSync(new URL('../model.json', import.meta.url)));
const tuple = { user: fgaObject('agent', 'bea'), relation: 'collector', object: fgaObject('resource', 'incident:42') };
async function configured(t) {
  const f = await setup(t), client = new OpenFgaClient({ apiUrl, retryParams: { maxRetry: 0 }, baseOptions: { timeout: 4000, proxy: false } });
  const { id: storeId } = await client.createStore({ name: 'irontrellis-disposable-test' });
  client.storeId = storeId; t.after(() => client.deleteStore());
  const { authorization_model_id: modelId } = await client.writeAuthorizationModel(model);
  client.authorizationModelId = modelId; await client.write({ writes: [tuple] });
  const journal = join(f.options.outputDirectory, '..', 'openfga.jsonl');
  const config = { apiUrl, storeId, modelId, record: policyJournal(journal) };
  const policy = openFgaPolicy(config);
  return { ...f, client, journal, config, policy, tool: openLocalEvidenceTool({ ...f.options, additionalPolicy: policy }) };
}
test('actual OpenFGA permission, tuple revocation, and original-attempt reconciliation', async t => {
  const f = await configured(t);
  assert.equal((await f.tool.collect(f.request)).packet.status, 'PACKET_VERIFIED');
  await f.client.write({ deletes: [tuple] });
  const denied = await f.tool.collect({ ...f.request, operationId: 'after-revocation' });
  assert.equal(denied.result.status, 'POLICY_REFUSED'); assert.equal(denied.result.reason, 'DENY');
  assert.equal((await f.tool.collect(f.request)).result.status, 'RECONCILIATION_ONLY');
  assert.equal(readdirSync(f.options.outputDirectory).length, 1);
  const evidence = readFileSync(f.journal, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(evidence.map(e => e.result.decision), ['ALLOW', 'DENY']);
  assert(evidence[0].result.diagnostics.includes('HIGHER_CONSISTENCY'));
  assert.equal(f.owner.exportHistory().filter(e => e.type === 'TRANSACTION_INTENT_CONSUMED').length, 1);
});
test('a newly written model does not silently replace the pinned model', async t => {
  const f = await configured(t), changed = structuredClone(model);
  changed.type_definitions[1].relations.collector = { difference: { base: { this: {} }, subtract: { this: {} } } };
  const next = await f.client.writeAuthorizationModel(changed);
  assert.notEqual(next.authorization_model_id, f.config.modelId);
  assert.equal((await f.tool.collect(f.request)).packet.status, 'PACKET_VERIFIED');
});
test('a missing model and unreachable service refuse instead of falling back to Core alone', async t => {
  const f = await configured(t);
  for (const config of [{ ...f.config, modelId: '01AAAAAAAAAAAAAAAAAAAAAAAA' }, { ...f.config, apiUrl: 'http://127.0.0.1:1' }]) {
    const result = await openLocalEvidenceTool({ ...f.options, additionalPolicy: openFgaPolicy(config) })
      .collect({ ...f.request, operationId: config.modelId + ':' + new URL(config.apiUrl).port });
    assert.equal(result.result.status, 'POLICY_REFUSED'); assert.equal(result.result.reason, 'ERROR');
  }
  assert.deepEqual(readdirSync(f.options.outputDirectory), []);
});
test('an actual service response after Core retirement cannot authorize work', async t => {
  const f = await configured(t), original = f.policy;
  const additionalPolicy = { ...original, async evaluate(request, signal) {
    const result = await original.evaluate(request, signal);
    await f.owner.advanceEpoch({ agent: 'bea', from: 1, to: 2 }); return result;
  } };
  await assert.rejects(openLocalEvidenceTool({ ...f.options, additionalPolicy }).collect(f.request), e => e.code === 'HISTORY_CONFLICT');
  assert.deepEqual(readdirSync(f.options.outputDirectory), []);
});
test('a relationship permit cannot override a Core grant revocation', async t => {
  const f = await configured(t); await f.owner.revoke('collect');
  assert.equal((await f.tool.collect(f.request)).result.status, 'NOT_AUTHORIZED');
  assert.deepEqual(readdirSync(f.options.outputDirectory), []);
});
