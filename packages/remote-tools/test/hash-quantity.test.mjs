import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {generateKeyPair} from '@ramex-labs/irontrellis';
import * as core from '@ramex-labs/irontrellis/adapter';
import {createToolRegistry,createCooperativeExecutor,createCooperativeRecovery} from '../index.mjs';
import {setup,code} from './helpers.mjs';
const fixtures=JSON.parse(readFileSync(new URL('./hash-vectors.json',import.meta.url),'utf8'));
for(const v of fixtures.vectors)test(`frozen hash-domain canonical parity and explicit SHA256 migration: ${v.name}`,()=>{
  const args={...v.arguments};for(const field of v.amountFields)args[field]=BigInt(args[field]);
  const contract={version:'continuity-tool-contract/1',...v.config},registry=createToolRegistry(v.config);
  assert.equal(core.canonicalEncode(contract),v.contractCanonical);assert.equal(core.hashCanonical(contract,'keccak256'),v.oldContractId);
  assert.equal(registry.contractId,v.newContractId);assert.notEqual(registry.contractId,v.oldContractId);
  const terms=id=>({version:'continuity-tool-terms/1',serviceId:v.config.serviceId,account:v.config.account,tool:v.config.tools[0].id,arguments:args,businessKey:v.businessKey,contractId:id});
  assert.equal(core.canonicalEncode(terms(v.oldContractId)),v.oldTermsCanonical);assert.equal(core.hashCanonical(terms(v.oldContractId),'keccak256'),v.oldTermsDigest);
  assert.equal(core.canonicalEncode(terms(registry.contractId)),v.newTermsCanonical);assert.equal(core.hashCanonical(terms(registry.contractId),'keccak256'),v.samePayloadLegacyKeccak);
  const operation={intentId:'job:1',tool:v.config.tools[0].id,arguments:args,businessKey:v.businessKey,contractId:registry.contractId};
  assert.equal(registry.capture(operation).termsCommitment,v.newTermsDigest);assert.notEqual(v.newTermsDigest,v.samePayloadLegacyKeccak);
});

test('real amount and counterparty admission executes once and recovers a lost service response',async t=>{
  const tools=fixtures.vectors.find(v=>v.name==='amount-counterparty').config.tools,s=await setup(t,{tools});
  const key=generateKeyPair('ed25519','vendor:key');await s.owner.registerCounterparty({counterpartyId:'vendor:1',keys:[{keyId:'vendor:key',scheme:'ed25519',credential:key.credential}]});
  const request={operationId:'payment:1',businessKey:'invoice:1',tool:'pay',arguments:{amount:1200n,counterparty:'vendor:1'}};
  let commits=0;const executor=createCooperativeExecutor({local:s.local,registry:s.registry,role:'operator',tenure:'shift:1',client:{...s.client,async commit(id){commits++;await s.client.commit(id);throw Error('synthetic response lost')}}});t.after(()=>executor.close());
  const result=await executor.run(request);assert.equal(result.execution.invocation.status,'OUTCOME_UNKNOWN');
  const intent=s.store.state().intentDeclarations.get(request.operationId).data;assert.equal(intent.amount,1200n);assert.equal(intent.counterpartyId,'vendor:1');
  const effects=s.destination.inspect().effects;assert.equal(effects.length,1);assert.equal(effects[0].arguments.amount,1200n);assert.equal(effects[0].arguments.counterparty,'vendor:1');
  const recovery=createCooperativeRecovery({local:s.local,client:s.client,registry:s.registry});t.after(()=>recovery.close());
  const observed=await recovery.lookup(request);assert.equal(observed.serviceReport.result.state,'APPLIED');assert.ok(observed.observationAcknowledgment);assert.equal(observed.dispatchPerformed,false);
  await assert.rejects(recovery.lookup({...request,arguments:{...request.arguments,amount:1201n}}),code('OPERATION_CONFLICT'));
  await assert.rejects(recovery.lookup({...request,arguments:{...request.arguments,counterparty:'vendor:2'}}),code('OPERATION_CONFLICT'));
  assert.equal(commits,1);assert.equal(s.destination.inspect().effects.length,1);
});
