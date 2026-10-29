import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createIronTrellisTool,createIronTrellisTools} from '../langchain.mjs';
import {createProtectedEvidenceDestination,readProtectedEvidence,createToolRegistry} from '../index.mjs';
import {protectedEvidenceProfile} from '../protected-evidence.mjs';
import {setup} from './helpers.mjs';

test('LangChain tool invokes actual format-2 executor with fixed host-assigned identity',async t=>{
  const s=await setup(t),tool=createIronTrellisTool({registry:s.registry,executor:s.executor,tool:'ticket.create',operationId:s.request.operationId,businessKey:s.request.businessKey});
  const result=JSON.parse(await tool.invoke(s.request.arguments));assert.equal(result.lastReportedServiceState,'APPLIED');assert.equal(s.destination.inspect().effects.length,1);
  await assert.rejects(tool.invoke({...s.request.arguments,operationId:'forged'}));
  assert.throws(()=>createIronTrellisTools({registry:s.registry,executor:s.executor,operations:[{tool:'ticket.create',operationId:'1',businessKey:'1'},{tool:'ticket.create',operationId:'2',businessKey:'2'}]}));
});

test('LangChain amount schema converts exact decimal text, rejects ambiguous quantities',async()=>{
  const registry=createToolRegistry({serviceId:'amount:synthetic',account:'test',tools:[{id:'pay',action:'pay',resource:'vendor',fields:{amount:'amount',counterparty:'identifier'},projection:{amount:'amount',counterparty:'counterparty',unit:'cent'}}]});
  let input;const executor={async run(value){input=value;return {execution:{status:'TEST_CAPTURE'},serviceReport:null,externalOutcome:'NOT_PROVEN',revocationBoundary:'DESTINATION_ACKNOWLEDGED_CHECKPOINT'}}};
  const tool=createIronTrellisTool({registry,executor,tool:'pay',operationId:'fixed',businessKey:'fixed'});
  await tool.invoke({amount:'12345678901234567890',counterparty:'vendor:1'});assert.equal(input.arguments.amount,12345678901234567890n);
  for(const amount of ['-0','01','1.2','1e3',((1n<<256n)).toString()])await assert.rejects(tool.invoke({amount,counterparty:'vendor:1'}));
});

test('protected evidence closes and restores actual reviewer access under Core authorization',async t=>{
  const parent=realpathSync(mkdtempSync(join(tmpdir(),'it-evidence-')));t.after(()=>rmSync(parent,{recursive:true,force:true}));
  const bundleDirectory=join(parent,'bundle');mkdirSync(bundleDirectory,{mode:0o700});
  const body=Buffer.from('Synthetic case evidence only.\n'),token='7'.repeat(64),file={name:'case.txt',bytes:body.length,sha256:createHash('sha256').update(body).digest('hex')};
  writeFileSync(join(bundleDirectory,file.name),body,{mode:0o400});
  const evidence={bundleDirectory,resource:'evidence:synthetic',files:[file],reviewerTokenHash:createHash('sha256').update(token).digest('hex'),socketPath:join(parent,'reader.sock')};
  const profile=protectedEvidenceProfile(evidence),s=await setup(t,{tools:profile.registry.tools,serviceId:profile.registry.serviceId,registryAccount:profile.registry.account,destinationFactory:createProtectedEvidenceDestination,destinationConfig:{evidence,initialize:true}});
  assert.equal((await readProtectedEvidence({socketPath:evidence.socketPath,token})).status,200);
  assert.equal((await readProtectedEvidence({socketPath:evidence.socketPath,token:'8'.repeat(64)})).status,401);
  const restrict={operationId:'evidence:close',businessKey:'close:1',tool:'evidence.restrict',arguments:{reason:'Synthetic test containment'}};
  assert.equal((await s.executor.run(restrict)).serviceReport.result.state,'APPLIED');
  assert.equal((await readProtectedEvidence({socketPath:evidence.socketPath,token})).status,403);
  const restore={operationId:'evidence:restore',businessKey:'restore:1',tool:'evidence.restore',arguments:{reason:'Synthetic test review'}};
  assert.equal((await s.executor.run(restore)).serviceReport.result.state,'APPLIED');
  const observed=await readProtectedEvidence({socketPath:evidence.socketPath,token});assert.equal(observed.status,200);assert.equal(observed.body.files[0].base64,body.toString('base64'));
});
