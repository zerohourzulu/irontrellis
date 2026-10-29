import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, mkdirSync, copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import * as remote from '@ramex-labs/irontrellis-remote';
import * as langchain from '@ramex-labs/irontrellis-remote/langchain';
import * as local from '@ramex-labs/irontrellis-remote/local';
import * as runtime from '@ramex-labs/irontrellis-remote/runtime';
import * as attempts from '@ramex-labs/irontrellis-remote/attempts';
import * as coreLocal from '@ramex-labs/irontrellis/local';
import * as coreRuntime from '@ramex-labs/irontrellis/runtime';
import * as coreAttempts from '@ramex-labs/irontrellis/attempts';
import {openConfiguredEventStore, createHistoryTransfer, openCheckpointStorage} from '@ramex-labs/irontrellis/adapter';

test('all five SDK entrypoints resolve and privileged exports are Core identities', () => {
  for (const name of ['createToolRegistry','createCooperativeClient','createCooperativeDestination','createCooperativeExecutor','createCooperativeRecovery','inspectDestinationLock','recoverDestinationLock','createProtectedEvidenceDestination','readProtectedEvidence']) assert.equal(typeof remote[name], 'function', name);
  assert.equal('migrateDestinationHistory' in remote, false, 'legacy migration is explicitly unsupported');
  assert.equal(typeof langchain.createIronTrellisTool, 'function');
  assert.equal(typeof langchain.createIronTrellisTools, 'function');
  for (const [actual, expected] of [[local,coreLocal],[runtime,coreRuntime],[attempts,coreAttempts]]) {
    assert.deepEqual(Object.keys(actual),Object.keys(expected));
    for (const key of Object.keys(expected)) assert.equal(actual[key], expected[key], key);
  }
});

test('installed local SDK writes a native format-2 history that transfers and fully replays', async t => {
  const directory=mkdtempSync(join(tmpdir(),'irontrellis-sdk-'));
  t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const historyFile=join(directory,'history.jsonl');
  let tick=100;
  const config={historyFile,domain:local.createLocalDomain(),owner:'operations',controller:'operator',now:()=>++tick,witness:false};
  const owner=await local.createLocalOwner(config);
  await owner.createAgent({id:'sdk-agent'});
  await owner.grant({id:'sdk-grant',to:'sdk-agent',actions:['read'],resources:['document'],expiresAt:1000});
  const store=openConfiguredEventStore({...config,historyProfile:'irontrellis-event/2',trust:'FULL_REPLAY'});
  t.after(()=>store.close());
  assert.equal(store.format,'irontrellis-event/2');
  assert.ok(store.state().agents.has('sdk-agent'));
  const checkpointDirectory=join(directory,'receiver');mkdirSync(checkpointDirectory,{mode:0o700});
  const receiver=openCheckpointStorage(checkpointDirectory);
  const transfer=JSON.parse(JSON.stringify(createHistoryTransfer(store)));
  receiver.begin(transfer.manifest,transfer.transferId,null);
  transfer.chunks.forEach((chunk,index)=>receiver.chunk(transfer.transferId,index,chunk));
  const verified=receiver.ready(transfer.transferId);
  assert.deepEqual(verified.head,store.head());
  assert.equal(verified.historyId,store.state().eventHistoryHashes[0]);
  assert.equal(verified.headAuthentication,'HEAD_ATTESTATION');
  if(process.env.IRONTRELLIS_TEST_HISTORY_DIR){
    const output=resolve(process.env.IRONTRELLIS_TEST_HISTORY_DIR);mkdirSync(output,{recursive:true});
    copyFileSync(historyFile,join(output,'sdk-format2.jsonl'));
  }
});

test('LangChain schema exposes arguments only and rejects authority-selection injection', () => {
  const registry=remote.createToolRegistry({serviceId:'sdk-service',account:'synthetic',tools:remote.REFERENCE_TOOLS});
  let calls=0;
  const executor={run(){calls++;throw new Error('schema-only test must not dispatch');},close(){},checkpoint(){throw new Error('unused');}};
  const tool=langchain.createIronTrellisTool({registry,executor,tool:registry.tools[0].id,operationId:'sdk-op',businessKey:'sdk-case'});
  assert.equal(tool.schema.safeParse({title:'read document'}).success,true);
  for (const key of ['actor','historyFile','session','operationId','businessKey','grant','signHash']) {
    assert.equal(tool.schema.safeParse({title:'read document',[key]:'attacker-selected'}).success,false,key);
  }
  assert.equal(calls,0);
});
