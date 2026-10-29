import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync,copyFileSync} from 'node:fs';
import {join} from 'node:path';
import * as core from '@ramex-labs/irontrellis/adapter';
import {createLocalDomain,createLocalAttemptOwner} from '@ramex-labs/irontrellis/local';
import * as remote from '../index.mjs';
import {encodeTransport,decodeTransport,signRequest,canonicalDigest,verifyResponse} from '../wire.mjs';
import {setup,prepared,code} from './helpers.mjs';
const state=async promise=>(await promise).result.state;

test('real format-2 admission, authenticated transfer and durable effect are idempotent',async t=>{
  const s=await setup(t),first=await s.executor.run(s.request);
  assert.equal(first.execution.invocation.status,'SUBMITTED');assert.equal(first.serviceReport.result.state,'APPLIED');
  const again=await s.executor.run(s.request);assert.equal(again.execution.result.status,'RETRY');
  assert.deepEqual(again.serviceReport.result,first.serviceReport.result);assert.equal(s.destination.inspect().effects.length,1);
  assert.equal(first.externalOutcome,'NOT_PROVEN');assert.equal(s.store.format,'irontrellis-event/2');
});

test('same-time revocation checkpoint fences prepared work and cancellation survives restart',async t=>{
  const s=await setup(t),key=await prepared(s);await s.owner.revoke('tools');
  assert.equal(await state(s.checkpoint()),'CHECKPOINTED');
  assert.equal((await s.client.commit(key)).result.code,'CHECKPOINT_CHANGED');
  assert.equal(await state(s.client.cancel(key)),'CANCELLED');await s.restart();
  assert.equal(await state(s.client.commit(key)),'CANCELLED');assert.equal(s.destination.inspect().effects.length,0);
});

test('local revocation alone is not a destination acknowledged fence',async t=>{
  const s=await setup(t),key=await prepared(s);await s.owner.revoke('tools');
  assert.equal(await state(s.client.commit(key)),'APPLIED');assert.equal(s.destination.inspect().effects.length,1);
});

for(const expiry of [500,1000])test(`trusted expiry at ${expiry} refuses commit`,async t=>{
  const s=await setup(t),key=await prepared(s);s.setTime(expiry);
  assert.equal((await s.client.commit(key)).result.code,'AUTHORIZATION_REFUSED');assert.equal(s.destination.inspect().effects.length,0);
});

test('checkpoint clock cannot regress; cancellation survives a bad clock',async t=>{
  const s=await setup(t),key=await prepared(s);s.setTime(99);
  assert.equal((await s.client.commit(key)).result.code,'CLOCK_INVALID');
  assert.equal(await state(s.client.cancel(key)),'CANCELLED');assert.equal(s.destination.inspect().lastTime,100);
});

test('unadmitted or substituted arguments cannot execute under a coordinator signature',async t=>{
  const s=await setup(t);await s.checkpoint();assert.equal((await s.client.prepare(s.wire())).result.code,'AUTHORIZATION_REFUSED');
  const key=await prepared(s);assert.equal((await s.client.prepare({...s.wire(),arguments:{title:'Substituted'}})).result.code,'AUTHORIZATION_REFUSED');
  assert.equal(await state(s.client.commit(key)),'APPLIED');assert.equal(s.destination.inspect().effects.length,1);
});

test('a fresh intent cannot reuse an already applied business identity',async t=>{
  const s=await setup(t);await s.executor.run(s.request);
  const request={...s.request,operationId:'job:duplicate'},key=await s.admitOnly(request);await s.checkpoint();
  assert.equal((await s.client.prepare(s.wire(request))).result.code,'BUSINESS_KEY_CONFLICT');
  assert.equal(await state(s.client.commit(key)),'UNKNOWN');assert.equal(s.destination.inspect().effects.length,1);
});

test('commit/cancel race orders through one durable transaction; terminal result retained',async t=>{
  const s=await setup(t),key=await prepared(s);await Promise.all([s.client.commit(key),s.client.cancel(key)]);
  const first=(await s.client.status(key)).result;assert.ok(['APPLIED','CANCELLED'].includes(first.state));
  await s.restart();assert.deepEqual((await s.client.commit(key)).result,first);
  assert.equal(s.destination.inspect().effects.length,first.state==='APPLIED'?1:0);
});

test('lost commit response remains unknown locally; recovery reads without redelivery',async t=>{
  const s=await setup(t);let submissions=0;
  const uncertain=remote.createCooperativeExecutor({local:s.local,registry:s.registry,role:'operator',tenure:'shift:1',client:{...s.client,async commit(key){submissions++;await s.client.commit(key);throw Error('reply lost')}}});
  t.after(()=>uncertain.close());const answer=await uncertain.run(s.request);
  assert.equal(answer.execution.invocation.status,'OUTCOME_UNKNOWN');assert.equal(s.destination.inspect().effects.length,1);
  const recovery=remote.createCooperativeRecovery({local:s.local,client:s.client,registry:s.registry});t.after(()=>recovery.close());
  const recovered=await recovery.lookup(s.request);assert.equal(recovered.serviceReport.result.state,'APPLIED');assert.equal(recovered.dispatchPerformed,false);
  assert.equal(recovered.retryPolicy,'NO_AUTOMATIC_REDELIVERY');assert.ok(recovered.observationAcknowledgment);assert.equal(submissions,1);
  assert.equal((await recovery.cancel(s.request)).serviceReport.result.state,'TOO_LATE');assert.equal(s.destination.inspect().effects.length,1);
});

test('wrong pinned coordinator or destination keys never authenticate an operation',async t=>{
  const s=await setup(t),wrong=generateKeyPairSync('ed25519'),unknown='0x'+'f'.repeat(64),before=s.destination.inspect().sequence;
  const wrongCoordinator=remote.createCooperativeClient({url:s.destination.url,serviceId:s.serviceId,coordinatorPrivateKey:wrong.privateKey,servicePublicKey:s.provider.publicKey});
  await assert.rejects(wrongCoordinator.status(unknown));assert.equal(s.destination.inspect().sequence,before);
  const wrongService=remote.createCooperativeClient({url:s.destination.url,serviceId:s.serviceId,coordinatorPrivateKey:s.coordinator.privateKey,servicePublicKey:wrong.publicKey});
  await assert.rejects(wrongService.status(unknown));assert.equal(s.destination.inspect().effects.length,0);
});

test('format-2 transfers refuse incomplete/chunk equivocation and allow exact duplicate delivery',async t=>{
  const s=await setup(t),transfer=core.createHistoryTransfer(s.store),id=transfer.transferId;
  assert.equal(await state(s.client.checkpointBegin(transfer.manifest,id)),'CHECKPOINT_STAGED');
  assert.equal((await s.client.checkpointCommit(id)).result.code,'TRANSFER_INCOMPLETE');
  const bad=[...transfer.chunks[0]];bad[0]=(bad[0][0]==='A'?'B':'A')+bad[0].slice(1);
  assert.equal((await s.client.checkpointChunk(id,0,bad)).result.code,'TRANSFER_CHUNK_INVALID');
  for(let i=0;i<transfer.chunks.length;i++){assert.equal(await state(s.client.checkpointChunk(id,i,transfer.chunks[i])),'CHECKPOINT_CHUNKED');assert.equal(await state(s.client.checkpointChunk(id,i,transfer.chunks[i])),'CHECKPOINT_CHUNKED');}
  assert.equal(await state(s.client.checkpointCommit(id)),'CHECKPOINTED');const seq=s.destination.inspect().sequence;
  assert.equal(await state(s.client.checkpointCommit(id)),'CHECKPOINTED');assert.equal(s.destination.inspect().sequence,seq);
});

test('alternate same-domain history identity and prior-head rollback are refused',async t=>{
  const s=await setup(t),prior=core.createHistoryTransfer(s.store);await prepared(s);
  const rolled=await s.client.checkpointBegin(prior.manifest,prior.transferId);assert.equal(rolled.result.state,'CHECKPOINT_STAGED');
  for(let i=0;i<prior.chunks.length;i++)await s.client.checkpointChunk(prior.transferId,i,prior.chunks[i]);
  assert.equal((await s.client.checkpointCommit(prior.transferId)).result.code,'CHECKPOINT_CONFLICT');
  await s.client.abortCheckpointTransfer(prior.transferId);
  const owner=await createLocalAttemptOwner({...s.local,historyFile:join(s.dir,'foreign.jsonl')});
  const foreign=core.openConfiguredEventStore({historyFile:join(s.dir,'foreign.jsonl'),witness:false});t.after(()=>foreign.close());
  assert.deepEqual(owner.exportHistory()[0].data.domain,s.local.domain);
  assert.equal((await s.client.checkpointHistory(foreign)).result.code,'CHECKPOINT_CONFLICT');
});

test('authenticated history fork with same genesis is rejected by record-chain prefix',async t=>{
  const s=await setup(t);await s.checkpoint();
  // Retain a complete independent branch, including its synthetic owner key and authenticated pin.
  const branch=join(s.dir,'branch.jsonl');
  for(const suffix of ['', '.head','.owner-key.json']){try{copyFileSync(s.local.historyFile+suffix,branch+suffix);}catch(e){if(e.code!=='ENOENT')throw e;}}
  const {openLocalOwner}=await import('@ramex-labs/irontrellis/local');
  const alternate=openLocalOwner({...s.local,historyFile:branch});
  await s.owner.createAgent({id:'left'});await s.checkpoint();await alternate.createAgent({id:'right'});
  const fork=core.openConfiguredEventStore({...s.local,historyFile:branch});t.after(()=>fork.close());
  assert.equal((await s.client.checkpointHistory(fork)).result.code,'CHECKPOINT_CONFLICT');
});

test('fully valid chain without head authentication is refused',async t=>{
  const s=await setup(t,{headAuthenticationPolicy:'REQUIRE_OWNER'}),unattested=join(s.dir,'replica.jsonl');
  core.createHistoryStore(unattested,s.owner.exportHistory(),{witness:false}).close();
  const replica=core.openConfiguredEventStore({historyFile:unattested,allowUnpinned:true,witness:false});t.after(()=>replica.close());
  assert.equal((await s.client.checkpointHistory(replica)).result.code,'CHECKPOINT_CONFLICT');
});

test('self-consistent transfer bytes with forged record hash cannot become a checkpoint',async t=>{
  const s=await setup(t),transfer=core.createHistoryTransfer(s.store),rows=Buffer.from(transfer.chunks[0].join(''),'base64').toString().trimEnd().split('\n').map(JSON.parse);
  rows.at(-1).recordHash='0x'+'3'.repeat(64);const bytes=Buffer.from(rows.map(x=>core.canonicalEncode(x)+'\n').join(''));
  const digest='0x'+createHash('sha256').update(bytes).digest('hex');
  const manifest={...transfer.manifest,segments:[{...transfer.manifest.segments[0],bytes:bytes.length,digest}]};
  const id=core.hashCanonical(manifest,'sha256');await s.client.checkpointBegin(manifest,id);await s.client.checkpointChunk(id,0,bytes.toString('base64').match(/.{1,4096}/g));
  assert.equal((await s.client.checkpointCommit(id)).result.code,'TRANSFER_INVALID');assert.equal(s.destination.inspect().checkpoint,null);
});

test('legacy storage/profile/API inputs are rejected without dual acceptance',async t=>{
  const s=await setup(t);assert.equal(s.client.checkpoint,undefined);assert.equal(remote.migrateDestinationHistory,undefined);
  assert.throws(()=>core.openConfiguredEventStore({...s.local,historyBinding:'old'}),code('PROFILE_MISMATCH'));
  await assert.rejects(remote.createCooperativeDestination({...s.destinationOptions,historyProfile:'continuity-segmented-local/1'}),code('UNSUPPORTED_HISTORY_PROFILE'));
  await assert.rejects(remote.createCooperativeDestination({...s.destinationOptions,historyId:undefined}),code('INVALID_HASH'));
  assert.throws(()=>signRequest({version:'continuity-cooperative-request/1',serviceId:s.serviceId,nonce:'0'.repeat(64),operation:'checkpoint',payload:{events:s.owner.exportHistory()}},s.coordinator.privateKey),code('UNSUPPORTED_OPERATION'));
});

test('transport preserves scalar types and rejects duplicate keys, bad tags and forged signatures',async t=>{
  const s=await setup(t),value={zero:'000',integer:0,amount:0n,empty:'',nil:null};assert.deepEqual({...decodeTransport(encodeTransport(value))},value);
  assert.throws(()=>decodeTransport(Buffer.from('["object",[["x",["number",1]],["x",["number",2]]]]')));
  const body={version:'continuity-cooperative-request/1',serviceId:s.serviceId,nonce:'a'.repeat(64),operation:'status',payload:{key:'0x'+'e'.repeat(64)}};
  const signed={...signRequest(body,s.coordinator.privateKey),signature:'0'.repeat(128)};
  const response=await fetch(s.destination.url+'/cooperative',{method:'POST',body:encodeTransport(signed)});assert.equal(response.status,400);
});

test('close releases local history resources and refuses later publication/recovery',async t=>{
  const s=await setup(t);s.executor.close();await assert.rejects(async()=>s.executor.checkpoint(),code('READ_UNAVAILABLE'));
  const recovery=remote.createCooperativeRecovery({local:s.local,client:s.client,registry:s.registry});recovery.close();await assert.rejects(recovery.lookup(s.request),code('READ_UNAVAILABLE'));
});

test('strict default refuses an unattested runtime tail; fresh owner checkpoint permits it',async t=>{
  const s=await setup(t),directory=join(s.dir,'strict');mkdirSync(directory);
  const options={...s.destinationOptions,directory};delete options.headAuthenticationPolicy;
  const destination=await remote.createCooperativeDestination(options);t.after(()=>destination.close());
  assert.equal(destination.inspect().headAuthenticationPolicy,'REQUIRE_OWNER');
  const client=remote.createCooperativeClient({url:destination.url,serviceId:s.serviceId,coordinatorPrivateKey:s.coordinator.privateKey,servicePublicKey:s.provider.publicKey});
  await s.admitOnly();assert.equal((await client.checkpointHistory(s.store)).result.code,'CHECKPOINT_CONFLICT');
  await client.abortCheckpointTransfer(core.createHistoryTransfer(s.store).transferId);
  await s.owner.checkpoint({checkpointId:'strict:owner'});
  assert.equal((await client.checkpointHistory(s.store)).result.state,'CHECKPOINTED');await destination.close();
});

test('authentication policy is validated and pinned against restart downgrade',async t=>{
  const s=await setup(t,{headAuthenticationPolicy:'REQUIRE_OWNER'});
  for(const headAuthenticationPolicy of [null,'anything',false,0])await assert.rejects(remote.createCooperativeDestination({...s.destinationOptions,headAuthenticationPolicy}),code('INVALID_AUTHENTICATION_POLICY'));
  await s.destination.close();
  await assert.rejects(remote.createCooperativeDestination({...s.destinationOptions,headAuthenticationPolicy:'COORDINATOR_AUTHENTICATED'}),code('DESTINATION_IDENTITY_MISMATCH'));
  await s.restart();assert.equal(s.destination.inspect().headAuthenticationPolicy,'REQUIRE_OWNER');
});

// Under the destination's default REQUIRE_OWNER, an executor whose handle has no
// owner key writes an unattested admission, the destination refuses its checkpoint and nothing is dispatched. The run keeps
// its recorded outcome (OUTCOME_UNKNOWN) and now carries a plain diagnostic, which names REQUIRE_OWNER as one possible cause
// only, since a clock or history conflict gives the same refusal; the working configurations carry none.
test('REQUIRE_OWNER with a session-only executor: nothing dispatched, the outcome unchanged, and a plain diagnostic',async t=>{
  const s=await setup(t,{headAuthenticationPolicy:'REQUIRE_OWNER'});
  const run=await s.executor.run(s.request);
  assert.equal(run.execution.invocation.status,'OUTCOME_UNKNOWN');assert.equal(run.serviceReport,null);assert.equal(s.destination.inspect().effects.length,0);
  assert.match(run.diagnostic,/refused the checkpoint before anything was dispatched.*One possible cause.*\(REQUIRE_OWNER\).*owner signer.*COORDINATOR_AUTHENTICATED.*clock or history conflict/);
  assert.equal((await s.checkpoint()).result.code,'CHECKPOINT_CONFLICT','the head stays unattested');
});
test('the working configurations carry no diagnostic: COORDINATOR_AUTHENTICATED, or REQUIRE_OWNER with the owner signer',async t=>{
  const a=await setup(t);
  const first=await a.executor.run(a.request);
  assert.equal(first.execution.invocation.status,'SUBMITTED');assert.equal(first.diagnostic,undefined);
  const b=await setup(t,{headAuthenticationPolicy:'REQUIRE_OWNER'});
  const {loadOwnerKeyFile}=await import('@ramex-labs/irontrellis');
  const executor=remote.createCooperativeExecutor({local:{...b.local,signer:loadOwnerKeyFile(b.local.historyFile+'.owner-key.json')},client:b.client,registry:b.registry,role:'operator',tenure:'shift:1'});
  t.after(()=>executor.close());
  const run=await executor.run(b.request);
  assert.equal(run.execution.invocation.status,'SUBMITTED');assert.equal(run.serviceReport.result.state,'APPLIED');assert.equal(run.diagnostic,undefined);
});
test('a clock conflict under COORDINATOR_AUTHENTICATED : the same refusal, and the diagnostic does not blame REQUIRE_OWNER',async t=>{
  const s=await setup(t,{headAuthenticationPolicy:'COORDINATOR_AUTHENTICATED',destinationConfig:{now:()=>99}}); // the destination's clock behind the head (100)
  assert.equal(s.destination.inspect().headAuthenticationPolicy,'COORDINATOR_AUTHENTICATED');
  const run=await s.executor.run(s.request);
  assert.equal(run.execution.invocation.status,'OUTCOME_UNKNOWN');assert.equal(s.destination.inspect().effects.length,0);
  assert.equal((await s.checkpoint()).result.code,'CHECKPOINT_CONFLICT');
  assert.doesNotMatch(run.diagnostic,/The destination requires an owner-attested head/);
  assert.match(run.diagnostic,/One possible cause.*A clock or history conflict also refuses it/);
});
