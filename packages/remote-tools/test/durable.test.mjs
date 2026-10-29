import test from 'node:test';
import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {once} from 'node:events';
import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createCooperativeClient,inspectDestinationLock,recoverDestinationLock,createCooperativeDestination} from '../index.mjs';
import {setup,prepared,code} from './helpers.mjs';

async function worker(s,point){
  await s.destination.close();
  const child=fork(new URL('./crash-worker.mjs',import.meta.url),{stdio:['ignore','ignore','pipe','ipc']});
  const reply=once(child,'message');
  child.send({point,registry:{serviceId:s.serviceId,account:s.registry.account,tools:s.registry.tools},options:{directory:s.directory,domain:s.local.domain,historyId:s.historyId,headAuthenticationPolicy:s.destinationOptions.headAuthenticationPolicy,serviceId:s.serviceId,
    coordinatorPublicKey:s.coordinator.publicKey.export({type:'spki',format:'pem'}),servicePrivateKey:s.provider.privateKey.export({type:'pkcs8',format:'pem'})}});
  const [message]=await reply;if(message.error)throw Error(message.error);
  const client=createCooperativeClient({url:message.url,serviceId:s.serviceId,coordinatorPrivateKey:s.coordinator.privateKey,servicePublicKey:s.provider.publicKey,timeoutMs:10000});
  return {child,client};
}
for(const point of ['transfer-begin-synced','transfer-chunk-synced','before-checkpoint-reference','checkpoint-reference-synced'])test(`process crash at ${point} recovers explicitly and resumes exact transfer`,async t=>{
  const s=await setup(t),{child,client}=await worker(s,point);t.after(()=>{if(child.exitCode===null)child.kill('SIGKILL')});
  const exit=once(child,'exit');await assert.rejects(client.checkpointHistory(s.store));assert.equal((await exit)[0],75);
  const lock=inspectDestinationLock({directory:s.directory});
  assert.throws(()=>recoverDestinationLock({directory:s.directory,expectedLock:{...lock,instance:'00000000-0000-0000-0000-000000000000'}}),code('DESTINATION_LOCK_CHANGED'));
  const recovered=recoverDestinationLock({directory:s.directory,expectedLock:lock});assert.equal(recovered.recovered,true);
  await s.restart();assert.equal((await s.checkpoint()).result.state,'CHECKPOINTED');
  assert.equal(s.destination.inspect().checkpoint.head.hash,s.store.head().hash);assert.equal(s.destination.inspect().effects.length,0);
});

test('durable APPLIED effect survives process death and exact-lock recovery without replay',async t=>{
  const s=await setup(t),key=await prepared(s),{child,client}=await worker(s);t.after(()=>{if(child.exitCode===null)child.kill('SIGKILL')});
  assert.equal((await client.commit(key)).result.state,'APPLIED');
  const lock=inspectDestinationLock({directory:s.directory});
  assert.throws(()=>recoverDestinationLock({directory:s.directory,expectedLock:lock}),code('DESTINATION_LOCK_OWNER_ALIVE'));
  const exit=once(child,'exit');child.kill('SIGKILL');await exit;
  recoverDestinationLock({directory:s.directory,expectedLock:lock});await s.restart();
  assert.equal((await s.client.commit(key)).result.state,'APPLIED');assert.equal(s.destination.inspect().effects.length,1);
});

test('lifetime lock excludes a second destination and refused recovery leaves original bytes',async t=>{
  const s=await setup(t),lock=inspectDestinationLock({directory:s.directory}),before=readFileSync(join(s.directory,'destination.lock'));
  await assert.rejects(createCooperativeDestination(s.destinationOptions),code('DESTINATION_LOCKED'));
  assert.throws(()=>recoverDestinationLock({directory:s.directory,expectedLock:lock}),code('DESTINATION_LOCK_OWNER_ALIVE'));
  assert.deepEqual(readFileSync(join(s.directory,'destination.lock')),before);
});

test('snapshot checksum tampering refuses restart and never initializes empty state',async t=>{
  const s=await setup(t);await s.executor.run(s.request);await s.destination.close();
  const path=join(s.directory,'snapshot.bin'),original=readFileSync(path),changed=Buffer.from(original);changed[changed.length-5]^=1;writeFileSync(path,changed);
  await assert.rejects(createCooperativeDestination(s.destinationOptions));
  writeFileSync(path,original);await s.restart();assert.equal(s.destination.inspect().effects.length,1);
});
