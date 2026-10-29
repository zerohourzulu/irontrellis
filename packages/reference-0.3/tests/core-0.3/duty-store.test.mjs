import {test} from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import * as core from '../../packages/core-0.2/src/core/index.ts';
import {stateOf} from '../../packages/core-0.3/src/local-store.ts';
import {produceContinuationAdministration,exportContinuationEvents} from '../../packages/core-0.3/src/history.ts';
import {DirectoryHistoryStore,recoverLock,lockRecord} from '../../packages/core-0.3/src/history-store/index.ts';
import {dutyFixture} from './fixtures/duty-fixture.mjs';
import {signHash} from './fixtures/history-fixture.mjs';

async function candidate(f){
  const history=f.store.snapshot().history;
  return (await produceContinuationAdministration(history,{expectedDomain:f.options.domain,expectedHistoryHead:history.head,runtimeSessionId:'session',transition:{
    id:'duty-policy:activate',type:'ATTEMPT_DUTY_POLICY_ACTIVATED',timestamp:100,
    data:{actorId:'worker',descriptor:f.selection.descriptor,descriptorHash:f.selection.descriptorHash,activationAuthorityId:'activation'},
  }},{signHash})).result.event;
}
async function child(path,payload,cut='-'){
  const p=spawn(process.execPath,['--experimental-strip-types',new URL('./fixtures/history-store-worker.mjs',import.meta.url).pathname,'append',path,payload,cut],{stdio:['ignore','pipe','pipe','ipc']});
  let stdout='',stderr='',message;p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);p.on('message',m=>{if(m.status!=='READY')message=m});
  const done=new Promise((resolve,reject)=>{p.once('error',reject);p.once('exit',(code,signal)=>resolve({code,signal,stdout,stderr,message}))});
  await new Promise((resolve,reject)=>{p.once('message',resolve);p.once('error',reject);p.once('exit',()=>reject(Error('Worker ended before READY: '+stderr)))});
  return {go:()=>p.send('GO'),done};
}
test('process death on either side of manifest replacement keeps activation and reserves atomic',async t=>{
  for(const cut of ['before-manifest-replace','manifest-replaced'])await t.test(cut,async t=>{
    const f=await dutyFixture(t);f.grant();const before=f.store.snapshot(),event=await candidate(f),payload=join(f.dir,'event.json');
    writeFileSync(payload,JSON.stringify({event,revision:before.revision}));
    const worker=await child(f.store.path,payload,cut);worker.go();const result=await worker.done;
    assert.equal(result.signal,'SIGKILL',result.stderr);assert.ok(result.stdout.includes('CUT '+cut));
    const reopened=new DirectoryHistoryStore(f.store.path),after=reopened.snapshot(),committed=cut==='manifest-replaced';
    assert.equal(after.history.eventCount,before.history.eventCount+(committed?1:0));
    assert.equal(after.capacity.dutyReserved??0,committed?6:0);
    assert.equal(stateOf(exportContinuationEvents(after.history)).attemptDutyPolicies.size,committed?1:0);
    recoverLock(reopened.path,lockRecord(join(reopened.path,'.writer-lock')).sha256);
    const repeat=await f.duties.activate(f.input);assert.equal(repeat.alreadyRecorded,committed);assert.equal(f.calls,committed?0:1);
    assert.equal(f.store.snapshot().capacity.dutyReserved,6);
  });
});
test('two processes racing the same signed activation commit exactly one event and one reserve',async t=>{
  const f=await dutyFixture(t);f.grant();const before=f.store.snapshot(),event=await candidate(f),payload=join(f.dir,'race.json');
  writeFileSync(payload,JSON.stringify({event,revision:before.revision}));
  const a=await child(f.store.path,payload),b=await child(f.store.path,payload);a.go();b.go();
  const results=await Promise.all([a.done,b.done]);assert.equal(results.filter(r=>r.code===0).length,1,JSON.stringify(results));
  assert.ok(results.some(r=>['STORE_BUSY','HISTORY_CONFLICT'].includes(r.message?.code)),JSON.stringify(results));
  const after=f.store.snapshot();assert.equal(after.history.eventCount,before.history.eventCount+1);assert.equal(after.capacity.dutyReserved,6);
  assert.equal(core.canonicalEncode(exportContinuationEvents(after.history).at(-1)),core.canonicalEncode(event));
});
