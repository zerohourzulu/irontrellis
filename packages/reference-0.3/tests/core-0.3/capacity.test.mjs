import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,readFileSync,writeFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createRequire} from 'node:module';
import {createLocalDomain,createLocalOwner,openLocalOwner} from '../../packages/core-0.3/src/local-owner.ts';
import {openLocalSimulation,commitTerms} from '../../packages/core-0.3/src/simulation.ts';
import {ManagedLocalEventStore,capacityOf} from '../../packages/core-0.3/src/capacity.ts';
import {PortableFileEventStore} from '../../packages/core-0.2/src/indexer/portable-file-event-store.ts';
const {generatePrivateKey,privateKeyToAccount}=createRequire(new URL('../../packages/core/package.json',import.meta.url))('viem/accounts');
const code=c=>e=>e.code===c;
function setup(t){
 const directory=mkdtempSync(join(tmpdir(),'continuity-capacity-'));t.after(()=>rmSync(directory,{recursive:true,force:true}));
 const key=generatePrivateKey(),account=privateKeyToAccount(key);
 const config={historyFile:join(directory,'history.jsonl'),domain:createLocalDomain(),owner:'owner',controller:'host',now:()=>100};
 const owner=createLocalOwner(config);owner.createAgent({id:'worker'});owner.createAgent({id:'successor'});owner.createRole({id:'role'});owner.appoint({agent:'worker',role:'role',tenure:'tenure',number:1});
 owner.declareSuccession({id:'succession',from:'worker',to:'successor',role:'role'});
 owner.admitRuntime({session:'session',agent:'worker',epoch:1,key:'key',address:account.address,expiresAt:1000});
 owner.grant({id:'permission',to:'worker',actions:['read'],resources:['doc'],expiresAt:1000});
 const options={...config,session:'session',signHash:hash=>account.signMessage({message:{raw:hash}})};
 const op={id:'job',action:'read',resource:'doc',role:'role',tenure:'tenure',termsCommitment:commitTerms({case:'synthetic'})};
 const runtime=openLocalSimulation(options);
 // Raw writes construct fixtures only; not a supported managed application path.
 const fill=n=>{const raw=new PortableFileEventStore(config.historyFile),events=raw.readAll();raw.appendAll(Array.from({length:n},(_,i)=>({id:'padding:'+events.length+':'+i,type:'AGENT_CREATED',timestamp:100,data:{agentId:'padding:'+events.length+':'+i,principalId:'owner',controllerId:'host',initialControlEpoch:1}})));};
 const capacity=()=>capacityOf(owner.exportHistory());
 return {key,directory,config,owner,options,op,runtime,fill,capacity};
}
test('drain preserves admitted receipt and finite owner control across restart',async t=>{
 const f=setup(t);await f.runtime.run(f.op);f.fill(f.capacity().unreservedEvents);
 assert.equal(f.capacity().mode,'DRAINING');assert.equal(f.capacity().unreservedEvents,0);assert.equal(f.capacity().controlReserved,8);
 const before=readFileSync(f.config.historyFile);assert.throws(()=>f.owner.createAgent({id:'extra'}),code('CAPACITY_RESERVED'));assert.deepEqual(readFileSync(f.config.historyFile),before);
 await assert.rejects(f.runtime.run({...f.op,id:'extra-job'}),code('CAPACITY_RESERVED'));assert.deepEqual(readFileSync(f.config.historyFile),before);
 const reopened=openLocalSimulation(f.options);assert.equal((await reopened.run(f.op)).status,'RECONCILIATION_ONLY');assert.equal((await reopened.recordReceipt(f.op)).status,'RECEIPT_RESULT');
 const count=f.capacity().eventCount;assert.equal((await reopened.recordReceipt(f.op)).status,'ALREADY_RECORDED');assert.equal(f.capacity().eventCount,count);
 const owner=openLocalOwner(f.config);owner.revoke('permission');owner.advanceEpoch({agent:'worker',from:1,to:2});
 owner.succeed({id:'handover',rule:'succession',fromAgent:'worker',fromTenure:'tenure',toAgent:'successor',toTenure:'next',role:'role',number:2});
 assert.ok(f.capacity().compatible);assert.ok(f.capacity().controlReserved<8);assert.deepEqual(capacityOf(new PortableFileEventStore(f.config.historyFile).readAll()),f.capacity());
});
test('failed signing retains the original reservation; a different job cannot spend it',async t=>{
 const f=setup(t);f.fill(f.capacity().unreservedEvents-12);let calls=0;
 const runtime=openLocalSimulation({...f.options,signHash:async()=>{calls++;throw Error('unavailable');}});
 await assert.rejects(runtime.run(f.op),code('SIGNER_FAILED'));assert.equal(calls,1);assert.equal(f.capacity().declaredJobs,1);assert.equal(f.capacity().unreservedEvents,0);
 const before=readFileSync(f.config.historyFile);await assert.rejects(f.runtime.run({...f.op,id:'other'}),code('CAPACITY_RESERVED'));assert.deepEqual(readFileSync(f.config.historyFile),before);
 assert.equal((await f.runtime.run(f.op)).status,'SIMULATION_RESULT');
});
test('signer cannot let another managed writer spend recovery space',async t=>{
 const f=setup(t);f.fill(f.capacity().unreservedEvents-12);
 const runtime=openLocalSimulation({...f.options,signHash:async hash=>{assert.throws(()=>f.owner.createAgent({id:'intruder'}),code('CAPACITY_RESERVED'));return f.options.signHash(hash);}});
 assert.equal((await runtime.run(f.op)).invocation.status,'SUBMITTED');assert.ok(f.capacity().compatible);
});
test('control during signing denies stale admission while keeping the reservation',async t=>{
 const f=setup(t);f.fill(f.capacity().unreservedEvents-12);let first=true;
 const runtime=openLocalSimulation({...f.options,signHash:async hash=>{if(first){first=false;f.owner.revoke('permission');}return f.options.signHash(hash);}});
 await assert.rejects(runtime.run(f.op),code('HISTORY_CONFLICT'));assert.equal(f.owner.exportHistory().filter(e=>e.type==='TRANSACTION_INTENT_ADMITTED').length,0);assert.equal(f.capacity().declaredJobs,1);assert.equal(f.capacity().controlReserved,7);
});
test('over-budget history remains readable but cannot silently join managed writes',async t=>{
 const f=setup(t);f.fill(97-f.capacity().eventCount);assert.equal(f.capacity().mode,'INCOMPATIBLE');const before=readFileSync(f.config.historyFile);
 assert.throws(()=>f.owner.revoke('permission'),code('CAPACITY_INCOMPATIBLE'));await assert.rejects(f.runtime.run(f.op),code('CAPACITY_INCOMPATIBLE'));assert.deepEqual(readFileSync(f.config.historyFile),before);assert.equal(f.owner.exportHistory().length,97);
});
test('wide event and unsupported batch writes cannot consume a reserve',t=>{
 const f=setup(t),before=readFileSync(f.config.historyFile),resources=Array.from({length:32},(_,i)=>'resource:'+i);
 assert.throws(()=>f.owner.grant({id:'wide',to:'worker',actions:['read'],resources,expiresAt:1000}),code('CAPACITY_EVENT_LIMIT'));assert.deepEqual(readFileSync(f.config.historyFile),before);
 assert.throws(()=>new ManagedLocalEventStore(f.config.historyFile).appendAll([]),code('CAPACITY_BATCH_UNSUPPORTED'));
});

function child(f,mode,id){
 const file=join(f.directory,'worker-'+id.replaceAll(':','-')+'.json');writeFileSync(file,JSON.stringify({key:f.key,config:{...f.config,now:undefined},op:f.op}),{mode:0o600});
 return new Promise((resolve,reject)=>{const p=spawn(process.execPath,['--experimental-strip-types',fileURLToPath(new URL('./fixtures/capacity-worker.mjs',import.meta.url)),file,mode,id],{stdio:['ignore','pipe','pipe']});let output='',errors='';p.stdout.on('data',x=>output+=x);p.stderr.on('data',x=>errors+=x);p.on('error',reject);p.on('exit',(code,signal)=>resolve({code,signal,output,errors}));});
}
test('real process death after declaration preserves reservation and permits only the original job',async t=>{
 const f=setup(t);f.fill(f.capacity().unreservedEvents-12);
 const result=await child(f,'kill','job');assert.equal(result.signal,'SIGKILL');assert.equal(f.capacity().declaredJobs,1);assert.equal(f.capacity().unreservedEvents,0);
 await assert.rejects(f.runtime.run({...f.op,id:'replacement-id'}),code('CAPACITY_RESERVED'));
 assert.equal((await f.runtime.run(f.op)).invocation.status,'SUBMITTED');assert.equal(f.owner.exportHistory().filter(e=>e.type==='TRANSACTION_INTENT_ADMITTED').length,1);
});
test('two real process contenders cannot reserve the final job space twice',async t=>{
 const f=setup(t);f.fill(f.capacity().unreservedEvents-12);
 const results=await Promise.all([child(f,'run','job:a'),child(f,'run','job:b')]);
 for(const r of results){assert.equal(r.code,0,r.errors);assert.equal(r.signal,null);}
 assert.equal(f.capacity().declaredJobs,1);assert.equal(f.owner.exportHistory().filter(e=>e.type==='TRANSACTION_INTENT_ADMITTED').length,1);assert.ok(f.capacity().compatible);
});
