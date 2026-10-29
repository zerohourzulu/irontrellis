import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import * as core from '../../packages/core-0.2/src/core/index.ts';
import {buildPortableDutyPolicyDescriptor} from '../../packages/core-0.2/src/core/duty-policy.ts';
import {capacityOf,assertCapacityTransition,ManagedLocalEventStore} from '../../packages/core-0.3/src/capacity.ts';
import {historyCapacity,hasAdministrativeRoom,projectHistoryUsage} from '../../packages/core-0.3/src/history-store/capacity.ts';
import {CONTINUATION_PROFILE} from '../../packages/core-0.3/src/history.ts';
import {DirectoryHistoryStore,commitHistoryAdministration} from '../../packages/core-0.3/src/history-store/index.ts';
import {initializeStore} from '../../packages/core-0.3/src/history-store/store.ts';
import {stateOf} from '../../packages/core-0.3/src/local-store.ts';
import {LIMITS} from '../../packages/core-0.3/src/history-store/codec.ts';
import {fixture,capture,padded,signHash} from './fixtures/history-fixture.mjs';

// Census-only candidates deliberately omit signatures/selection fields. These
// tests never pass them off as replayed histories or authority to append.
const activation=(dutyId='duty',limits={dispositionLimit:4,contestLimit:2})=>({
 id:'activation:'+dutyId,type:'ATTEMPT_DUTY_POLICY_ACTIVATED',timestamp:100,
 data:{descriptor:{dutyId,...limits}},
});
const code=c=>e=>e.code===c;
const lifecycleTypes=[
 'TRANSACTION_INTENT_ADMITTED','TRANSACTION_INTENT_CONSUMED','TRANSACTION_OUTCOME_RECORDED','RECEIPT_RECORDED',
 'OUTCOME_OBSERVATION_RECORDED','ATTEMPT_DUTY_CREATED','ATTEMPT_DUTY_ASSIGNED','ATTEMPT_DUTY_REVIEW_CLOSED',
 'OBLIGATION_CREATED','OBLIGATION_PERFORMANCE_ASSIGNED','OBLIGATION_STATUS_RECORDED',
];

test('activation census adds six independent slots and preserves the legacy eleven/eight census',async t=>{
 const f=await fixture(t,{policy:'E5'}),before=capacityOf(f.events);
 assert.deepEqual(Object.keys(before),['profile','eventCount','maxEvents','reservedByRecordType','declaredJobs','lifecycleReserved','controlReserved','unreservedEvents','compatible','mode','canDeclareJob','remainingPhysicalEvents','pointInTimeOnly','grantsAuthority']);
 assert.deepEqual(Object.keys(before.reservedByRecordType),lifecycleTypes);
 assert.equal(before.declaredJobs,1);assert.equal(before.controlReserved,8);
 const used=new Set(f.events.map(e=>e.type));
 assert.deepEqual(before.reservedByRecordType,Object.fromEntries(lifecycleTypes.map(type=>[type,used.has(type)?0:1])));
 assert.equal(before.lifecycleReserved,lifecycleTypes.filter(type=>!used.has(type)).length);
 for(const limits of [{dispositionLimit:4,contestLimit:2},{dispositionLimit:0,contestLimit:0},{dispositionLimit:99,contestLimit:99}]){
  const after=capacityOf([...f.events,activation('duty',limits)]);
  assert.equal(after.dutyReserved,6);assert.equal(after.activatedDuties,1);
  assert.deepEqual(after.reservedByRecordType,before.reservedByRecordType);
  assert.equal(after.lifecycleReserved,before.lifecycleReserved);assert.equal(after.controlReserved,before.controlReserved);
  assert.equal(after.unreservedEvents,before.unreservedEvents-7);assert.equal(after.compatible,false);
 }
 assert.equal(capacityOf([...f.events,activation('duty'),activation('another')]).dutyReserved,12);
 assert.equal(capacityOf([...f.events,activation('duty'),activation('duty')]).dutyReserved,6);
 // Duplicate selection is rejected by replay; census alone cannot authorize it.
});

test('managed96 refuses activation and later unsupported duty records without changing bytes',async t=>{
 const f=await fixture(t,{policy:'E5'}),store=new ManagedLocalEventStore(f.config.historyFile),before=readFileSync(f.config.historyFile);
 for(const type of ['ATTEMPT_DUTY_POLICY_ACTIVATED','ATTEMPT_DUTY_DISPOSITION_RECORDED','ATTEMPT_DUTY_CONTEST_RECORDED']){
  const event={...activation(),type};
  assert.throws(()=>assertCapacityTransition(f.events,[event]),code('CAPACITY_INCOMPATIBLE'));
  assert.throws(()=>store.withExclusiveWriter(w=>w.appendAtExpectedHead(event,f.handle.head)),code('CAPACITY_INCOMPATIBLE'));
  assert.deepEqual(readFileSync(f.config.historyFile),before);
 }
});

test('presign census needs seven free event slots including existing legacy reserves',async t=>{
 const f=await fixture(t,{policy:'E5'}),reserve=historyCapacity(f.handle,1).reservedEvents;
 const seven=capture(padded(f.events,1024-reserve-7)),six=capture(padded(f.events,1024-reserve-6));
 assert.equal(historyCapacity(seven,16).projected.events,1017);
 assert.equal(historyCapacity(six,16).projected.events,1018);
 assert.equal(hasAdministrativeRoom(seven,activation(),16),true);
 assert.equal(hasAdministrativeRoom(six,activation(),16),false);
 for(const type of ['ATTEMPT_DUTY_DISPOSITION_RECORDED','ATTEMPT_DUTY_CONTEST_RECORDED'])
  assert.equal(hasAdministrativeRoom(f.handle,{...activation(),type},1),false);
 for(const segments of [0,-1,1.5,1025,f.events.length+1])assert.equal(hasAdministrativeRoom(f.handle,activation(),segments),false);
});

test('a signed activation reserves durably and unrelated writers cannot spend its six slots',async t=>{
 const f=await fixture(t,{policy:'E5'});
 const descriptor=buildPortableDutyPolicyDescriptor(stateOf(f.events),{
  dutyId:'duty',acceptedAttesterRoleId:'role',incidentSourceDigest:{algorithm:'sha256',value:'0x'+'a'.repeat(64)},
 });
 f.owner.grant({id:'activate',to:'worker',actions:['ACTIVATE_DUTY_POLICY'],resources:['duty-policy:'+core.hashCanonical(descriptor)],expiresAt:10000});
 for(let i=0;i<9;i++)f.owner.grant({id:'spare:'+i,to:'worker',actions:['unrelated'],resources:['spare:'+i],expiresAt:10000});
 const events=f.owner.exportHistory(),reserve=historyCapacity(capture(events),1).reservedEvents;
 const input={expectedDomain:f.config.domain,runtimeSessionId:'session',transition:{id:'activated',type:'ATTEMPT_DUTY_POLICY_ACTIVATED',timestamp:100,
  data:{actorId:'worker',descriptor,descriptorHash:core.hashCanonical(descriptor),activationAuthorityId:'activate'}}};
 const area=dirname(f.config.historyFile),full=capture(padded(events,1024-reserve-7));
 // Internal test seeding preserves a complete, replay-valid prefix; production
 // working histories use explicit migration rather than initializeStore.
 initializeStore(join(area,'seven'),full);
 const store=new DirectoryHistoryStore(join(area,'seven'));
 let calls=0;
 const after=await commitHistoryAdministration(store,input,{signHash:async hash=>{calls++;return signHash(hash)},now:()=>100});
 assert.equal(calls,1);assert.equal(after.capacity.dutyReserved,6);
 assert.equal(after.capacity.reservedEvents,reserve+6);assert.equal(after.capacity.projected.events,1024);
 assert.deepEqual(new DirectoryHistoryStore(store.path).snapshot().capacity,after.capacity);
 assert.throws(()=>store.append({id:'unrelated',type:'PRINCIPAL_CREATED',timestamp:100,data:{principalId:'unrelated'}},after.revision),code('CAPACITY_RESERVED'));
 assert.equal(after.capacity.canDeclareJob,false);
 for(let i=0;i<8;i++){
  const snapshot=store.snapshot();
  const written=store.append({id:'revoke-spare:'+i,type:'AUTHORITY_REVOKED',timestamp:100,data:{authorityId:'spare:'+i,revokerId:'owner'}},snapshot.revision);
  assert.equal(written.capacity.controlReserved,7-i);assert.equal(written.capacity.dutyReserved,6);
 }
 const drained=store.snapshot();
 assert.throws(()=>store.append({id:'revoke-spare:8',type:'AUTHORITY_REVOKED',timestamp:100,data:{authorityId:'spare:8',revokerId:'owner'}},drained.revision),code('CAPACITY_RESERVED'));
 assert.deepEqual(store.snapshot().revision,drained.revision);
 initializeStore(join(area,'six'),capture(padded(events,1024-reserve-6)));
 const six=new DirectoryHistoryStore(join(area,'six')),before=six.snapshot();calls=0;
 await assert.rejects(commitHistoryAdministration(six,input,{signHash:async hash=>{calls++;return signHash(hash)},now:()=>100}),code('CAPACITY_RESERVED'));
 assert.equal(calls,0);assert.deepEqual(six.snapshot().revision,before.revision);
});

test('canonical byte exhaustion refuses activation while event slots remain available',async t=>{
 const f=await fixture(t,{policy:'E5'});
 const descriptor=buildPortableDutyPolicyDescriptor(stateOf(f.events),{
  dutyId:'duty',acceptedAttesterRoleId:'role',incidentSourceDigest:{algorithm:'sha256',value:'0x'+'b'.repeat(64)},
 });
 f.owner.grant({id:'activate-byte',to:'worker',actions:['ACTIVATE_DUTY_POLICY'],resources:['duty-policy:'+core.hashCanonical(descriptor)],expiresAt:10000});
 const source=f.owner.exportHistory(),reserve=historyCapacity(capture(source),1).reservedEvents;
 const input={expectedDomain:f.config.domain,runtimeSessionId:'session',transition:{id:'activated-byte',type:'ATTEMPT_DUTY_POLICY_ACTIVATED',timestamp:100,
  data:{actorId:'worker',descriptor,descriptorHash:core.hashCanonical(descriptor),activationAuthorityId:'activate-byte'}}};
 const threshold=6*1024*1024-(reserve+7)*8192;
 const events=[...source],template=padded(source,source.length+1,{wide:true}).at(-1);
 let bytes=events.reduce((n,e)=>n+Buffer.byteLength(core.canonicalEncode(e)),0),prior;
 while(bytes<=threshold){
  prior=bytes;const n=events.length,id='duty-wide:'+n;
  const e={...template,id,data:{grant:{...template.data.grant,authorityId:id,rootAuthorityId:id,
   constraints:{...template.data.grant.constraints,resources:Array.from({length:28},(_,i)=>('r'+n+':'+i).padEnd(230,'x'))}}}};
  events.push(e);bytes+=Buffer.byteLength(core.canonicalEncode(e));
 }
 assert.ok(prior<=threshold);assert.ok(bytes>threshold);assert.ok(events.length+reserve+7<1024);
 const before=capture(events.slice(0,-1)),after=capture(events),segments=Math.ceil(events.length/64);
 assert.equal(historyCapacity(after,segments).compatible,true);
 assert.equal(hasAdministrativeRoom(before,activation(),segments),true);
 assert.equal(hasAdministrativeRoom(after,activation(),segments),false);
 const path=join(dirname(f.config.historyFile),'byte-full');initializeStore(path,after);
 const store=new DirectoryHistoryStore(path),unchanged=store.snapshot();let calls=0;
 await assert.rejects(commitHistoryAdministration(store,input,{signHash:async hash=>{calls++;return signHash(hash)},now:()=>100}),code('CAPACITY_RESERVED'));
 assert.equal(calls,0);assert.deepEqual(store.snapshot().revision,unchanged.revision);
});

test('each projected dimension independently reserves activation plus six future maxima',()=>{
 // Literal accepted limits and costs make the expectations independent of the
 // implementation's projection expression. These are arithmetic boundary
 // vectors, not claims that every limit is reachable in a replay-valid history.
 const maxima={events:1024,canonicalBytes:6*1024*1024,nodes:524288,encodedBytes:32*1024*1024,segments:1024};
 const costs={events:1,canonicalBytes:8192,nodes:512,encodedBytes:32768,segments:1};
 const existingReserve=19,totalReserve=existingReserve+7;
 for(const dimension of Object.keys(maxima)){
  const usage={events:0,canonicalBytes:0,nodes:0,encodedBytes:0,segments:0};
  usage[dimension]=maxima[dimension]-totalReserve*costs[dimension];
  const at=projectHistoryUsage(usage,totalReserve);
  assert.equal(at.compatible,true,dimension);assert.equal(at.projected[dimension],maxima[dimension]);
  assert.equal(projectHistoryUsage({...usage,[dimension]:usage[dimension]+1},totalReserve).compatible,false,dimension);
 }
 const usage={events:100,canonicalBytes:12000,nodes:600,encodedBytes:15000,segments:3};
 const before=projectHistoryUsage(usage,existingReserve),after=projectHistoryUsage(usage,existingReserve+6);
 for(const dimension of Object.keys(maxima))assert.equal(after.projected[dimension]-before.projected[dimension],6*costs[dimension],dimension);
});

test('new job admission still requires twelve slots outside every duty reservation',()=>{
 const usage={events:1006,canonicalBytes:1000,nodes:10,encodedBytes:1000,segments:1};
 assert.equal(projectHistoryUsage(usage,6).canDeclareJob,true);
 assert.equal(projectHistoryUsage({...usage,events:1007},6).canDeclareJob,false);
 assert.equal(projectHistoryUsage({...usage,events:1018},6).compatible,true);
 assert.equal(projectHistoryUsage({...usage,events:1019},6).compatible,false);
});

test('real-history node, encoded-byte and segment maxima are dominated by event count',()=>{
 assert.equal(CONTINUATION_PROFILE.maxEvents*CONTINUATION_PROFILE.maxEventNodes,CONTINUATION_PROFILE.maxHistoryNodes);
 assert.equal(CONTINUATION_PROFILE.maxEvents*LIMITS.eventBytes,LIMITS.historyBytes);
 assert.equal(CONTINUATION_PROFILE.maxEvents,LIMITS.segments);
 // One segment must hold at least one event. Consequently an otherwise-valid
 // real history cannot exhaust these dimensions independently of event count;
 // the isolated boundary vectors above still check every budget comparison.
});
