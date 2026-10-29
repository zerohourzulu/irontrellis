import {test} from 'node:test';
import assert from 'node:assert/strict';
import {capacityOf,dutyReservationOf,assertCapacityTransition} from '../../packages/core-0.3/src/capacity.ts';
import {historyCapacity,hasAdministrativeRoom,projectHistoryUsage} from '../../packages/core-0.3/src/history-store/capacity.ts';
import {dutyFixture} from './fixtures/duty-fixture.mjs';
import {fixture,capture,padded} from './fixtures/history-fixture.mjs';

// These are arithmetic-only census inputs, deliberately not authenticated
// events. No synthetic census is presented as replay-valid history.
const activate=(dutyId='duty')=>({id:'activate:'+dutyId,type:'ATTEMPT_DUTY_POLICY_ACTIVATED',timestamp:100,data:{descriptor:{dutyId}}});
const disposition=(n,dutyId='duty',status='COMPLETED_UNDER_POLICY')=>({id:'disposition:'+dutyId+':'+n,type:'ATTEMPT_DUTY_DISPOSITION_RECORDED',timestamp:100,data:{dutyId,status}});
const contest=(n,dutyId='duty')=>({id:'contest:'+dutyId+':'+n,type:'ATTEMPT_DUTY_CONTEST_RECORDED',timestamp:100,data:{dutyId}});
const census=events=>dutyReservationOf(events);

test('four dispositions and two contests consume only their corresponding finite reservations',()=>{
 const events=[activate()];
 assert.deepEqual(census(events),{activatedDuties:1,dutyReserved:6,withinLimits:true});
 for(let n=1;n<=4;n++){
  events.push(disposition(n));
  assert.deepEqual(census(events),{activatedDuties:1,dutyReserved:6-n,withinLimits:true});
 }
 assert.equal(census([...events,disposition(5)]).withinLimits,false);
 assert.equal(census([...events,disposition(5)]).dutyReserved,2);
 for(let n=1;n<=2;n++){
  events.push(contest(n));
  assert.deepEqual(census(events),{activatedDuties:1,dutyReserved:2-n,withinLimits:true});
 }
 assert.deepEqual(census([...events,contest(3)]),{activatedDuties:1,dutyReserved:0,withinLimits:false});
 assert.deepEqual(census([...events,disposition(5)]),{activatedDuties:1,dutyReserved:0,withinLimits:false});
});

test('contest exhaustion leaves all four disposition slots and never resets counters',()=>{
 const events=[activate(),contest(1),contest(2)];
 assert.deepEqual(census(events),{activatedDuties:1,dutyReserved:4,withinLimits:true});
 assert.deepEqual(census([...events,contest(3)]),{activatedDuties:1,dutyReserved:4,withinLimits:false});
 for(let n=1;n<=4;n++)events.push(disposition(n,'duty','ESCALATED'));
 assert.deepEqual(census(events),{activatedDuties:1,dutyReserved:0,withinLimits:true});
 assert.equal(census([...events,activate()]).dutyReserved,0,'duplicate activation census cannot reset a consumed quota; replay rejects duplicate activation');
});

test('completion preserves unused quota and every duty has independent reservations',()=>{
 const events=[activate(),activate('other'),disposition(1)];
 assert.deepEqual(census(events),{activatedDuties:2,dutyReserved:11,withinLimits:true});
 events.push(disposition(2),disposition(3),disposition(4),contest(1),contest(2));
 assert.deepEqual(census(events),{activatedDuties:2,dutyReserved:6,withinLimits:true});
 assert.deepEqual(census([...events,disposition(5)]),{activatedDuties:2,dutyReserved:6,withinLimits:false});
 assert.deepEqual(census([...events,disposition(1,'other')]),{activatedDuties:2,dutyReserved:5,withinLimits:true});
});

test('unselected duties and preactivation candidates cannot consume another duty reserve',()=>{
 assert.deepEqual(census([activate(),disposition(1,'unknown')]),{activatedDuties:1,dutyReserved:6,withinLimits:false});
 assert.deepEqual(census([activate(),contest(1,'unknown')]),{activatedDuties:1,dutyReserved:6,withinLimits:false});
 assert.deepEqual(census([disposition(1),activate()]),{activatedDuties:1,dutyReserved:6,withinLimits:false});
 assert.deepEqual(census([contest(1)]),{activatedDuties:0,dutyReserved:0,withinLimits:false});
});

test('D1 consumption leaves legacy lifecycle/control reservations and old output shape intact',async t=>{
 const f=await fixture(t,{policy:'E5'}),before=capacityOf(f.events);
 const suffix=[activate(),disposition(1),contest(1)],after=capacityOf([...f.events,...suffix]);
 assert.deepEqual(Object.keys(before),['profile','eventCount','maxEvents','reservedByRecordType','declaredJobs','lifecycleReserved','controlReserved','unreservedEvents','compatible','mode','canDeclareJob','remainingPhysicalEvents','pointInTimeOnly','grantsAuthority']);
 assert.equal(after.dutyReserved,4);assert.equal(after.activatedDuties,1);
 for(const key of ['lifecycleReserved','controlReserved','declaredJobs'])assert.equal(after[key],before[key],key);
 assert.deepEqual(after.reservedByRecordType,before.reservedByRecordType);
 assert.equal(after.unreservedEvents,before.unreservedEvents-7);
 assert.equal(after.compatible,false);
 for(const candidate of suffix)assert.throws(()=>assertCapacityTransition(f.events,[candidate]),e=>e.code==='CAPACITY_INCOMPATIBLE');
});

test('a reserved record retains each projected maximum while an unrelated record cannot spend it',()=>{
 const maxima={events:1024,canonicalBytes:6*1024*1024,nodes:524288,encodedBytes:32*1024*1024,segments:1024};
 const costs={events:1,canonicalBytes:8192,nodes:512,encodedBytes:32768,segments:1};
 const legacy=19,beforeReserve=legacy+census([activate()]).dutyReserved;
 const afterReserve=legacy+census([activate(),disposition(1)]).dutyReserved;
 for(const dimension of Object.keys(maxima)){
  const usage={events:0,canonicalBytes:0,nodes:0,encodedBytes:0,segments:0};
  usage[dimension]=maxima[dimension]-beforeReserve*costs[dimension];
  const written=Object.fromEntries(Object.entries(usage).map(([key,value])=>[key,value+costs[key]]));
  assert.equal(projectHistoryUsage(usage,beforeReserve).compatible,true,dimension);
  const consumed=projectHistoryUsage(written,afterReserve);
  assert.equal(consumed.compatible,true,dimension);assert.equal(consumed.projected[dimension],maxima[dimension]);
  assert.equal(projectHistoryUsage(written,beforeReserve).compatible,false,dimension);
 }
});

test('presign room uses complete replayed activation and only permits matching D1 reservation arithmetic',async t=>{
 const f=await dutyFixture(t);f.grant();await f.duties.activate(f.input);
 const snapshot=f.store.snapshot(),segments=snapshot.capacity.usage.segments;
 assert.equal(historyCapacity(snapshot.history,segments).dutyReserved,6);
 for(const candidate of [disposition(1),contest(1)]){
  assert.equal(hasAdministrativeRoom(snapshot.history,candidate,segments),true);
  assert.equal(hasAdministrativeRoom(snapshot.history,{...candidate,data:{dutyId:'unknown'}},segments),false);
 }
 const fullEventCount=1024-snapshot.capacity.reservedEvents;
 const full=capture(padded(f.owner.exportHistory(),fullEventCount));
 const fullSegments=Math.ceil(fullEventCount/64);
 assert.equal(historyCapacity(full,fullSegments).projected.events,1024);
 for(const candidate of [disposition(1),contest(1)])assert.equal(hasAdministrativeRoom(full,candidate,fullSegments),true);
 assert.equal(hasAdministrativeRoom(full,{id:'unrelated',type:'PRINCIPAL_CREATED',timestamp:100,data:{principalId:'unrelated'}},fullSegments),false);
 assert.equal(f.store.snapshot().capacity.dutyReserved,6,'unsigned room candidates never change durable reservation');
});
