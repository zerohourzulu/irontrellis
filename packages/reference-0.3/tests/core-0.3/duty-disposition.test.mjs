import {test} from 'node:test';
import assert from 'node:assert/strict';
import {join} from 'node:path';
import {existsSync} from 'node:fs';
import {dutyFixture} from './fixtures/duty-fixture.mjs';
import {signHash,account,authArgs} from './fixtures/history-fixture.mjs';
import {openLocalDutyPolicy} from '../../packages/core-0.3/src/duties.ts';
import {openLocalAttemptRecorder,inspectContinuationAttempts} from '../../packages/core-0.3/src/attempts.ts';
import {observeContinuationHistory} from '../../packages/core-0.3/src/observation.ts';
import {stateOf} from '../../packages/core-0.3/src/local-store.ts';
import {authorizeContinuation} from '../../packages/core-0.3/src/history.ts';
import * as core from '../../packages/core-0.2/src/core/index.ts';
import * as oldCore from '../../sdk/duty-activation/dist/core-0.2/src/core/index.js';
const digest=n=>({algorithm:'sha256',value:'0x'+n.repeat(64)});
const keys=['SOURCE_REVIEWED','HISTORY_REVIEWED','FINDING_RECORDED','CONTROL_REVIEWED'];
const checklist=()=>Object.fromEntries(keys.map(k=>[k,{state:'SATISFIED',reason:'Reviewed; remaining outside uncertainty stated.'}]));
const equal=(a,b)=>assert.equal(core.canonicalEncode(a),core.canonicalEncode(b));
async function setup(t,{policy='E5',findingGrant=true,dispositionGrant=true}={}){
 const f=await dutyFixture(t,{policy});f.grant();await f.duties.activate(f.input);
 const resource='duty:'+f.selection.descriptorHash;
 if(findingGrant)f.owner.grant({id:'finding',to:'worker',actions:['ATTEST_DUTY_FINDING'],resources:[resource],expiresAt:1000});
 if(dispositionGrant)f.owner.grant({id:'disposition',to:'worker',actions:['RECORD_DUTY_DISPOSITION'],resources:[resource],expiresAt:1000});
 const input={id:'complete',duty:'duty',disposition:'COMPLETED_UNDER_POLICY',checklist:checklist(),reportDigest:digest('b'),nextStep:null,attestationAuthority:'finding',dispositionAuthority:'disposition'};
 const contest=id=>({id,duty:'duty',targetDispositionId:'duty-disposition:complete',reason:'Incident material may have been incomplete.',reportDigest:digest('c'),attestationAuthority:'finding',dispositionAuthority:'disposition'});
 const calls=[];
 const make=(finding,outer)=>openLocalDutyPolicy({...f.options,signHash:async h=>{calls.push('outer');assert.equal(existsSync(join(f.store.path,'.writer-lock')),false);return outer?outer(h):signHash(h)}},
  {session:'session',signHash:async h=>{calls.push('finding');assert.equal(existsSync(join(f.store.path,'.writer-lock')),false);return finding?finding(h):signHash(h)}});
 return {...f,f,resource,input,contest,calls,make,duties:make()};
}

test('complete local investigation has two signatures, preserved transaction uncertainty and reserved remaining capacity',async t=>{
 const x=await setup(t),before=x.owner.exportHistory(),capacity=x.store.snapshot().capacity;
 const prep=x.duties.prepareDisposition(x.input);assert.equal(prep.executionCapability,false);assert.deepEqual(x.calls,[]);
 const result=await x.duties.dispose(x.input),events=x.owner.exportHistory();
 assert.deepEqual(x.calls,['finding','outer']);equal(events.slice(0,-1),before);
 assert.equal(result.view.dutyDisposition,'COMPLETED_UNDER_POLICY');assert.equal(result.view.outstanding,false);assert.equal(result.view.externalOutcome,'NOT_PROVEN');
 assert.equal(stateOf(events).attemptDuties.get('duty').record.status,'OPEN');
 assert.equal(x.store.snapshot().capacity.dutyReserved,5);assert.equal(x.store.snapshot().capacity.lifecycleReserved,capacity.lifecycleReserved);
 for(const action of ['inspect','export'])assert.equal(authorizeContinuation(x.store.snapshot().history,authArgs(events,action)).result.decision,'DENY');
 assert.equal(oldCore.replayPortable({operationVersion:oldCore.PORTABLE_REPLAY_VERSION,events}).status,'REJECTED');
 assert.ok(Buffer.byteLength(core.canonicalEncode(events.at(-1)))<=8192);
 assert.equal(inspectContinuationAttempts(x.store.snapshot().history).attempts[0].duty.disposition.dutyDisposition,'COMPLETED_UNDER_POLICY');
 const query=observeContinuationHistory(x.store.snapshot().history).survives('worker');assert.equal(query.epistemicStatus,'ESTABLISHED',JSON.stringify(query));
 assert.equal(query.answer.attemptDuties[0].currentView.dutyDisposition,'COMPLETED_UNDER_POLICY');
 t.diagnostic('Dual-signature event bytes: '+Buffer.byteLength(core.canonicalEncode(events.at(-1))));
});

test('missing material can escalate but cannot complete; syntax and oversized input refuse before callbacks',async t=>{
 const x=await setup(t);const missing={...x.input,disposition:'ESCALATED',checklist:checklist(),nextStep:'Ask the internal custodian for the missing incident file.'};missing.checklist.SOURCE_REVIEWED.state='UNAVAILABLE';
 const result=await x.duties.dispose(missing);assert.equal(result.view.dutyDisposition,'ESCALATED');assert.equal(result.view.outstanding,true);
 for(const kind of ['incomplete','empty-next-step','extra','undefined','long-reason','long-next-step','absent-report','wrong-digest'])await t.test(kind,async t=>{
  const y=await setup(t),v=structuredClone(y.input);
  if(kind==='incomplete')v.checklist.HISTORY_REVIEWED.state='UNRESOLVED';
  if(kind==='empty-next-step'){v.disposition='ESCALATED';v.checklist.HISTORY_REVIEWED.state='UNRESOLVED';v.nextStep='';}
  if(kind==='extra')v.checklist.OTHER={state:'SATISFIED',reason:'extra'};
  if(kind==='undefined')v.nextStep=undefined;
  if(kind==='long-reason')v.checklist.SOURCE_REVIEWED.reason='x'.repeat(257);
  if(kind==='long-next-step'){v.disposition='ESCALATED';v.checklist.SOURCE_REVIEWED.state='UNAVAILABLE';v.nextStep='x'.repeat(513)}
  if(kind==='absent-report')delete v.reportDigest;
  if(kind==='wrong-digest')v.reportDigest.algorithm='sha512';
  const before=y.store.snapshot().revision;await assert.rejects(y.duties.dispose(v));assert.deepEqual(y.calls,[]);equal(y.store.snapshot().revision,before);
 });
});

test('attestation and disposition authority are independently necessary',async t=>{
 for(const missing of ['finding','disposition'])await t.test(missing,async t=>{
  const x=await setup(t,{findingGrant:missing!=='finding',dispositionGrant:missing!=='disposition'});
  await assert.rejects(x.duties.dispose(x.input));assert.deepEqual(x.calls,[]);
 });
 const x=await setup(t);await assert.rejects(x.duties.dispose({...x.input,attestationAuthority:'disposition',dispositionAuthority:'finding'}));assert.deepEqual(x.calls,[]);
});

test('exact retries report current view after contests and retirement, never sign again',async t=>{
 const x=await setup(t),first=await x.duties.dispose(x.input);await x.duties.contest(x.contest('challenge'));
 x.owner.advanceEpoch({agent:'worker',from:1,to:2});x.owner.revoke('finding');x.owner.revoke('disposition');
 const calls=x.calls.length,head=x.store.snapshot().history.head;
 const repeated=await x.duties.dispose(x.input);assert.equal(repeated.alreadyRecorded,true);assert.equal(repeated.eventId,first.eventId);
 assert.equal(repeated.view.dutyDisposition,'CONTESTED');equal(repeated.head,head);assert.equal(x.calls.length,calls);
 await assert.rejects(x.duties.dispose({...x.input,reportDigest:digest('d')}),e=>e.code==='OPERATION_CONFLICT');
 const repeatContest=await x.duties.contest(x.contest('challenge'));assert.equal(repeatContest.alreadyRecorded,true);assert.equal(x.calls.length,calls);
});

test('later same-duty evidence stales completion; unrelated events, expiry and revocation do not',async t=>{
 const x=await setup(t,{policy:'E6'});await x.duties.dispose(x.input);
 x.owner.createAgent({id:'unrelated'});x.owner.revoke('finding');x.f.setTime(1001);
 assert.equal(x.duties.inspect('duty').policy.dutyDisposition,'COMPLETED_UNDER_POLICY');
 // A later existing E6 review is relevant evidence, but does not complete D1.
 await openLocalAttemptRecorder(x.f.options).reviewDuty({id:'later-review',duty:'duty',summaryDigest:digest('e').value});
 assert.equal(x.duties.inspect('duty').policy.dutyDisposition,'NEEDS_REVIEW');
 assert.equal(x.duties.inspect('duty').policy.outstanding,true);
});

test('quotas are independent; contests persist through escalation and further evidence',async t=>{
 const x=await setup(t,{policy:'E6'});
 for(let i=0;i<4;i++)await x.duties.dispose({...x.input,id:i?'complete:'+i:'complete'});
 assert.equal(x.store.snapshot().capacity.dutyReserved,2);
 const calls=x.calls.length;await assert.rejects(x.duties.dispose({...x.input,id:'fifth'}));assert.equal(x.calls.length,calls);
 await openLocalAttemptRecorder(x.f.options).reviewDuty({id:'after-four',duty:'duty',summaryDigest:digest('e').value});
 assert.equal(x.duties.inspect('duty').policy.dutyDisposition,'NEEDS_REVIEW');
 await x.duties.contest(x.contest('one'));await x.duties.contest(x.contest('two'));assert.equal(x.store.snapshot().capacity.dutyReserved,0);
 const after=x.calls.length;await assert.rejects(x.duties.contest(x.contest('three')));assert.equal(x.calls.length,after);
 assert.equal(x.duties.inspect('duty').policy.dutyDisposition,'CONTESTED');
 const y=await setup(t);await y.duties.dispose(y.input);await y.duties.contest(y.contest('one'));await y.duties.contest(y.contest('two'));
 const escalated=await y.duties.dispose({...y.input,id:'escalate',disposition:'ESCALATED',nextStep:'Investigate the contest with the existing Principal.'});
 assert.equal(escalated.view.dutyDisposition,'CONTESTED');assert.equal(y.store.snapshot().capacity.dutyReserved,2);
});

test('each signing callback is followed by fresh authority, head and monotone-clock checks',async t=>{
 for(const phase of ['finding','outer'])for(const change of ['head','expiry','regression'])await t.test(phase+':'+change,async t=>{
  const x=await setup(t),mutate=async hash=>{if(change==='head')x.owner.createAgent({id:'racer'});else x.f.setTime(change==='expiry'?1000:99);return signHash(hash)};
  const duties=x.make(phase==='finding'?mutate:undefined,phase==='outer'?mutate:undefined);
  await assert.rejects(duties.dispose(x.input));assert.equal(x.owner.exportHistory().some(e=>e.type==='ATTEMPT_DUTY_DISPOSITION_RECORDED'),false);
  assert.deepEqual(x.calls,phase==='finding'?['finding']:['finding','outer']);
 });
 const x=await setup(t),duties=x.make(async h=>{x.f.setTime(101);return signHash(h)},async h=>{x.f.setTime(102);return signHash(h)});
 await duties.dispose(x.input);assert.equal(x.owner.exportHistory().at(-1).timestamp,100);
 const y=await setup(t),regressed=y.make(async h=>{y.f.setTime(101);return signHash(h)},async h=>{y.f.setTime(100);return signHash(h)});
 await assert.rejects(regressed.dispose(y.input),e=>e.code==='CLOCK_INVALID');
});

test('a bad first signature never calls the second signer, and a failed second signer never appends',async t=>{
 const x=await setup(t);await assert.rejects(x.make(async()=>`0x${'0'.repeat(130)}`).dispose(x.input));assert.deepEqual(x.calls,['finding']);
 const y=await setup(t),before=y.store.snapshot().revision;await assert.rejects(y.make(undefined,async()=>{throw Error('offline')}).dispose(y.input));equal(y.store.snapshot().revision,before);
});

test('a distinct internal attester needs its own current Role, runtime and exact permission',async t=>{
 const x=await dutyFixture(t);x.owner.createAgent({id:'reviewer'});x.owner.createRole({id:'review-role'});
 x.owner.appoint({agent:'reviewer',role:'review-role',tenure:'review-tenure',number:1});
 x.owner.admitRuntime({agent:'reviewer',session:'review-session',epoch:1,key:'review-key',address:account.address,expiresAt:1000});
 const selected=x.duties.describe({duty:'duty',incidentSourceDigest:digest('a'),attesterRole:'review-role'});
 x.grant({resources:[selected.activationResource]});await x.duties.activate({...x.input,descriptor:selected.descriptor});
 const resource='duty:'+selected.descriptorHash;
 x.owner.grant({id:'finding',to:'reviewer',actions:['ATTEST_DUTY_FINDING'],resources:[resource],expiresAt:1000});
 x.owner.grant({id:'disposition',to:'worker',actions:['RECORD_DUTY_DISPOSITION'],resources:[resource],expiresAt:1000});
 const input={id:'complete',duty:'duty',disposition:'COMPLETED_UNDER_POLICY',checklist:checklist(),reportDigest:digest('b'),nextStep:null,attestationAuthority:'finding',dispositionAuthority:'disposition'};
 await assert.rejects(x.duties.dispose(input));
 const duties=openLocalDutyPolicy(x.options,{session:'review-session',signHash});
 const result=await duties.dispose(input);assert.equal(result.view.dutyDisposition,'COMPLETED_UNDER_POLICY');
 const event=x.owner.exportHistory().at(-1);assert.equal(event.data.actorId,'worker');assert.equal(event.data.finding.challenge.attesterId,'reviewer');
 const changed=openLocalDutyPolicy({...x.options,signHash:async hash=>{x.setTime(1000);return signHash(hash)}},{session:'review-session',signHash});
 await assert.rejects(changed.dispose({...input,id:'expired-reviewer'}));
});

test('captured caller input cannot change between signatures; copied finding cannot target another event',async t=>{
 const x=await setup(t),input=structuredClone(x.input);
 const duties=x.make(async hash=>{input.reportDigest.value=digest('f').value;input.checklist.SOURCE_REVIEWED.state='UNAVAILABLE';return signHash(hash)});
 await duties.dispose(input);const original=x.owner.exportHistory().at(-1);
 equal(original.data.finding.challenge.operation.reportDigest,x.input.reportDigest);
 const changed={...original,id:'duty-disposition:forged'};const before=x.store.snapshot().revision;
 assert.throws(()=>x.store.append(changed,before));equal(x.store.snapshot().revision,before);
 for(const patch of [{purpose:'CONTEST'},{evidenceIndexHash:digest('f').value},{previousDispositionEventId:original.id}]){
  const event=structuredClone(original);Object.assign(event.data.finding.challenge,patch);
  assert.equal(core.replayPortable({operationVersion:core.PORTABLE_REPLAY_VERSION,events:[...x.owner.exportHistory().slice(0,-1),event]}).status,'REJECTED');
 }
});

test('an existing review or a report digest by itself does not complete the activated duty',async t=>{
 const x=await setup(t,{policy:'E6'});
 await openLocalAttemptRecorder(x.f.options).reviewDuty({id:'review-only',duty:'duty',summaryDigest:digest('b').value});
 assert.equal(x.duties.inspect('duty').policy.dutyDisposition,'OPEN');
 await assert.rejects(x.duties.dispose({id:'missing-finding',duty:'duty',reportDigest:digest('b')}));
 assert.deepEqual(x.calls,[]);
});

test('Role replacement alone keeps a completion historical; explicit A to B to A assignments make it need review',async t=>{
 const x=await setup(t);await x.duties.dispose(x.input);
 x.f.append('role-to-replacement','ROLE_TRANSFERRED',{roleId:'role',fromAgentId:'worker',fromRoleTenureId:'tenure',toAgentId:'replacement',toRoleTenureId:'replacement-tenure',toTenureNumber:2,principalId:'owner',transferKind:'REASSIGNMENT'});
 assert.equal(x.duties.inspect('duty').policy.dutyDisposition,'COMPLETED_UNDER_POLICY');
 x.owner.admitRuntime({agent:'replacement',session:'replacement-session',epoch:1,key:'replacement-key',address:account.address,expiresAt:1000});
 for(const [id,action] of [['new-finding','ATTEST_DUTY_FINDING'],['new-disposition','RECORD_DUTY_DISPOSITION']])x.owner.grant({id,to:'replacement',actions:[action],resources:[x.resource],expiresAt:1000});
 x.owner.grant({id:'assign-new',to:'replacement',actions:['ASSIGN_ATTEMPT_DUTY'],resources:['job'],expiresAt:1000});
 const replacementOptions={...x.f.options,session:'replacement-session'};
 await assert.rejects(openLocalDutyPolicy(replacementOptions).dispose({...x.input,id:'without-assignment',attestationAuthority:'new-finding',dispositionAuthority:'new-disposition'}));
 await openLocalAttemptRecorder(replacementOptions).assignDuty({id:'to-replacement',duty:'duty'});
 assert.equal(x.duties.inspect('duty').policy.dutyDisposition,'NEEDS_REVIEW');
 x.f.append('role-back-to-worker','ROLE_TRANSFERRED',{roleId:'role',fromAgentId:'replacement',fromRoleTenureId:'replacement-tenure',toAgentId:'worker',toRoleTenureId:'return-tenure',toTenureNumber:3,principalId:'owner',transferKind:'REASSIGNMENT'});
 await openLocalAttemptRecorder(x.f.options).assignDuty({id:'back-to-worker',duty:'duty'});
 const view=x.duties.inspect('duty').policy;assert.equal(view.currentAssigneeId,'worker');assert.equal(view.dutyDisposition,'NEEDS_REVIEW');
 assert.equal((await x.duties.dispose(x.input)).view.dutyDisposition,'NEEDS_REVIEW');
});

test('large escaped checklist cannot exceed the event envelope by signing first',async t=>{
 const x=await setup(t),input=structuredClone(x.input);
 for(const key of keys)input.checklist[key].reason='\\'.repeat(256);
 input.disposition='ESCALATED';input.checklist.SOURCE_REVIEWED.state='UNAVAILABLE';input.nextStep='\\'.repeat(512);
 const before=x.store.snapshot().revision;
 await assert.rejects(x.duties.dispose(input));assert.deepEqual(x.calls,[]);equal(x.store.snapshot().revision,before);
});

test('the old single-signature store route refuses D1 finding events before its callback',async t=>{
 const x=await setup(t);const {commitHistoryAdministration}=await import('../../packages/core-0.3/src/history-store/index.ts');let calls=0;
 await assert.rejects(commitHistoryAdministration(x.store,{expectedDomain:x.f.options.domain,runtimeSessionId:'session',transition:{id:'wrong-writer',type:'ATTEMPT_DUTY_DISPOSITION_RECORDED',timestamp:100,data:{dutyId:'duty'}}},{signHash:async h=>{calls++;return signHash(h)},now:()=>100}),e=>e.code==='DUTY_WRITER_REQUIRED');
 assert.equal(calls,0);
});

// Two still-valid child grants must not become an implicit retry route during signing.
test('either signer phase refuses switching to another grant route after expiry',async t=>{
 for(const phase of ['finding','outer'])await t.test(phase,async t=>{
  const x=await setup(t);
  const template=x.owner.exportHistory().find(e=>e.type==='AUTHORITY_GRANTED'&&e.data.grant.authorityId==='finding').data.grant;
  x.f.append('branch-parent','AUTHORITY_GRANTED',{grant:{...template,authorityId:'branch-parent',rootAuthorityId:'branch-parent',granteeId:'replacement',constraints:{...template.constraints,maxDelegationDepth:1}}});
  for(const [id,expiresAt]of [['branch-a',101],['branch-b',1000]])x.f.append(id,'AUTHORITY_GRANTED',{grant:{...template,authorityId:id,rootAuthorityId:'branch-parent',parentAuthorityId:'branch-parent',grantorId:'replacement',constraints:{...template.constraints,expiresAt,maxDelegationDepth:0}}});
  const change=async h=>{x.f.setTime(101);return signHash(h)};
  const duties=x.make(phase==='finding'?change:undefined,phase==='outer'?change:undefined);
  const before=x.store.snapshot().revision;
  await assert.rejects(duties.dispose({...x.input,attestationAuthority:'branch-parent'}));
  equal(x.store.snapshot().revision,before);assert.deepEqual(x.calls,phase==='finding'?['finding']:['finding','outer']);
 });
});

test('the actual retained-evidence reader child shows completion and then persistent contest',async t=>{
 const x=await setup(t);await x.duties.dispose(x.input);
 const {writeFileSync}=await import('node:fs'),{join}=await import('node:path');
 const {runObservation}=await import('../../lib/reader-runner.mjs');
 const path=join(x.f.dir,'observed.json');
 const {encode}=await import('../../lib/reader-contract.mjs');
 const write=()=>writeFileSync(path,encode(x.owner.exportHistory()));
 write();
 const source={path,source:'duty-case',disclosure:'evidence',configHash:null};
 const completed=runObservation(source,'survives',{agent:'worker'});
 assert.ok(JSON.stringify(completed).includes('COMPLETED_UNDER_POLICY'));
 assert.ok(JSON.stringify(completed).includes('NOT_PROVEN'));
 await x.duties.contest(x.contest('reader-contest'));write();
 const contested=runObservation(source,'handover_report');
 assert.ok(JSON.stringify(contested).includes('CONTESTED'));
 assert.ok(JSON.stringify(contested).includes('duty-disposition:complete'));
});

test('a later signed outside report changes freshness but does not itself complete or contest the duty',async t=>{
 const x=await setup(t);await x.duties.dispose(x.input);
 const before=x.duties.inspect('duty').policy;
 const identity=stateOf(x.owner.exportHistory()).intentAdmissions.get('job').adapterIdentity;
 const acknowledgment=core.createRemoteServiceReportAcknowledgment(identity,digest('d').value);
 await openLocalAttemptRecorder(x.f.options).observe({id:'later-outside-report',intent:'job',acknowledgment});
 const after=x.duties.inspect('duty').policy;
 assert.equal(after.dutyDisposition,'NEEDS_REVIEW');assert.equal(after.externalOutcome,'NOT_PROVEN');
 assert.equal(after.policy.contestCount,0);assert.equal(after.lastRecordedDisposition.eventId,before.lastRecordedDisposition.eventId);
 const {derivePortableDutyEvidenceIndex}=await import('../../packages/core-0.2/src/core/duty-disposition.ts');
 const index=derivePortableDutyEvidenceIndex(stateOf(x.owner.exportHistory()),'duty');
 assert.equal(index.counts.OUTCOME_OBSERVATION_RECORDED,1);
 assert.equal(index.records.at(-1).eventId,'attempt-observation:later-outside-report');
 equal((await x.duties.dispose(x.input)).view,after);
});
