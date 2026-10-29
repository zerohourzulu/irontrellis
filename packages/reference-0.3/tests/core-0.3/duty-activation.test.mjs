import {dutyFixture} from './fixtures/duty-fixture.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {join,dirname} from 'node:path';
import {existsSync} from 'node:fs';
import * as core from '../../packages/core-0.2/src/core/index.ts';
import * as oldCore from '../../sdk/continuation-release/core/dist/core-0.2/src/core/index.js';
import * as oldHistory from '../../sdk/continuation-release/core/dist/core-0.3/src/history.js';
import {fixture,capture,signHash,authArgs} from './fixtures/history-fixture.mjs';
import {openLocalOwner} from '../../packages/core-0.3/src/local-owner.ts';
import {stateOf} from '../../packages/core-0.3/src/local-store.ts';
import {openLocalDutyPolicy,inspectContinuationDutyPolicy} from '../../packages/core-0.3/src/duties.ts';
import {inspectContinuationAttempts} from '../../packages/core-0.3/src/attempts.ts';
import {observeContinuationHistory} from '../../packages/core-0.3/src/observation.ts';
import {prepareMigration,stageMigration,activateMigration,DirectoryHistoryStore} from '../../packages/core-0.3/src/history-store/index.ts';
import {prepareContinuationAdministration,authorizeContinuation} from '../../packages/core-0.3/src/history.ts';

const digest={algorithm:'sha256',value:'0x'+'a'.repeat(64)};
const mutable=x=>structuredClone(x);
const event=(id,type,data)=>({id,type,timestamp:100,data});

test('D1 activates the original E5 duty without changing prior evidence, spent allowance or revocation',async t=>{
  const f=await dutyFixture(t);f.grant();const before=f.owner.exportHistory(),state=stateOf(before),capacity=f.store.snapshot().capacity;
  const r=await f.duties.activate(f.input),after=f.owner.exportHistory(),next=stateOf(after);
  assert.equal(r.alreadyRecorded,false);assert.equal(f.calls,1);
  assert.equal(core.canonicalEncode(after.slice(0,-1)),core.canonicalEncode(before));
  assert.deepEqual(next.genesis,state.genesis);assert.deepEqual(next.intentAdmissions,state.intentAdmissions);
  assert.deepEqual(next.attemptDuties,state.attemptDuties);assert.deepEqual(next.eventHistoryHashes.slice(0,-1),state.eventHistoryHashes);
  for(const action of ['inspect','export'])assert.equal(authorizeContinuation(f.store.snapshot().history,authArgs(after,action)).result.decision,'DENY');
  assert.equal(next.attemptDutyPolicies.size,1);assert.equal(r.view.dutyDisposition,'OPEN');assert.equal(r.view.outstanding,true);assert.equal(r.view.externalOutcome,'NOT_PROVEN');
  assert.equal(f.store.snapshot().capacity.reservedEvents,capacity.reservedEvents+6);
  assert.equal(core.canonicalEncode(new DirectoryHistoryStore(f.store.path).snapshot().history.head),core.canonicalEncode(r.head));
  assert.equal(inspectContinuationDutyPolicy(f.store.snapshot().history,'duty').policy.dutyDisposition,'OPEN');
  assert.equal(inspectContinuationAttempts(f.store.snapshot().history).attempts[0].duty.disposition.version,'continuity-attempt-duty-view/1');
  assert.equal(observeContinuationHistory(f.store.snapshot().history).eventCount,after.length);
});

test('E6 remains E6; old complete-history readers refuse while the identified prefix stays verifiable',async t=>{
  const f=await dutyFixture(t,{policy:'E6'});f.grant();const before=f.owner.exportHistory();
  assert.equal(oldCore.replayPortable({operationVersion:oldCore.PORTABLE_REPLAY_VERSION,events:before}).status,'ACCEPTED');
  await f.duties.activate(f.input);const events=f.owner.exportHistory(),head=f.store.snapshot().history.head;
  assert.equal(events[0].data.adapterPolicyHash,core.PORTABLE_ADAPTER_POLICY_E6_HASH);
  assert.equal(oldCore.replayPortable({operationVersion:oldCore.PORTABLE_REPLAY_VERSION,events}).status,'REJECTED');
  assert.throws(()=>oldHistory.captureContinuationHistory({operationVersion:oldHistory.CONTINUATION_HISTORY_VERSION,events,expectedHead:head}));
  const old=oldHistory.captureContinuationHistory({operationVersion:oldHistory.CONTINUATION_HISTORY_VERSION,events:before,expectedHead:capture(before).head});
  assert.deepEqual(old.head,capture(before).head);
  assert.equal(core.canonicalEncode(oldCore.replayPortable({operationVersion:oldCore.PORTABLE_REPLAY_VERSION,events:before})),core.canonicalEncode(core.replayPortable({operationVersion:core.PORTABLE_REPLAY_VERSION,events:before})));
});

test('current queries disclose the activated policy and old disclosure requests refuse explicitly',async t=>{
  const f=await dutyFixture(t);f.grant();await f.duties.activate(f.input);
  const events=f.owner.exportHistory(),observation=observeContinuationHistory(f.store.snapshot().history);
  const survives=observation.survives('worker');assert.equal(survives.epistemicStatus,'ESTABLISHED',JSON.stringify(survives));
  assert.equal(survives.answer.attemptDuties[0].currentView.dutyDisposition,'OPEN');
  assert.equal(Object.hasOwn(survives.answer.attemptDuties[0],'status'),false);
  assert.equal(survives.scope.recognizedExtensions[0].version,'continuity-attempt-disposition/1');
  const old=core.survivesPortable({operationVersion:core.PORTABLE_QUERY_VERSION,observedEvents:events,targetAgentId:'worker',evaluationTime:100,disclosure:core.portablePublicQueryDisclosure('SURVIVES')});
  assert.equal(old.code,'DISCLOSURE_INVALID');
  const admission=events.find(e=>e.type==='TRANSACTION_INTENT_ADMITTED'),proof=admission.data.authorizationProof;
  const binding=Object.fromEntries(['runtimeSessionId','credentialKeyId','controlEpoch','roleId','roleTenureId','intentId','nonce'].map(key=>[key,proof[key]]));
  const responsible=core.responsiblePortable({operationVersion:core.PORTABLE_QUERY_VERSION,
    evaluationEvents:events.slice(0,proof.historyHead.position+1),observedEvents:events,
    authorizationDomain:f.options.domain,request:proof.request,evaluationTime:proof.evaluationTime,
    consequentialBinding:{...binding,runtimeSignature:admission.data.runtimeSignature},disclosure:core.portablePublicQueryDisclosure('RESPONSIBLE',[core.DUTY_POLICY_VERSION])});
  assert.equal(responsible.epistemicStatus,'ESTABLISHED',JSON.stringify(responsible));
  assert.equal(responsible.answer.attemptDuties[0].currentView.policy.descriptor.dutyId,'duty');
});

test('exact activation retry survives retirement without another signature; changed operation and second activation refuse',async t=>{
  const f=await dutyFixture(t);f.grant();const first=await f.duties.activate(f.input);
  f.owner.advanceEpoch({agent:'worker',from:1,to:2});f.owner.revoke('activation');
  const repeated=await openLocalDutyPolicy(f.options).activate(f.input);
  assert.equal(repeated.eventId,first.eventId);assert.equal(repeated.alreadyRecorded,true);assert.equal(f.calls,1);
  assert.notEqual(repeated.head.hash,first.head.hash);
  await assert.rejects(f.duties.activate({...f.input,activationAuthority:'different'}),e=>e.code==='OPERATION_CONFLICT');
  await assert.rejects(f.duties.activate({...f.input,id:'second'}));assert.equal(f.calls,1);
});

test('the segmented host API rejects managed96 and executable selection input',async t=>{
  const f=await fixture(t,{policy:'E5'});assert.throws(()=>openLocalDutyPolicy(f.options),e=>e.code==='PROFILE_MISMATCH');
  const x=await dutyFixture(t);let reads=0;
  assert.throws(()=>x.duties.describe({duty:'duty',get incidentSourceDigest(){reads++;return digest},attesterRole:'role'}));assert.equal(reads,0);
  await assert.rejects(x.duties.activate({...x.input,unexpected:undefined}));assert.equal(x.calls,0);
  assert.throws(()=>inspectContinuationDutyPolicy({...x.store.snapshot().history},'duty'),e=>e.code==='INVALID_HISTORY_HANDLE');
});

test('activation requires the exact live dedicated grant before requesting a signature',async t=>{
  const variants=[
    ['missing',null],['broad-action',{actions:['ACTIVATE_DUTY_POLICY','other']}],
    ['broad-resource',{resources:['wrong']}],['multiple-resources',{resources:null}],
    ['capped',{maxTransactions:1}],['amount-capped',{maxAmount:1n}],
    ['expired',{expiresAt:100}],['future',{notBefore:101}],['wrong-grantee',{to:'replacement'}],
  ];
  for(const [name,changes] of variants)await t.test(name,async t=>{
    const f=await dutyFixture(t);
    if(changes)f.grant(name==='multiple-resources'?{resources:[f.selection.activationResource,'other']}:changes);
    const before=f.store.snapshot().revision;
    await assert.rejects(f.duties.activate(f.input));assert.equal(f.calls,0);assert.deepEqual(f.store.snapshot().revision,before);
  });
  await t.test('revoked',async t=>{const f=await dutyFixture(t);f.grant();f.owner.revoke('activation');await assert.rejects(f.duties.activate(f.input));assert.equal(f.calls,0)});
  await t.test('wrong-selected-grant',async t=>{const f=await dutyFixture(t);f.grant();await assert.rejects(f.duties.activate({...f.input,activationAuthority:'record'}));assert.equal(f.calls,0)});
});

test('descriptor source facts and fixed rule identity cannot be substituted',async t=>{
  for(const key of ['rulesHash','domain','genesisHash','baseAdapterPolicyHash','dutyId','dutyCreationEventId','dutyRecordHash','sourceIntentId','sourceAdmissionEventId','durableRoleId','principalId','acceptedAttesterRoleId','dispositionLimit','contestLimit'])await t.test(key,async t=>{
    const f=await dutyFixture(t),d=mutable(f.selection.descriptor);
    if(key==='domain')d.domain={...d.domain,deploymentId:'other'};
    else if(key.endsWith('Hash'))d[key]='0x'+'b'.repeat(64);
    else if(key.endsWith('Limit'))d[key]=0;
    else d[key]='other';
    // Even an exact grant for the forged descriptor cannot alter source facts or fixed semantics.
    f.grant({resources:['duty-policy:'+core.hashCanonical(d)]});
    await assert.rejects(f.duties.activate({...f.input,descriptor:d}));assert.equal(f.calls,0);
  });
});

test('same-Pincipal attester selection allows an internal reviewer Role but never creates new authority',async t=>{
  const f=await dutyFixture(t);f.owner.createRole({id:'reviewer'});
  const selection=f.duties.describe({duty:'duty',incidentSourceDigest:digest,attesterRole:'reviewer'});
  f.grant({resources:[selection.activationResource]});
  await f.duties.activate({...f.input,descriptor:selection.descriptor});
  assert.equal(stateOf(f.owner.exportHistory()).attemptDutyPolicies.get('duty').descriptor.acceptedAttesterRoleId,'reviewer');
  assert.equal(f.owner.exportHistory().filter(e=>e.type==='AUTHORITY_GRANTED').length,f.events.filter(e=>e.type==='AUTHORITY_GRANTED').length+1);
});

test('wrong Principal, delegable or delegated roots, and active prohibitions cannot activate a duty',async t=>{
  for(const kind of ['wrong-principal','delegable','delegated','prohibited','intersection','capped-winner','alternate-winner'])await t.test(kind,async t=>{
    const f=await dutyFixture(t),base=mutable(f.events.find(e=>e.type==='AUTHORITY_GRANTED').data.grant);
    const grant={...base,authorityId:'activation',rootAuthorityId:'activation',constraints:{...base.constraints,
      actions:[f.selection.activationAction],resources:[f.selection.activationResource],maxDelegationDepth:0}};
    delete grant.constraints.maxTransactions;
    if(kind==='wrong-principal'){
      f.append('foreign','PRINCIPAL_CREATED',{principalId:'foreign'});grant.grantorId='foreign';
    }
    if(kind==='delegable')grant.constraints.maxDelegationDepth=1;
    if(kind==='delegated'){
      f.append('parent','AUTHORITY_GRANTED',{grant:{...grant,authorityId:'parent',rootAuthorityId:'parent',granteeId:'replacement',constraints:{...grant.constraints,maxDelegationDepth:1}}});
      grant.grantorId='replacement';grant.parentAuthorityId='parent';grant.rootAuthorityId='parent';
    }
    if(kind==='intersection'){
      f.append('intersection','AUTHORITY_GRANTED',{grant:{...grant,authorityId:'intersection',rootAuthorityId:'intersection',constraints:{...grant.constraints,actions:['different']}}});
      grant.constraints.requiredIntersectionIds=['intersection'];
    }
    if(kind==='capped-winner'||kind==='alternate-winner'){
      f.append('a-winner','AUTHORITY_GRANTED',{grant:{...grant,authorityId:'a-winner',rootAuthorityId:'a-winner',constraints:{...grant.constraints,...(kind==='capped-winner'?{maxTransactions:1}:{})}}});
    }
    f.append('activation-grant','AUTHORITY_GRANTED',{grant});
    if(kind==='prohibited')f.append('prohibition','AUTHORITY_GRANTED',{grant:{kind:'PROHIBITION',scope:'GLOBAL',authorityId:'prohibition',grantorId:f.events[0].data.globalPolicySourceId,subjectActorId:'worker',constraints:grant.constraints}});
    await assert.rejects(f.duties.activate(f.input));assert.equal(f.calls,0);
    assert.equal(stateOf(f.owner.exportHistory()).attemptDutyPolicies.size,0);
  });
});

test('retired runtime, changed Role tenure and owner-string substitution cannot activate',async t=>{
  for(const kind of ['epoch','tenure','owner'])await t.test(kind,async t=>{
    const f=await dutyFixture(t);f.grant();
    if(kind==='epoch')f.owner.advanceEpoch({agent:'worker',from:1,to:2});
    if(kind==='tenure')f.owner.succeed({id:'replace',rule:'succession',fromAgent:'worker',fromTenure:'tenure',toAgent:'replacement',toTenure:'tenure:2',role:'role',number:2});
    if(kind==='owner')assert.throws(()=>openLocalDutyPolicy({...f.options,owner:'foreign'}),e=>e.code==='PROFILE_MISMATCH');
    else await assert.rejects(f.duties.activate(f.input));
    assert.equal(f.calls,0);
  });
});

test('post-sign checks allow forward time, reject expiry/regression and preserve the original signed timestamp',async t=>{
  for(const [name,at,success] of [['forward',101,true],['grant-expiry',1000,false],['session-expiry',10000,false],['regression',99,false]])await t.test(name,async t=>{
    let f;f=await dutyFixture(t,{sign:async h=>{assert.equal(existsSync(join(f.store.path,'.writer-lock')),false);f.setTime(at);return signHash(h)}});f.grant({expiresAt:name==='session-expiry'?20000:1000});
    if(success){await f.duties.activate(f.input);assert.equal(f.owner.exportHistory().at(-1).timestamp,100)}
    else{const before=f.store.snapshot().revision;await assert.rejects(f.duties.activate(f.input));assert.deepEqual(f.store.snapshot().revision,before)}
    assert.equal(f.calls,1);
  });
});

test('a concurrent append during signing conflicts; request mutation cannot change the captured effect',async t=>{
  let f;f=await dutyFixture(t,{sign:async h=>{f.owner.createAgent({id:'unrelated'});return signHash(h)}});f.grant();
  await assert.rejects(f.duties.activate(f.input),e=>e.code==='HISTORY_CONFLICT');assert.equal(stateOf(f.owner.exportHistory()).attemptDutyPolicies.size,0);
  let x,input;x=await dutyFixture(t,{sign:async h=>{input.descriptor.dutyId='mutated';return signHash(h)}});x.grant();input=mutable(x.input);
  await x.duties.activate(input);assert.equal(stateOf(x.owner.exportHistory()).attemptDutyPolicies.has('duty'),true);
});

test('failed signer, invalid signature, and unsupported future events cannot append',async t=>{
  for(const signer of [async()=>{throw Error('offline')},async()=>`0x${'0'.repeat(130)}`]){
    const f=await dutyFixture(t,{sign:signer});f.grant();const before=f.store.snapshot().revision;await assert.rejects(f.duties.activate(f.input));assert.deepEqual(f.store.snapshot().revision,before);
  }
  const f=await dutyFixture(t);f.grant();await f.duties.activate(f.input);
  for(const type of ['ATTEMPT_DUTY_DISPOSITION_RECORDED','ATTEMPT_DUTY_CONTEST_RECORDED']){
    const before=f.store.snapshot().revision;assert.throws(()=>f.append('future:'+type,type,{dutyId:'duty'}));assert.deepEqual(f.store.snapshot().revision,before);
  }
  assert.throws(()=>prepareContinuationAdministration(f.store.snapshot().history,{expectedDomain:f.options.domain,expectedHistoryHead:f.store.snapshot().history.head,runtimeSessionId:'session',transition:event('future','ATTEMPT_DUTY_DISPOSITION_RECORDED',{dutyId:'duty',actorId:'worker'})}));
});
