import {test} from 'node:test';
import assert from 'node:assert/strict';
import * as core from '../../packages/core-0.2/src/core/index.ts';
import * as h from '../../packages/core-0.3/src/history.ts';
import {prepareAdministrativeEvent,produceAdministrativeEvent} from '../../packages/core-0.2/src/administration/index.ts';
import {stateOf} from '../../packages/core-0.3/src/local-store.ts';
import {captureHistory} from '../../packages/core-0.3/src/observation.ts';
import {fixture,capture,padded,authArgs,signHash} from './fixtures/history-fixture.mjs';
const code=c=>e=>e.code===c;

test('captured history is immutable, exact-head bound and preserves every prefix',async t=>{
 const f=await fixture(t),events=padded(f.events,320),view=capture(events);
 assert.equal(view.eventCount,320);assert.equal(view.executionCapability,false);
 assert.equal(view.head.hash,core.hashEventHistory(events));
 for(const position of [0,1,f.events.length-1,95,127,255,319])assert.equal(h.continuationPrefix(view,position).head.hash,core.hashEventHistory(events.slice(0,position+1)));
 events.at(-1).data.principalId='changed';assert.equal(h.exportContinuationEvents(view).at(-1).data.principalId,'extra:319');
 assert.throws(()=>h.exportContinuationEvents(view).push({}));
 assert.throws(()=>h.captureContinuationHistory({operationVersion:h.CONTINUATION_HISTORY_VERSION,events:f.events,expectedHead:{...f.handle.head,hash:'0x'+'0'.repeat(64)}}),code('HEAD_MISMATCH'));
 assert.throws(()=>captureHistory(h.exportContinuationEvents(view)),code('HISTORY_LIMIT'));
});
test('copied, forged, foreign-module and serialized handles never acquire state authority',async t=>{
 const f=await fixture(t);let reads=0;const hostile=new Proxy({}, {get(){reads++;throw Error('read')}});
 for(const fake of [{...f.handle},JSON.parse(JSON.stringify(f.handle)),{},null,hostile]){
  assert.throws(()=>h.authorizeContinuation(fake,hostile),code('INVALID_HISTORY_HANDLE'));
  await assert.rejects(h.produceContinuationAdministration(fake,hostile,hostile),code('INVALID_HISTORY_HANDLE'));
 }
 const foreign=await import('../../packages/core-0.2/src/history/index.ts?foreign-test');
 const other=foreign.captureContinuationHistory({operationVersion:h.CONTINUATION_HISTORY_VERSION,events:f.events,expectedHead:f.handle.head});
 assert.throws(()=>h.exportContinuationEvents(other),code('INVALID_HISTORY_HANDLE'));assert.equal(reads,0);
});
test('one captured input preserves getter values, rejects omitted undefined and sparse histories',async t=>{
 const f=await fixture(t);let reads=0;const events=[...f.events];const original=events[2];
 events[2]={...original,get data(){reads++;return reads===1?original.data:{agentId:'forged'}}};
 const view=h.captureContinuationHistory({operationVersion:h.CONTINUATION_HISTORY_VERSION,events,expectedHead:f.handle.head});assert.equal(reads,1);assert.equal(view.head.hash,f.handle.head.hash);
 const bad=[...f.events];bad[2]={...original,hidden:undefined};assert.throws(()=>capture(bad),code('INVALID_INPUT'));
 const sparse=[...f.events];delete sparse[2];assert.throws(()=>h.captureContinuationHistory({operationVersion:h.CONTINUATION_HISTORY_VERSION,events:sparse,expectedHead:f.handle.head}));
});
test('authorization and all three queries preserve old results on common prefixes',async t=>{
 const f=await fixture(t);const args=authArgs(f.events);
 assert.deepEqual(h.authorizeContinuation(f.handle,args).result,core.authorizePortable({...args,operationVersion:core.PORTABLE_AUTHORIZATION_VERSION,events:f.events,expectedHistoryHead:f.handle.head}));
 for(const kind of ['WHY','RESPONSIBLE','SURVIVES']){
  const extra=kind==='SURVIVES'?{targetAgentId:'worker'}:{authorizationDomain:f.config.domain,request:args.request};
  const input={...extra,evaluationTime:100,disclosure:core.portablePublicQueryDisclosure(kind)};
  const fn=kind==='WHY'?core.whyPortable:kind==='RESPONSIBLE'?core.responsiblePortable:core.survivesPortable;
  assert.deepEqual(h.queryContinuation(kind,f.handle,f.handle,input).result,fn({...input,operationVersion:core.PORTABLE_QUERY_VERSION,evaluationEvents:f.events,observedEvents:f.events}));
 }
});
test('spent authority and revoked authority remain denied after 1024-event replay',async t=>{
 const f=await fixture(t),events=padded(f.events,1024),view=capture(events);
 for(const action of ['inspect','export']){
  const result=h.authorizeContinuation(view,authArgs(events,action)).result;assert.equal(result.decision,'DENY');
 }
 const copied={...events.at(-1),id:'new-event',data:{principalId:'another'}};
 assert.throws(()=>h.appendContinuationEvent(view,copied),code('HISTORY_LIMIT'));
 assert.throws(()=>capture(padded(f.events,1025)),code('HISTORY_LIMIT'));
});
test('historical queries and recorded receipts remain independently verifiable beyond 256',async t=>{
 const f=await fixture(t),later=capture(padded(f.events,320));
 const artifact=f.receipt.artifact;assert.ok(artifact);
 const input={artifact,expectedDomain:f.config.domain,verifierTime:100};
 const verified=h.verifyContinuationReceipt(f.handle,later,input).result;
 assert.equal(verified.status,'EVALUATED');assert.equal(verified.historical,true);
 const why=h.queryContinuation('WHY',f.handle,later,{authorizationDomain:f.config.domain,request:authArgs(f.events).request,evaluationTime:100,disclosure:core.portablePublicQueryDisclosure('WHY')}).result;
 assert.equal(why.scope.headRelationship,'STRICT_EXTENSION');
 assert.equal(why.scope.freshness,'AT_EVALUATION');
});
test('new administrative path signs duty observations after 256; old128 boundary stays closed',async t=>{
 const f=await fixture(t,{policy:'E5'}),view=capture(padded(f.events,320));
 const admission=f.events.find(e=>e.type==='TRANSACTION_INTENT_ADMITTED');
 const identity=stateOf(f.events).intentAdmissions.get('job').adapterIdentity;
 const ack=core.createRemoteServiceReportAcknowledgment(identity,'0x'+'b'.repeat(64));
 const input={expectedDomain:f.config.domain,expectedHistoryHead:view.head,runtimeSessionId:'session',transition:{id:'late-report',type:'OUTCOME_OBSERVATION_RECORDED',timestamp:100,
  data:{intentId:'job',sourceAdmissionEventId:admission.id,acknowledgment:ack,actorId:'worker'}}};
 assert.throws(()=>prepareAdministrativeEvent({...input,events:h.exportContinuationEvents(view)}),e=>e.code==='INPUT_LIMIT');
 const produced=(await h.produceContinuationAdministration(view,input,{signHash})).result;
 const next=h.appendContinuationEvent(view,produced.event);assert.equal(next.eventCount,321);
 const answer=h.queryContinuation('SURVIVES',next,next,{targetAgentId:'worker',evaluationTime:100,disclosure:core.portablePublicQueryDisclosure('SURVIVES')}).result;
 assert.equal(answer.epistemicStatus,'ESTABLISHED');assert.equal(answer.answer.attemptDuties[0].status,'OPEN');
});


test('fresh runtime admission after 256 binds original domain, nonce and exact head',async t=>{
 const f=await fixture(t);f.owner.grant({id:'followup',to:'worker',actions:['followup'],resources:['incident'],expiresAt:10000,maxTransactions:1});
 const prior=f.owner.exportHistory(), declaration=prior.find(e=>e.type==='TRANSACTION_INTENT_DECLARED');
 let view=capture(padded(prior,320));
 view=h.appendContinuationEvent(view,{...declaration,id:'declaration:followup',data:{...declaration.data,intentId:'followup',nonce:'operation:followup',action:'followup'}});
 const binding={runtimeSessionId:'session',credentialKeyId:'key',controlEpoch:1,roleId:'role',roleTenureId:'tenure',intentId:'followup',nonce:'operation:followup'};
 const args={domain:f.config.domain,request:{actorId:'worker',action:'followup',resource:'incident',claimedAt:100,termsCommitment:f.op.termsCommitment},evaluationTime:100,policyVersion:prior[0].data.policyVersion,binding};
 const challenge=h.continuationRuntimeChallenge(view,args).result;
 const signature=await signHash(core.hashPortableRuntimeAuthorizationChallenge(challenge));
 const input={...args,admissionEventId:'admit:followup',binding:{...binding,runtimeSignature:signature}};
 const proposed=h.proposeContinuationAdmission(view,input).result;assert.equal(proposed.status,'PROPOSED');
 const next=h.appendContinuationEvent(view,proposed.admissionEvent);assert.equal(next.eventCount,322);
 const repeat=h.proposeContinuationAdmission(next,input).result;assert.equal(repeat.status,'RETRY');
 const changed=h.proposeContinuationAdmission(view,{...input,request:{...args.request,resource:'elsewhere'}}).result;assert.notEqual(changed.status,'PROPOSED');
 const drift=h.appendContinuationEvent(view,{id:'intervening',type:'PRINCIPAL_CREATED',timestamp:100,data:{principalId:'intervening'}});
 assert.notEqual(h.proposeContinuationAdmission(drift,input).result.status,'PROPOSED');
});

test('create and record a new receipt above 256, then verify its original prefix',async t=>{
 const f=await fixture(t,{recordReceipt:false}),view=capture(padded(f.events,320));let calls=0;
 const artifact=(await h.createContinuationReceipt(view,{intentId:'job',issuedAt:100,externalOutcome:'SIMULATED'},{keyId:'key',signHash:async hash=>{calls++;return signHash(hash)}})).result;
 assert.equal(calls,1);const input={artifact,expectedDomain:f.config.domain,recordEventId:'receipt:late'};
 const proposal=h.proposeContinuationReceiptRecord(view,input).result;assert.equal(proposal.status,'PROPOSED');
 const next=h.appendContinuationEvent(view,proposal.recordEvent);
 assert.equal(h.verifyContinuationReceipt(next,next,{artifact,expectedDomain:f.config.domain,verifierTime:100}).result.current,true);
 const later=h.appendContinuationEvent(next,{id:'later',type:'PRINCIPAL_CREATED',timestamp:101,data:{principalId:'later'}});
 const verification=h.verifyContinuationReceipt(next,later,{artifact,expectedDomain:f.config.domain,verifierTime:101}).result;
 assert.equal(verification.historical,true);assert.equal(verification.canonicalInclusion.status,'PASS');
});

test('E6 evidence review after 256 keeps the unresolved duty OPEN',async t=>{
 const f=await fixture(t,{policy:'E6'}),view=capture(padded(f.events,320));
 const input={expectedDomain:f.config.domain,expectedHistoryHead:view.head,runtimeSessionId:'session',transition:{id:'review:late',type:'ATTEMPT_DUTY_REVIEW_CLOSED',timestamp:100,
  data:{dutyId:'duty',actorId:'worker',observationEventIds:[],summaryDigest:'0x'+'a'.repeat(64)}}};
 const produced=(await h.produceContinuationAdministration(view,input,{signHash})).result;
 const next=h.appendContinuationEvent(view,produced.event);
 const answer=h.queryContinuation('SURVIVES',next,next,{targetAgentId:'worker',evaluationTime:100,disclosure:core.portablePublicQueryDisclosure('SURVIVES')}).result;
 assert.equal(answer.epistemicStatus,'ESTABLISHED');assert.equal(answer.answer.attemptDuties[0].status,'OPEN');assert.equal(answer.answer.attemptDuties[0].reviewStatus,'REVIEW_CLOSED');
});

test('overfull/oversize signed events refuse before signer invocation',async t=>{
 const f=await fixture(t,{policy:'E6'}),view=capture(padded(f.events,1024));let calls=0;
 const input={expectedDomain:f.config.domain,expectedHistoryHead:view.head,runtimeSessionId:'session',transition:{id:'review:late',type:'ATTEMPT_DUTY_REVIEW_CLOSED',timestamp:100,
  data:{dutyId:'duty',actorId:'worker',observationEventIds:[],summaryDigest:'0x'+'a'.repeat(64)}}};
 await assert.rejects(h.produceContinuationAdministration(view,input,{signHash:async hash=>{calls++;return signHash(hash)}}),code('HISTORY_LIMIT'));assert.equal(calls,0);
 const events=[...f.events,{id:'oversize',type:'PRINCIPAL_CREATED',timestamp:100,data:{principalId:'x'.repeat(9000)}}];
 assert.throws(()=>h.captureContinuationHistory({operationVersion:h.CONTINUATION_HISTORY_VERSION,events,expectedHead:f.handle.head}),code('EVENT_LIMIT'));
});

test('administrative parity on a common prefix and changing input during signing',async t=>{
 const f=await fixture(t,{policy:'E6'});
 const input={expectedDomain:f.config.domain,expectedHistoryHead:f.handle.head,runtimeSessionId:'session',transition:{id:'review:common',type:'ATTEMPT_DUTY_REVIEW_CLOSED',timestamp:100,
  data:{dutyId:'duty',actorId:'worker',observationEventIds:[],summaryDigest:'0x'+'a'.repeat(64)}}};
 assert.deepEqual(h.prepareContinuationAdministration(f.handle,input).result,prepareAdministrativeEvent({...input,events:f.events}));
 const normal=await produceAdministrativeEvent({...input,events:f.events},{signHash});
 const original=input.transition.data.summaryDigest;
 const produced=(await h.produceContinuationAdministration(f.handle,input,{signHash:async hash=>{input.transition.data.summaryDigest='0x'+'b'.repeat(64);return signHash(hash)}})).result;
 assert.deepEqual(produced,normal);assert.equal(produced.event.data.summaryDigest,original);
});


test('signed obligation and attempt duty creation fit at 1023 events without resetting provenance',async t=>{
 const normal=await fixture(t);
 const {openLocalRuntime}=await import('../../packages/core-0.3/src/runtime.ts');
 await openLocalRuntime(normal.options).obligate({id:'obligation',operation:'job',description:'Complete investigation',deadline:10000,succession:'succession',reviewAuthority:'record'});
 const obligation=normal.owner.exportHistory().at(-1);
 const attempt=await fixture(t,{policy:'E6'}),duty=attempt.events.at(-1);
 for(const [f,event,prior] of [[normal,obligation,normal.events],[attempt,duty,attempt.events.slice(0,-1)]]){
  const view=capture(padded(prior,1023));
  const {administrativeAuthorization:_old,...originalData}=event.data;
  const data={...originalData,record:{...originalData.record,description:'Investigation '.padEnd(1024,'x')}};
  const input={expectedDomain:f.config.domain,expectedHistoryHead:view.head,runtimeSessionId:'session',transition:{...event,data}};
  const result=(await h.produceContinuationAdministration(view,input,{signHash})).result;
  const next=h.appendContinuationEvent(view,result.event);assert.equal(next.eventCount,1024);
  assert.equal(result.event.data.administrativeAuthorization.challenge.eventHistoryHash,view.head.hash);
  const answer=h.queryContinuation('SURVIVES',next,next,{targetAgentId:'worker',evaluationTime:100,disclosure:core.portablePublicQueryDisclosure('SURVIVES')}).result;
  assert.equal(answer.epistemicStatus,'ESTABLISHED');
  assert.equal(event.type==='OBLIGATION_CREATED'?answer.answer.obligations[0].status:answer.answer.attemptDuties[0].status,'OPEN');
 }
});

test('event shape and total byte budgets refuse before a handle is minted',async t=>{
 const f=await fixture(t);
 const base={id:'shape',type:'PRINCIPAL_CREATED',timestamp:100,data:{principalId:'shape'}};
 let nested={};for(let i=0;i<18;i++)nested={next:nested};
 for(const extra of [{members:Array(33).fill(0)},nested,{members:Array(32).fill(Object.fromEntries(Array.from({length:10},(_,i)=>['a'+i,0])))}]){
  assert.throws(()=>h.captureContinuationHistory({operationVersion:h.CONTINUATION_HISTORY_VERSION,events:[...f.events,{...base,data:{...base.data,extra}}],expectedHead:f.handle.head}),code('EVENT_LIMIT'));
 }
 // Individually bounded synthetic records exceed the aggregate limit before semantic replay.
 const fat={...base,data:{a:'a'.repeat(3500),b:'b'.repeat(3500)}};
 assert.throws(()=>h.captureContinuationHistory({operationVersion:h.CONTINUATION_HISTORY_VERSION,events:Array.from({length:1000},(_,i)=>({...fat,id:'fat:'+i})),expectedHead:f.handle.head}),code('HISTORY_LIMIT'));
 const corrupted=[...f.events];corrupted[2]={...corrupted[2],type:'NOT_AN_EVENT'};
 assert.throws(()=>h.captureContinuationHistory({operationVersion:h.CONTINUATION_HISTORY_VERSION,events:corrupted,expectedHead:f.handle.head}),code('INVALID_HISTORY'));
});

test('wide denial graphs retain explicit output exhaustion; they never become permission',async t=>{
 const f=await fixture(t),events=padded(f.events,96,{wide:true}),view=capture(events);
 const result=h.authorizeContinuation(view,authArgs(events)).result;
 assert.equal(result.decision,'INDETERMINATE');assert.equal(result.code,'OUTPUT_LIMIT_EXCEEDED');
 assert.deepEqual(result,core.authorizePortable({...authArgs(events),operationVersion:core.PORTABLE_AUTHORIZATION_VERSION,events,expectedHistoryHead:view.head}));
});
