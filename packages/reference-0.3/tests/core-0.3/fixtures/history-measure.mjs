// Reproducible synthetic full-history measurements, not worst-case latency bounds.
import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import * as core from '../../../packages/core-0.2/src/core/index.ts';
import * as h from '../../../packages/core-0.3/src/history.ts';
import {fixture,capture,padded,authArgs,signHash} from './history-fixture.mjs';
const rows=[],fixtures=[];
async function measure(name,fn){const start=performance.now();try{const result=await fn();rows.push({name,ms:Math.round((performance.now()-start)*100)/100,rssBytes:process.memoryUsage().rss,...(result?.status?{status:result.status}:{}),...(result?.epistemicStatus?{epistemicStatus:result.epistemicStatus}:{}),...(result?.code?{code:result.code}:{})});return result}catch(error){rows.push({name,error:String(error),ms:performance.now()-start});throw error}}
async function setup(options){const f=await fixture(undefined,options);fixtures.push(f);return f}
try{
 const f=await setup({policy:'E6'}),wide=process.argv.includes('--wide');
 const events=padded(f.events,1023,{wide});
 const view=await measure('capture_and_full_genesis_replay',()=>capture(events));
 const authority=await measure('spent_authority_evaluation',()=>h.authorizeContinuation(view,authArgs(events)).result);
 if(wide){
  assert.equal(authority.decision,'INDETERMINATE');assert.equal(authority.code,'OUTPUT_LIMIT_EXCEEDED');
  for(const kind of ['WHY','RESPONSIBLE','SURVIVES'])await measure('near_byte_limit_two_history_'+kind,()=>h.queryContinuation(kind,view,view,{evaluationTime:100,disclosure:core.portablePublicQueryDisclosure(kind),...(kind==='SURVIVES'?{targetAgentId:'worker'}:{authorizationDomain:f.config.domain,request:authArgs(events).request})}).result);
  const receiptCase=await setup(),receiptEvents=padded(receiptCase.events,1023,{wide:true}),receiptView=capture(receiptEvents);
  await measure('near_byte_limit_two_history_receipt_verification',()=>h.verifyContinuationReceipt(receiptView,receiptView,{artifact:receiptCase.receipt.artifact,expectedDomain:receiptCase.config.domain,verifierTime:100}).result);
  console.log(JSON.stringify({runtime:process.version,platform:process.platform,arch:process.arch,wide,profile:h.CONTINUATION_PROFILE,eventCount:view.eventCount,metrics:view.metrics,maxRssKiB:process.resourceUsage().maxRSS,authority,rows},null,2));
 }else{
  assert.equal(authority.decision,'DENY');
  const duty=f.events.at(-1),before=capture(padded(f.events.slice(0,-1),1023));
  const {administrativeAuthorization:_old,...data}=duty.data;
  const created=await measure('signed_attempt_duty_creation_at_1023',async()=>h.produceContinuationAdministration(before,{expectedDomain:f.config.domain,expectedHistoryHead:before.head,runtimeSessionId:'session',transition:{...duty,data}},{signHash}));
  const after=await measure('prospective_full_replay_to_1024',()=>h.appendContinuationEvent(before,created.result.event));
  for(const kind of ['WHY','RESPONSIBLE','SURVIVES'])await measure('historical_query_'+kind,()=>h.queryContinuation(kind,before,after,{evaluationTime:100,disclosure:core.portablePublicQueryDisclosure(kind),...(kind==='SURVIVES'?{targetAgentId:'worker'}:{authorizationDomain:f.config.domain,request:authArgs(events).request})}).result);
  const r=await setup(),later=capture(padded(r.events,1024));
  await measure('original_receipt_verification_at_1024',()=>{const result=h.verifyContinuationReceipt(r.handle,later,{artifact:r.receipt.artifact,expectedDomain:r.config.domain,verifierTime:100}).result;assert.equal(result.historical,true);assert.equal(result.canonicalInclusion.status,'PASS');return result});
  r.owner.grant({id:'followup',to:'worker',actions:['followup'],resources:['incident'],expiresAt:10000,maxTransactions:1});
  const prior=r.owner.exportHistory(),declaration=prior.find(e=>e.type==='TRANSACTION_INTENT_DECLARED');
  let admissionView=capture(padded(prior,1022));
  admissionView=h.appendContinuationEvent(admissionView,{...declaration,id:'declaration:followup',data:{...declaration.data,intentId:'followup',nonce:'operation:followup',action:'followup'}});
  const binding={runtimeSessionId:'session',credentialKeyId:'key',controlEpoch:1,roleId:'role',roleTenureId:'tenure',intentId:'followup',nonce:'operation:followup'};
  const args={domain:r.config.domain,request:{actorId:'worker',action:'followup',resource:'incident',claimedAt:100,termsCommitment:r.op.termsCommitment},evaluationTime:100,policyVersion:prior[0].data.policyVersion,binding};
  await measure('signed_next_admission_at_1023',async()=>{const signature=await signHash(core.hashPortableRuntimeAuthorizationChallenge(h.continuationRuntimeChallenge(admissionView,args).result));const result=h.proposeContinuationAdmission(admissionView,{...args,admissionEventId:'admit:followup',binding:{...binding,runtimeSignature:signature}}).result;assert.equal(result.status,'PROPOSED');return result});
  console.log(JSON.stringify({runtime:process.version,platform:process.platform,arch:process.arch,wide,profile:h.CONTINUATION_PROFILE,eventCount:view.eventCount,metrics:view.metrics,maxRssKiB:process.resourceUsage().maxRSS,rows},null,2));
 }
}catch(error){console.error(JSON.stringify({error:String(error),rows},null,2));process.exitCode=1}finally{for(const f of fixtures)f.cleanup()}
