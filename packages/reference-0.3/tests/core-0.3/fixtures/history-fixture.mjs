import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createRequire} from 'node:module';
import * as core from '../../../packages/core-0.2/src/core/index.ts';
import {createLocalDomain,createLocalOwner,createLocalAttemptOwner,createLocalReviewOwner} from '../../../packages/core-0.3/src/local-owner.ts';
import {openLocalSimulation,commitTerms} from '../../../packages/core-0.3/src/simulation.ts';
import {openLocalExecution} from '../../../packages/core-0.3/src/execution.ts';
import {openLocalAttemptRecorder} from '../../../packages/core-0.3/src/attempts.ts';
import * as history from '../../../packages/core-0.3/src/history.ts';
const {privateKeyToAccount}=createRequire(import.meta.url)('viem/accounts');
// Known-public synthetic fixture credentials; never deployment credentials.
export const account=privateKeyToAccount('0x'+'11'.repeat(32));
export const signHash=hash=>account.signMessage({message:{raw:hash}});
export const capture=events=>history.captureContinuationHistory({operationVersion:history.CONTINUATION_HISTORY_VERSION,events,
 expectedHead:{hash:core.hashEventHistory(events),position:events.length-1,canonicalTime:events.at(-1).timestamp}});
export function padded(events,count,{wide=false}={}){
 const result=[...events],template=events.find(e=>e.type==='AUTHORITY_GRANTED');
 while(result.length<count){const i=result.length;
  result.push(wide?{...template,id:'wide:'+i,data:{grant:{...template.data.grant,authorityId:'wide:'+i,rootAuthorityId:'wide:'+i,
   constraints:{...template.data.grant.constraints,actions:['unrelated'],resources:Array.from({length:28},(_,j)=>('resource:'+i+':'+j+':').padEnd(200,'x'))}}}}:
  {id:'extra:'+i,type:'PRINCIPAL_CREATED',timestamp:100,data:{principalId:'extra:'+i}});
 }return result;
}
export async function fixture(t,{policy='SIMULATED',recordReceipt=true}={}){
 const dir=mkdtempSync(join(tmpdir(),'continuity-history-'));const cleanup=()=>rmSync(dir,{recursive:true,force:true});if(t)t.after(cleanup);
 const config={historyFile:join(dir,'history.jsonl'),domain:createLocalDomain(),owner:'owner',controller:'controller',now:()=>100};
 const owner=(policy==='E5'?createLocalAttemptOwner:policy==='E6'?createLocalReviewOwner:createLocalOwner)(config);
 owner.createAgent({id:'worker'});owner.createAgent({id:'replacement'});owner.createRole({id:'role'});
 owner.appoint({agent:'worker',role:'role',tenure:'tenure',number:1});owner.declareSuccession({id:'succession',from:'worker',to:'replacement',role:'role'});
 owner.admitRuntime({agent:'worker',session:'session',epoch:1,key:'key',address:account.address,expiresAt:10000});
 owner.grant({id:'work',to:'worker',actions:['inspect'],resources:['incident'],expiresAt:10000,maxTransactions:1});
 owner.grant({id:'record',to:'worker',actions:['OBLIGATE','ASSIGN_PERFORMANCE','record-collection-disposition','OBSERVE_OUTCOME','CREATE_ATTEMPT_DUTY','ASSIGN_ATTEMPT_DUTY','CLOSE_ATTEMPT_DUTY'],resources:['incident','job','duty'],expiresAt:10000});
 owner.grant({id:'revoked',to:'worker',actions:['export'],resources:['incident'],expiresAt:10000});owner.revoke('revoked');
 const options={...config,session:'session',signHash};
 const op={id:'job',action:'inspect',resource:'incident',role:'role',tenure:'tenure',termsCommitment:commitTerms({case:'synthetic'})};
 let runtime,result,receipt;
 if(policy==='SIMULATED'){
  runtime=openLocalSimulation(options);result=await runtime.run(op);if(recordReceipt)receipt=await runtime.recordReceipt(op);
 }else{
  const hash=policy==='E5'?core.PORTABLE_ADAPTER_POLICY_E5_HASH:core.PORTABLE_ADAPTER_POLICY_E6_HASH;
  const unknown=input=>{const i=core.derivePortableAdapterIdentity(input);return{status:'OUTCOME_UNKNOWN',idempotencyKey:i.idempotencyKey,submissionFingerprint:i.submissionFingerprint}};
  runtime=openLocalExecution(options,{adapterProfile:core.approvedPortableAdapterProfileForPolicy(hash,core.REMOTE_SERVICE_REPORT_ADAPTER_ID),submit:unknown,reconcile:unknown},'REMOTE_REPORT');
  result=await runtime.run(op);
  await openLocalAttemptRecorder(options).createDuty({id:'duty',intent:'job',description:'Investigate the unknown result',deadline:10000});
 }
 const events=owner.exportHistory();return{owner,config,options,op,runtime,result,receipt,events,handle:capture(events),cleanup};
}
export function authArgs(events,action='inspect'){
 return {domain:events[0].data.domain,policyVersion:events[0].data.policyVersion,rootRecognitionPolicy:core.PORTABLE_ROOT_RECOGNITION_POLICY,
  request:{actorId:'worker',action,resource:'incident',claimedAt:100},evaluationTime:100,authoritative:true,consequential:false};
}
