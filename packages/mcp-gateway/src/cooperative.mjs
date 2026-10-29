import {assertSynchronous} from './access-http-guard.mjs';
import {join} from 'node:path';
import {existsSync,readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {fromJsonSchema} from '@modelcontextprotocol/server';
import {createToolRegistry,createCooperativeClient,createCooperativeExecutor,createCooperativeRecovery} from '@ramex-labs/irontrellis-remote';
import {openLocalAttemptRecorder,inspectDutyPolicyState,observeState} from '@ramex-labs/irontrellis';
import {openConfiguredEventStore,createHistoryTransfer,canonicalEncode,openLocalExecution,deriveAdapterIdentity,admissionControlIsCurrent,evaluateReceiptPolicy,
 approvedAdapterProfileForPolicy,ADAPTER_POLICY_E5_HASH,REMOTE_SERVICE_REPORT_ADAPTER_ID,
 createRemoteServiceReportAcknowledgment,adapterAcknowledgmentEvidence} from '@ramex-labs/irontrellis/adapter';
import {check,data,exact,id,hash,same,privateDirectory,readPrivate,durableCreate} from './data.js';
import {operationIdentity,publicError} from './gateway.js';

const reserved=new Set(['irontrellis_status','irontrellis_why','irontrellis_recover','irontrellis_cancel','irontrellis_observe']);
const reportedState=result=>result.state==='TOO_LATE'?result.report:result;
const digest=value=>'0x'+createHash('sha256').update(canonicalEncode(value)).digest('hex');
export const cancellationIdentity=(domain,businessKey)=>'mcp-cancel:'+hash({version:'continuity-mcp-cancellation/1',domain,businessKey:id(businessKey)},'sha256').slice(2);

function schemaFor(tool){
 const properties={};
 for(const [name,type] of Object.entries(tool.fields))properties[name]=Array.isArray(type)?{type:'string',enum:type}:
  type==='amount'?{type:'string',pattern:'^(0|[1-9][0-9]{0,77})$'}:
  type==='integer'?{type:'integer',minimum:0,maximum:Number.MAX_SAFE_INTEGER}:
  type==='boolean'?{type:'boolean'}:{type:'string',minLength:1,maxLength:type==='text'?1024:128};
 return {type:'object',properties,required:Object.keys(properties),additionalProperties:false};
}

/** Trusted application configuration. The MCP caller sees only fixed jobs and recovery verbs. */
export async function createCooperativeGateway(options){
 const local={...options.local,domain:data(options.local.domain)},storage=privateDirectory(options.storage);
 const registry=createToolRegistry(data(options.registry)),client=createCooperativeClient(options.destination);
 check(options.destination.serviceId===registry.serviceId,'SERVICE_MISMATCH');
 const store=openConfiguredEventStore(local),jobs=new Map(),business=new Set();
 const read=()=>{const state=store.state();check(same(state.genesis.domain,local.domain),'PROFILE_MISMATCH');return state;};
 const initial=read();check(initial.format==='irontrellis-event/2','PROFILE_MISMATCH');check(initial.genesis.adapterPolicyHash===ADAPTER_POLICY_E5_HASH,'PROFILE_MISMATCH');
 const session=initial.runtimeSessions.get(local.session);check(session&&session.controllerId===local.controller,'RUNTIME_NOT_CURRENT');
 check(Array.isArray(options.operations)&&options.operations.length>0&&options.operations.length<=32);
 for(const raw of options.operations){
  const j=exact(data(raw),['name','tool','businessKey','role','tenure']);
  check(/^[A-Za-z][A-Za-z0-9_]{0,47}$/.test(j.name)&&!reserved.has(j.name)&&!jobs.has(j.name));
  for(const key of ['tool','businessKey','role','tenure'])id(j[key]);check(!business.has(j.businessKey));business.add(j.businessKey);
  const tool=registry.tools.find(t=>t.id===j.tool);check(tool,'UNKNOWN_TOOL');
  const inputSchema=schemaFor(tool);
  jobs.set(j.name,{...j,toolDefinition:tool,inputSchema,schema:fromJsonSchema(inputSchema),operationId:operationIdentity(local.domain,j.businessKey),cancelId:cancellationIdentity(local.domain,j.businessKey)});
 }
 function policy(job,action,resource=job.toolDefinition.resource,projection={}){
  const state=read(),at=local.now(),agent=state.agents.get(session.agentId),tenure=state.tenures.get(job.tenure);
  check(Number.isSafeInteger(at)&&at>=state.head.canonicalTime,'CLOCK_INVALID');
  check(agent&&!agent.terminated&&agent.currentControlEpoch===session.controlEpoch&&(session.expiresAt===undefined||at<session.expiresAt)&&
   state.roles.get(job.role)?.currentTenureId===job.tenure&&tenure&&!tenure.closed&&tenure.agentId===session.agentId,'RUNTIME_NOT_CURRENT');
  const decision=observeState(read(),{at}).authorize({actor:session.agentId,action,resource,...projection});
  check(decision.decision==='ALLOW','INSPECTION_DENIED');return decision;
 }
 const inspect=job=>policy(job,'inspect-operation');
 function dispatchPolicy(job,operationId=job.operationId){
  inspect(job);const state=read(),at=local.now(),admission=state.intentAdmissions.get(operationId);
  check(Number.isSafeInteger(at)&&at>=state.head.canonicalTime,'CLOCK_INVALID');
  check(admission&&admissionControlIsCurrent(state,operationId,at),'RUNTIME_NOT_CURRENT');
  const proof=state.events[admission.admissionEventPosition].data.authorizationProof;
  // Continue the original admitted path and its already-reserved budget. A
  // fresh ALLOW under a replacement grant cannot substitute for that proof.
  check(evaluateReceiptPolicy(state,proof,at).live,'INSPECTION_DENIED');
 }

 const lookup=name=>{const job=jobs.get(name);check(job,'UNKNOWN_TOOL');return job;};
 const requestPath=job=>join(storage,job.operationId+'.request.json');
 const normalize=(job,args)=>Object.fromEntries(Object.entries(args).map(([k,v])=>[k,job.toolDefinition.fields[k]==='amount'?BigInt(v):v]));
 const request=(job,args)=>({operationId:job.operationId,businessKey:job.businessKey,tool:job.tool,arguments:normalize(job,args)});
 const select=(job,args)=>registry.capture({intentId:job.operationId,businessKey:job.businessKey,tool:job.tool,arguments:normalize(job,args),contractId:registry.contractId});
 function original(job){
  const saved=exact(readPrivate(requestPath(job)),['version','domain','contractId','serviceId','operationId','businessKey','tool','arguments']);
  check(saved.version==='irontrellis-mcp-cooperative-job/1'&&same(saved.domain,local.domain)&&saved.contractId===registry.contractId&&saved.serviceId===registry.serviceId&&
   saved.operationId===job.operationId&&saved.businessKey===job.businessKey&&saved.tool===job.tool,'OPERATION_CONFLICT');
  const selected=select(job,saved.arguments),state=read(),intent=state.intentDeclarations.get(job.operationId)?.data;
  check(intent&&state.intentAdmissions.has(job.operationId),'ADMISSION_REQUIRED');
  check(intent.termsCommitment===selected.termsCommitment&&intent.action===selected.action&&intent.resource===selected.resource,'OPERATION_CONFLICT');
  return {saved,request:request(job,saved.arguments),selected,identity:state.intentAdmissions.get(job.operationId).adapterIdentity};
 }
 function validateReply(job,reply){
  const orig=original(job),checked=client.inspectResponse(reply.receipt,reply.receipt.body.requestDigest);
  check(same(checked,reply),'REPORT_MISMATCH');
  const report=reply.result.state==='TOO_LATE'?reply.result.report:reply.result;
  check(report.key===orig.identity.idempotencyKey,'REPORT_MISMATCH');
  if(['APPLIED','PENDING','CANCELLED'].includes(report.state))check(report.fingerprint===orig.identity.submissionFingerprint&&report.intentId===job.operationId&&
   report.tool===job.tool&&report.businessKey===job.businessKey&&report.contractId===registry.contractId,'REPORT_MISMATCH');
  else check(report.state==='UNKNOWN','REPORT_UNAVAILABLE');
  return {orig,report};
 }
 function reports(job,kind='status'){
  const all=readdirSync(storage);check(all.length<=4096,'REPORT_LIMIT');
  const prefix=job.operationId+'.'+kind+'.',files=all.filter(n=>n.startsWith(prefix));check(files.length<=16,'REPORT_LIMIT');
  const rows=files.map(n=>{
   const row=exact(readPrivate(join(storage,n)),['version','requestHash','reply']);
   const {orig}=validateReply(job,row.reply);check(row.version==='irontrellis-mcp-cooperative-report/1'&&row.requestHash===hash(orig.saved)&&
    n===prefix+hash(row.reply.result).slice(2)+'.json','STORAGE_UNAVAILABLE');return row.reply;
  });
  return rows.sort((a,b)=>a.sequence-b.sequence);
 }
 function retain(job,reply,kind='status'){
  const {orig}=validateReply(job,reply),prior=reports(job,kind),latest=prior.at(-1);
  // Status reads keep the service sequence but sign a fresh request digest.
  // TOO_LATE is a cancellation answer wrapping the same immutable APPLIED state.
  // Compare state at equal sequence, not request-specific receipt bytes.
  check(!latest||reply.sequence>latest.sequence||(reply.sequence===latest.sequence&&same(reportedState(reply.result),reportedState(latest.result))),'REPORT_ROLLBACK');
  const path=join(storage,job.operationId+'.'+kind+'.'+hash(reply.result).slice(2)+'.json');
  if(!existsSync(path)){check(prior.length<16,'REPORT_LIMIT');durableCreate(path,{version:'irontrellis-mcp-cooperative-report/1',requestHash:hash(orig.saved),reply});}
 }
 const checkedLocal=guard=>({...local,async signHash(h){assertSynchronous(guard);const signed=await local.signHash(h);assertSynchronous(guard);return signed;}});
 const profile=approvedAdapterProfileForPolicy(ADAPTER_POLICY_E5_HASH,REMOTE_SERVICE_REPORT_ADAPTER_ID);
 const ack=(identity,report)=>createRemoteServiceReportAcknowledgment(identity,digest(report));
 const investigation=job=>{
  const state=read();
  check(same(state.genesis.domain,local.domain),'PROFILE_MISMATCH');
  const duty=[...state.attemptDuties.entries()].find(([,value])=>value.record.sourceIntentId===job.operationId);
  if(!duty||!state.attemptDutyPolicies.has(duty[0]))return {};
  return {investigation:inspectDutyPolicyState(state,duty[0])};
 };
 const summary=(job,reply,status)=>({...investigation(job),status,operationId:job.operationId,serviceState:reply?.result.state??null,
  serviceReport:reply?.result??null,reportDigest:reply?digest(reply.result):null,externalOutcome:'NOT_PROVEN',
  dispatchPerformed:false,retryPolicy:'NO_AUTOMATIC_REDELIVERY',reportFreshness:'LAST_AUTHENTICATED_REPORT'});
 let busy=false,closed=false;
 async function locked(work){if(busy)return {status:'BUSY'};busy=true;try{check(!closed,'GATEWAY_UNAVAILABLE');return await work();}catch(error){return publicError(error);}finally{busy=false;}}
 async function recoverJob(job,guard){
  assertSynchronous(guard);inspect(job);const orig=original(job);
  const recovery=createCooperativeRecovery({local,client,registry});
  let recovered;try{assertSynchronous(guard);inspect(job);recovered=await recovery.lookup(orig.request);}finally{recovery.close();}
  // Keep an authenticated late reply before checking whether it can be disclosed.
  retain(job,recovered.serviceReport);assertSynchronous(guard);inspect(job);
  return summary(job,recovered.serviceReport,'RECOVERED');
 }
 return Object.freeze({
  tools:()=>[...jobs.values()].map(j=>({name:j.name,inputSchema:data(j.inputSchema),description:'Run one approved cooperating-service job. Repeating it only looks up the original attempt.',annotations:{readOnlyHint:false,destructiveHint:true,idempotentHint:true,openWorldHint:true}})),
  run(name,input,{assertCurrent=()=>{},onProgress=()=>{}}={}){return locked(async()=>{
   assertSynchronous(assertCurrent);const job=lookup(name),args=data(input),valid=await job.schema['~standard'].validate(args);check(!valid.issues,'INVALID_ARGUMENTS');assertSynchronous(assertCurrent);
   const selected=select(job,args),projection={...selected.quantities,termsCommitment:selected.termsCommitment};
   if(read().intentAdmissions.has(job.operationId)){
    inspect(job);const orig=original(job);check(same(orig.saved.arguments,args),'OPERATION_CONFLICT');
    return {...await recoverJob(job,assertCurrent),status:'RECONCILIATION_ONLY'};
   }
   policy(job,job.toolDefinition.action,job.toolDefinition.resource,projection);inspect(job);
   const record={version:'irontrellis-mcp-cooperative-job/1',domain:local.domain,contractId:registry.contractId,serviceId:registry.serviceId,
    operationId:job.operationId,businessKey:job.businessKey,tool:job.tool,arguments:args};
   if(existsSync(requestPath(job)))check(same(readPrivate(requestPath(job)),record),'OPERATION_CONFLICT');else durableCreate(requestPath(job),record);
   let dispatchStarted=false;
   const guardedClient={...client};
   for(const method of ['checkpointBegin','checkpointChunk','checkpointCommit','prepare','commit'])guardedClient[method]=async(...values)=>{
    assertSynchronous(assertCurrent);dispatchPolicy(job);onProgress(method.startsWith('checkpoint')?'checkpoint':method);assertSynchronous(assertCurrent);dispatchPolicy(job);
    if(method==='prepare'||method==='commit')dispatchStarted=true;
    const reply=await client[method](...values);assertSynchronous(assertCurrent);dispatchPolicy(job);return reply;
   };
   // Guard each transfer hop: the client's convenience loop otherwise continues across revocation.
   guardedClient.checkpointHistory=async history=>{
    assertSynchronous(assertCurrent);dispatchPolicy(job);const transfer=createHistoryTransfer(history),{transferId}=transfer;
    let reply=await guardedClient.checkpointBegin(transfer.manifest,transferId);
    if(reply.result.state!=='CHECKPOINT_STAGED')return reply;
    for(let index=0;index<transfer.chunks.length;index++){
     reply=await guardedClient.checkpointChunk(transferId,index,transfer.chunks[index]);
     if(reply.result.state!=='CHECKPOINT_CHUNKED')return reply;
    }
    return guardedClient.checkpointCommit(transferId);
   };
   const executor=createCooperativeExecutor({local:checkedLocal(assertCurrent),client:guardedClient,registry,role:job.role,tenure:job.tenure});
   let result;try{result=await executor.run(request(job,args));}finally{executor.close();}
   let reply=result.serviceReport;
   if(reply){try{retain(job,reply);}catch{reply=null;}}
   assertSynchronous(assertCurrent);inspect(job);
   const state=read(),status=state.intentAdmissions.has(job.operationId)?(reply?'RESPONSE_RETAINED':'OUTCOME_UNKNOWN'):(result.execution.status==='NOT_AUTHORIZED'?'DENIED':'REFUSED');
   return {...summary(job,reply,status),coreStatus:result.execution.status,
    canonicalDisposition:(result.execution.invocation??result.execution.result)?.status??null,
    dispatchPerformed:dispatchStarted,revocationBoundary:'DESTINATION_ACKNOWLEDGED_CHECKPOINT'};
  });},
  checkCancellation(name){const job=lookup(name);inspect(job);policy(job,'cancel-operation',job.operationId);},
  recover(name,{assertCurrent=()=>{}}={}){return locked(()=>recoverJob(lookup(name),assertCurrent));},
  cancel(name,{assertCurrent=()=>{}}={}){return locked(async()=>{
   assertSynchronous(assertCurrent);const job=lookup(name);inspect(job);policy(job,'cancel-operation',job.operationId);const orig=original(job);
   const terms={version:'continuity-mcp-cancellation/1',originalIdentity:orig.identity,requestHash:hash(orig.saved),serviceId:registry.serviceId,contractId:registry.contractId};
   let reply,cancellationSent=false;
   const unknown=i=>({status:'OUTCOME_UNKNOWN',idempotencyKey:i.idempotencyKey,submissionFingerprint:i.submissionFingerprint});
   const reported=(i,r,status)=>{const acknowledgment=ack(i,r.result),evidence=adapterAcknowledgmentEvidence(i,acknowledgment);
    return {status,idempotencyKey:i.idempotencyKey,submissionFingerprint:i.submissionFingerprint,acknowledgment,...(status==='RETRY'?{retainedEvidence:evidence}:{evidence})};};
   const adapter={adapterProfile:profile,
    async submit(submission){const i=deriveAdapterIdentity(submission);try{
     assertSynchronous(assertCurrent);policy(job,'cancel-operation',job.operationId);dispatchPolicy(job,job.cancelId);
     // The separate Core cancellation admission precedes this durable dispatch marker.
     durableCreate(join(storage,job.cancelId+'.dispatch.json'),{identity:i,terms});
     assertSynchronous(assertCurrent);policy(job,'cancel-operation',job.operationId);dispatchPolicy(job,job.cancelId);
     cancellationSent=true;
     const recovery=createCooperativeRecovery({local,client,registry});let result;try{assertSynchronous(assertCurrent);policy(job,'cancel-operation',job.operationId);dispatchPolicy(job,job.cancelId);result=await recovery.cancel(orig.request);}finally{recovery.close();}
     retain(job,result.serviceReport,'cancel');retain(job,result.serviceReport);
     reply=result.serviceReport;return reported(i,reply,'SUBMITTED');
    }catch{return unknown(i);}},
    async reconcile(submission){const i=deriveAdapterIdentity(submission);try{reply=reports(job,'cancel').at(-1);return reply?reported(i,reply,'RETRY'):unknown(i);}catch{return unknown(i);}},
   };
   const result=await openLocalExecution(checkedLocal(assertCurrent),adapter,'REMOTE_REPORT').run({id:job.cancelId,intentId:job.cancelId,action:'cancel-operation',resource:job.operationId,role:job.role,tenure:job.tenure,termsCommitment:hash(terms,'sha256')});
   reply??=reports(job,'cancel').at(-1);
   if(reply){const consumption=read().intentConsumptions.get(job.cancelId);if(consumption)check(same(consumption.acknowledgment,ack(read().intentAdmissions.get(job.cancelId).adapterIdentity,reply.result)),'STORAGE_UNAVAILABLE');}
   assertSynchronous(assertCurrent);inspect(job);
   return {...summary(job,reply,reply?'CANCELLATION_REPORTED':'OUTCOME_UNKNOWN'),cancellationId:job.cancelId,
    canonicalDisposition:(result.invocation??result.result)?.status??null,cancellationDoesNotUndoEffects:true,dispatchPerformed:cancellationSent,originalDispatchPerformed:false,cancellationRequestSent:cancellationSent};
  });},
  observe(name,{assertCurrent=()=>{}}={}){return locked(async()=>{
   assertSynchronous(assertCurrent);const job=lookup(name);inspect(job);policy(job,'OBSERVE_OUTCOME',job.operationId);
   const reply=reports(job).at(-1);check(reply,'REPORT_UNAVAILABLE');const {orig,report}=validateReply(job,reply);check(report.state==='APPLIED','REPORT_NOT_APPLIED');
   const acknowledgment=ack(orig.identity,report),observationId='mcp:'+hash({operationId:job.operationId,reportDigest:digest(report),actor:session.agentId}).slice(2);
   const result=await openLocalAttemptRecorder(checkedLocal(assertCurrent)).observe({id:observationId,intent:job.operationId,acknowledgment});
   assertSynchronous(assertCurrent);inspect(job);return {status:'OBSERVATION_RECORDED',operationId:job.operationId,eventId:result.eventId,
    reportDigest:digest(report),dispatchPerformed:false,externalOutcome:'NOT_PROVEN',dutyDischarged:false};
  });},
  status(name){try{const job=lookup(name);inspect(job);if(!read().intentAdmissions.has(job.operationId))return {status:'NOT_STARTED',operationId:job.operationId,dispatchPerformed:false};
   const reply=reports(job).at(-1);return summary(job,reply,reply?'RESPONSE_RETAINED':'OUTCOME_UNKNOWN');}catch(error){return publicError(error);}},
  why(name){try{const job=lookup(name);inspect(job);const state=read(),decision=observeState(read(),{at:local.now()}).authorize({actor:session.agentId,action:job.toolDefinition.action,resource:job.toolDefinition.resource});return {decision:decision.decision,action:job.toolDefinition.action,resource:job.toolDefinition.resource,historyHead:decision.head.hash,scope:'CURRENT_PERMISSION_ONLY',executionCapability:false};}catch(error){return publicError(error);}},
  async close(){closed=true;store.close();},
 });
}
