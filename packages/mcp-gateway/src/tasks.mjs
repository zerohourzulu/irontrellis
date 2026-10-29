import {assertSynchronous} from './access-http-guard.mjs';
import {existsSync} from 'node:fs';
import {join} from 'node:path';
import {fromJsonSchema} from '@modelcontextprotocol/server';
import {check,data,exact,hash,same,privateDirectory,readPrivate,durableCreate} from './data.js';
import {operationIdentity} from './gateway.js';

export const TASKS_EXTENSION = 'io.modelcontextprotocol/tasks';
const terminal = new Set(['completed','cancelled','failed']);
const callResult = value => ({resultType:'complete',isError:['DENIED','REFUSED','OUTCOME_UNKNOWN'].includes(value.status),
 content:[{type:'text',text:JSON.stringify(value)}],structuredContent:value});
const phases = ['checkpoint','prepare','commit'];
const messages = {
 checkpoint:'Checking the destination history fence.',
 prepare:'Preparing the original job at the destination.',
 commit:'Waiting for the original destination result.',
};

/** One host-owned task per fixed business job. Handles never confer authority. */
export function createTaskManager({gateway,config,binding,now=Date.now,assertOwned=()=>{}}) {
 const storage=privateDirectory(config.storage),jobs=new Map(),active=new Map(),cancelling=new Map();
 const context=hash({domain:config.local.domain,registry:config.registry,binding});
 for(const operation of config.operations){
  const taskId='irontrellis-task:'+hash({domain:config.local.domain,businessKey:operation.businessKey}).slice(2);
  const tool=gateway.tools().find(t=>t.name===operation.name);
  jobs.set(taskId,{...operation,taskId,schema:fromJsonSchema(tool.inputSchema),operationId:operationIdentity(config.local.domain,operation.businessKey)});
 }
 const path=(job,part)=>join(storage,job.taskId+'.'+part+'.json');
 const stamp=()=>{const at=now();check(Number.isSafeInteger(at)&&at>=0,'CLOCK_INVALID');return new Date(at).toISOString();};
 function inspect(job,guard){assertSynchronous(assertOwned);assertSynchronous(guard);const state=gateway.status(job.name);check(state.status!=='REFUSED',state.reason??'INSPECTION_DENIED');return state;}
 function request(job){
  const row=exact(readPrivate(path(job,'request')),['version','context','taskId','businessKey','arguments','createdAt']);
  check(row.version==='irontrellis-mcp-task/1'&&row.context===context&&row.taskId===job.taskId&&row.businessKey===job.businessKey&&Number.isFinite(Date.parse(row.createdAt)),'TASK_CONFLICT');return row;
 }
 function getJob(taskId){const job=jobs.get(taskId);check(job&&existsSync(path(job,'request')),'TASK_NOT_FOUND');request(job);return job;}
 function write(job,part,value){if(!existsSync(path(job,part)))durableCreate(path(job,part),{context,taskId:job.taskId,at:stamp(),...value});}
 function read(job,part){
  if(!existsSync(path(job,part)))return null;
  const row=readPrivate(path(job,part));check(row.context===context&&row.taskId===job.taskId&&Number.isFinite(Date.parse(row.at)),'TASK_CONFLICT');return row;
 }
 function finish(job,value){
  if(read(job,'terminal'))return;
  const state=value.serviceState==='TOO_LATE'?value.serviceReport?.report?.state:value.serviceState;
  if(state==='CANCELLED')write(job,'terminal',{status:'cancelled'});
  else if(state==='APPLIED')write(job,'terminal',{status:'completed',result:callResult(value)});
  else if(['DENIED','REFUSED'].includes(value.status)&&gateway.status(job.name).status==='NOT_STARTED')
   write(job,'terminal',read(job,'cancel-request')?{status:'cancelled'}:{status:'completed',result:callResult(value)});
 }
 function view(job,guard){
  const current=inspect(job,guard),saved=request(job),end=read(job,'terminal');
  const base={taskId:job.taskId,createdAt:saved.createdAt,lastUpdatedAt:saved.createdAt,ttlMs:null,pollIntervalMs:1000};
  if(end){
   check(terminal.has(end.status),'TASK_CONFLICT');
   const actual=current.serviceState==='TOO_LATE'?current.serviceReport?.report:current.serviceReport;
   if(end.status==='cancelled')check(actual?.state==='CANCELLED'||(current.status==='NOT_STARTED'&&read(job,'cancel-request')),'TASK_CONFLICT');
   if(end.status==='completed'){
    const savedReport=end.result?.structuredContent?.serviceReport;
    check(actual?.state==='APPLIED'?same(savedReport?.state==='TOO_LATE'?savedReport.report:savedReport,actual):
     current.status==='NOT_STARTED'&&end.result?.isError===true,'TASK_CONFLICT');
   }
   return {...base,lastUpdatedAt:end.at,status:end.status,...(end.result?{result:end.result}:{})};}
  const last=phases.map(p=>({phase:p,row:read(job,p)})).filter(p=>p.row).at(-1);
  const cancel=read(job,'cancel-request');
  const statusMessage=cancel?'Cancellation requested; the destination outcome is not yet confirmed.':
   active.has(job.taskId)?(last?messages[last.phase]:'Checking permission for the original job.'):
   current.status==='NOT_STARTED'?'Interrupted before confirmed admission. No automatic restart.':
   current.serviceState==='PENDING'?'Destination work is pending. Inspect or cancel; it has not been sent again.':
   'Destination outcome is unknown. Resume inspection; do not repeat the action.';
  return {...base,status:'working',lastUpdatedAt:cancel?.at??last?.row.at??base.createdAt,statusMessage};
 }
 async function cancelJob(job,guard){
  if(cancelling.has(job.taskId))return cancelling.get(job.taskId);
  const work=(async()=>{
   if(active.has(job.taskId))await active.get(job.taskId);
   assertSynchronous(guard);gateway.checkCancellation(job.name);const current=inspect(job,guard);
   if(current.status==='NOT_STARTED'){write(job,'terminal',{status:'cancelled'});return;}
   const result=await gateway.cancel(job.name,{assertCurrent(){assertSynchronous(assertOwned);assertSynchronous(guard);}});finish(job,result);
  })().catch(()=>{}).finally(()=>cancelling.delete(job.taskId));
  cancelling.set(job.taskId,work);return work;
 }
 return Object.freeze({
  hasTool:name=>[...jobs.values()].some(j=>j.name===name),
  async start(name,args,guard){
   const job=[...jobs.values()].find(j=>j.name===name);check(job,'TASK_NOT_FOUND');inspect(job,guard);
   const input=data(args),valid=await job.schema['~standard'].validate(input);check(!valid.issues,'INVALID_ARGUMENTS');assertSynchronous(guard);inspect(job,guard);
   if(existsSync(path(job,'request'))){check(same(request(job).arguments,input),'OPERATION_CONFLICT');return {resultType:'task',...view(job,guard)};}
   check(active.size===0,'BUSY');
   durableCreate(path(job,'request'),{version:'irontrellis-mcp-task/1',context,taskId:job.taskId,businessKey:job.businessKey,arguments:input,createdAt:stamp()});
   // The durable request is the one-launch marker. Recovery never runs this branch.
   const work=Promise.resolve().then(()=>gateway.run(job.name,input,{
    assertCurrent(){assertSynchronous(assertOwned);assertSynchronous(guard);check(!read(job,'cancel-request'),'TASK_CANCEL_REQUESTED');},
    onProgress(phase){check(phases.includes(phase));write(job,phase,{});},
   })).then(result=>finish(job,result)).catch(()=>{}).finally(()=>active.delete(job.taskId));
   active.set(job.taskId,work);
   return {resultType:'task',...view(job,guard)};
  },
  async get(taskId,guard){
   const job=getJob(taskId);inspect(job,guard);
   if(!read(job,'terminal')&&!active.has(taskId)&&!cancelling.has(taskId)&&gateway.status(job.name).status!=='NOT_STARTED'){
    const result=await gateway.recover(job.name,{assertCurrent:guard});
    check(result.status!=='REFUSED',result.reason??'INSPECTION_DENIED');finish(job,result);
   }
   return {resultType:'complete',...view(job,guard)};
  },
  async cancel(taskId,guard){
   const job=getJob(taskId);inspect(job,guard);gateway.checkCancellation(job.name);
   if(!read(job,'terminal')){write(job,'cancel-request',{});void cancelJob(job,guard);}
   return {resultType:'complete'};
  },
  update(taskId,inputResponses,guard){
   const job=getJob(taskId);inspect(job,guard);check(inputResponses&&typeof inputResponses==='object'&&!Array.isArray(inputResponses));
   // No inputs are requested in this selected profile. Unknown response keys are ignored.
   return {resultType:'complete'};
  },
  async close(){await Promise.allSettled([...active.values(),...cancelling.values()]);},
 });
}

/** Current Tasks extension over the authenticated HTTP boundary; no legacy task types. */
export async function routeTaskRequest(manager,raw,headers,guard){
 let request;try{request=data(raw);}catch{return {jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid Request'}};}
 const method=request?.method,params=request?.params;
 const opted=params?._meta?.['io.modelcontextprotocol/clientCapabilities']?.extensions?.[TASKS_EXTENSION];
 const taskMethod=['tasks/get','tasks/cancel','tasks/update'].includes(method);
 const creation=method==='tools/call'&&manager.hasTool(params?.name)&&opted!==undefined;
 if(!taskMethod&&!creation)return null;
 const validId=typeof request.id==='string'||Number.isSafeInteger(request.id);
 const fail=(code,message)=>({jsonrpc:'2.0',id:validId?request.id:null,error:{code,message}});
 try{exact(request,['jsonrpc','id','method','params']);check(request.jsonrpc==='2.0'&&validId);}
 catch{return fail(-32600,'Invalid Request');}
 try{
  check(headers['mcp-protocol-version']==='2026-07-28'&&headers['mcp-method']===method);
  check(params?._meta?.['io.modelcontextprotocol/protocolVersion']==='2026-07-28');
  check(headers['mcp-name']===(taskMethod?params.taskId:params.name));
  check(opted&&typeof opted==='object'&&!Array.isArray(opted),'TASK_CAPABILITY_REQUIRED');
  exact(params,creation?['name','arguments']:method==='tasks/update'?['taskId','inputResponses']:['taskId'],['_meta']);
  assertSynchronous(guard);let result;
  if(creation)result=await manager.start(params.name,params.arguments,guard);
  else if(method==='tasks/get')result=await manager.get(params.taskId,guard);
  else if(method==='tasks/cancel')result=await manager.cancel(params.taskId,guard);
  else result=manager.update(params.taskId,params.inputResponses,guard);
  assertSynchronous(guard);return {jsonrpc:'2.0',id:request.id,result};
 }catch(error){
  if(error?.code==='TASK_CAPABILITY_REQUIRED')return {...fail(-32021,'Missing required client capability'),error:{code:-32021,message:'Missing required client capability',data:{requiredCapabilities:{extensions:{[TASKS_EXTENSION]:{}}}}}};
  const safe=new Set(['TASK_NOT_FOUND','OPERATION_CONFLICT','BUSY','INSPECTION_DENIED','RUNTIME_NOT_CURRENT','TASK_CONFLICT']);
  return fail(-32602,safe.has(error?.code)?error?.code:'Task request refused');
 }
}
