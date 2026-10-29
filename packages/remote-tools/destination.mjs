import {openCheckpointStorage} from '@ramex-labs/irontrellis/adapter';
import {HISTORY_PROFILE} from '@ramex-labs/irontrellis/adapter';
import http from 'node:http';
import {readdirSync,lstatSync} from 'node:fs';
import {join} from 'node:path';
import {protectedEvidenceProfile, openEvidenceReader} from './protected-evidence.mjs';
import { openDestinationStore } from './durable-store.mjs';
import { stateOf } from '@ramex-labs/irontrellis/adapter';
import { capture, exact, textId, hashId, integer, canonicalDigest, encodeTransport, decodeTransport,
  publicKeyIdentity, verifyRequest, signResponse, validateOperationShape, validateReport, MAX_WIRE_BYTES } from './wire.mjs';

const refuse=code=>{throw Object.assign(new Error(code),{code});};
const same=(a,b)=>canonicalDigest(a)===canonicalDigest(b);
const response=(state,code)=>({state,code});
const refusals=['NO_CHECKPOINT','CHECKPOINT_CONFLICT','CHECKPOINT_CHANGED','OPERATION_CONFLICT','BUSINESS_KEY_CONFLICT',
  'AUTHORIZATION_REFUSED','CLOCK_INVALID','CAPACITY_EXHAUSTED','INVALID_OPERATION','UNSUPPORTED_HISTORY_PROFILE','TRANSFER_INVALID','TRANSFER_CONFLICT','TRANSFER_CHUNK_INVALID','TRANSFER_STORAGE_LIMIT','TRANSFER_INCOMPLETE','TRANSFER_STORAGE_INVALID'];
const requestBytes=request=>new Promise((resolve,reject)=>{
  const parts=[];let size=0,settled=false;
  const timer=setTimeout(()=>{if(!settled){settled=true;reject(Error('REQUEST_TIMEOUT'));request.destroy();}},5000);
  const end=()=>clearTimeout(timer);
  request.on('data',chunk=>{if(settled)return;size+=chunk.length;if(size>MAX_WIRE_BYTES){settled=true;end();reject(Error('REQUEST_LIMIT'));request.destroy();}else parts.push(chunk);});
  request.on('end',()=>{if(settled)return;settled=true;end();resolve(Buffer.concat(parts));});
  request.on('error',error=>{if(settled)return;settled=true;end();reject(error);});
  request.on('aborted',()=>{if(settled)return;settled=true;end();reject(Error('REQUEST_ABORTED'));});
});

/** Synthetic effects only: effect and deduplication record share one commit. */
export async function createCooperativeDestination({directory,domain,historyId,headAuthenticationPolicy,serviceId,coordinatorPublicKey,servicePrivateKey,now,validateOperation,historyProfile,checkpointHooks}) {
  if(typeof serviceId==='string'&&serviceId.startsWith('evidence:'))throw Error('PROTECTED_PROFILE_REQUIRED');
  return createDestination({directory,domain,historyId,headAuthenticationPolicy,serviceId,coordinatorPublicKey,servicePrivateKey,now,validateOperation,historyProfile,checkpointHooks});
}

/** Fixed service-owned evidence bundle. Uses the same durable transaction as the reference destination. */
export async function createProtectedEvidenceDestination(options) {
  const profile=protectedEvidenceProfile(options.evidence);
  // Initial access is a one-time host decision. Missing storage on restart
  // must never quietly recreate an open bundle.
  if(options.initialize===true){
    if(readdirSync(options.directory).length!==0)throw Error('EVIDENCE_INITIALIZATION_REQUIRES_EMPTY_DIRECTORY');
  }else{
    if(options.initialize!==undefined&&options.initialize!==false)throw Error('INVALID_INITIALIZATION_MODE');
    for(const name of ['identity.bin','snapshot.bin'])if(!lstatSync(join(options.directory,name)).isFile())throw Error('EVIDENCE_STATE_REQUIRED');
  }
  const destination=await createDestination({...options,serviceId:profile.registry.serviceId,validateOperation:profile.registry.validateOperation},profile);
  return Object.freeze({...destination,registry:profile.registry});
}

async function createDestination({directory,domain,historyId,headAuthenticationPolicy,serviceId,coordinatorPublicKey,servicePrivateKey,now,validateOperation,historyProfile,checkpointHooks},evidence) {
  domain=capture(domain);hashId(historyId);textId(serviceId);
  if(headAuthenticationPolicy===undefined)headAuthenticationPolicy='REQUIRE_OWNER';
  if(!['REQUIRE_OWNER','COORDINATOR_AUTHENTICATED'].includes(headAuthenticationPolicy))throw Error('INVALID_AUTHENTICATION_POLICY');
  if(typeof now!=='function'||typeof validateOperation!=='function'||servicePrivateKey.type!=='private'||coordinatorPublicKey.type!=='public')throw Error('INVALID_CONFIGURATION');
  const coordinatorKey=publicKeyIdentity(coordinatorPublicKey),serviceKey=publicKeyIdentity(servicePrivateKey);
  if(historyProfile!==undefined&&historyProfile!==HISTORY_PROFILE)throw Error('UNSUPPORTED_HISTORY_PROFILE');
  let checkpoints;
  const history=c=>(checkpoints??=openCheckpointStorage(directory,checkpointHooks)).load(c.reference);
  const historyEvents=c=>history(c).events;
  const authenticate=h=>{
    if(h.historyId!==historyId||!same(h.domain,domain)||
      !(headAuthenticationPolicy==='COORDINATOR_AUTHENTICATED'||['HEAD_ATTESTATION','STATE_CHECKPOINT','GENESIS'].includes(h.headAuthentication)))refuse('CHECKPOINT_CONFLICT');
    return h;
  };
  // Storage initialization must precede creation of the transfer directory.
  const resolveCheckpoint=id=>authenticate((checkpoints??=openCheckpointStorage(directory,checkpointHooks)).load(id));
  const store=openDestinationStore({directory,checkpointResolver:resolveCheckpoint,initial:{version:'irontrellis-cooperative-destination/1',domain,historyId,headAuthenticationPolicy,serviceId,
    coordinatorKey,serviceKey,sequence:0,lastTime:0,checkpoint:null,attempts:[],businessKeys:[],effects:[]}});
  try{checkpoints??=openCheckpointStorage(directory,checkpointHooks);}catch(error){store.close();throw error;}
  const clock=state=>{
    let at;try{at=integer(now());}catch{refuse('CLOCK_INVALID');}
    if(at<state.lastTime||(state.checkpoint&&at<state.checkpoint.head.canonicalTime))refuse('CLOCK_INVALID');
    state.lastTime=at;
    return at;
  };
  const normalized=(events,operation,at,state)=>{
    let result;
    try{result=capture(validateOperation(events,operation,at,capture(state)));}
    catch{refuse('AUTHORIZATION_REFUSED');}
    exact(result,['intentId','idempotencyKey','submissionFingerprint','tool','arguments','businessKey','contractId']);
    hashId(result.idempotencyKey);hashId(result.submissionFingerprint);
    for(const name of ['intentId','tool','businessKey','contractId'])textId(result[name]);
    if(result.intentId!==operation.intentId||result.tool!==operation.tool||result.businessKey!==operation.businessKey||
        result.contractId!==operation.contractId||!same(result.arguments,operation.arguments))refuse('INVALID_OPERATION');
    return result;
  };
  const validateSaved=state=>{
    const heads=new Map();
    if(state.checkpoint!==null){
      exact(state.checkpoint,['head','reference']);const received=authenticate(history(state.checkpoint)),replayed=stateOf(received);
      if(!same(replayed.genesis.domain,domain)||!same(replayed.head,state.checkpoint.head))throw Error('STORAGE_UNAVAILABLE');
      heads.set(replayed.head.position,replayed.head);
    }
    const keys=new Set(),business=new Set(),effects=new Set();
    for(const item of state.attempts){
      exact(item,['key','fingerprint','intentId','operation','normalized','checkpointHead','preparedAt','report']);
      hashId(item.key);hashId(item.fingerprint);integer(item.preparedAt);validateOperationShape(item.operation);validateReport(item.report);
      exact(item.normalized,['intentId','idempotencyKey','submissionFingerprint','tool','arguments','businessKey','contractId']);
      exact(item.checkpointHead,['hash','position','canonicalTime']);hashId(item.checkpointHead.hash);
      integer(item.checkpointHead.position);integer(item.checkpointHead.canonicalTime);
      if(!state.checkpoint||item.checkpointHead.position>state.checkpoint.head.position||
        item.preparedAt<item.checkpointHead.canonicalTime)throw Error('STORAGE_UNAVAILABLE');
      if(!heads.has(item.checkpointHead.position))heads.set(item.checkpointHead.position,
        stateOf(historyEvents(state.checkpoint).slice(0,item.checkpointHead.position+1)).head);
      if(!same(heads.get(item.checkpointHead.position),item.checkpointHead))throw Error('STORAGE_UNAVAILABLE');
      if(keys.has(item.key)||item.normalized.idempotencyKey!==item.key||item.normalized.submissionFingerprint!==item.fingerprint||
          !same(item.normalized,{...item.operation,idempotencyKey:item.key,submissionFingerprint:item.fingerprint})||
          item.intentId!==item.operation.intentId||item.report.key!==item.key||item.report.fingerprint!==item.fingerprint||
          item.report.intentId!==item.intentId||item.report.tool!==item.operation.tool||item.report.businessKey!==item.operation.businessKey||
          item.report.contractId!==item.operation.contractId||item.report.checkpointHash!==item.checkpointHead.hash)throw Error('STORAGE_UNAVAILABLE');
      keys.add(item.key);
    }
    for(const binding of state.businessKeys){exact(binding,['businessKey','key','intentId']);if(business.has(binding.businessKey)||
      !state.attempts.some(item=>item.key===binding.key&&item.intentId===binding.intentId&&item.operation.businessKey===binding.businessKey))throw Error('STORAGE_UNAVAILABLE');business.add(binding.businessKey);}
    if(business.size!==state.attempts.length)throw Error('STORAGE_UNAVAILABLE');
    for(const effect of state.effects){
      exact(effect,['effectId','key','fingerprint','tool','arguments','businessKey','contractId']);
      const attempt=state.attempts.find(item=>item.key===effect.key);
      if(effects.has(effect.key)||!attempt||attempt.report.state!=='APPLIED'||attempt.report.effectId!==effect.effectId||
          effect.fingerprint!==attempt.fingerprint||effect.tool!==attempt.normalized.tool||
          !same(effect.arguments,attempt.normalized.arguments)||effect.businessKey!==attempt.normalized.businessKey||effect.contractId!==attempt.normalized.contractId)throw Error('STORAGE_UNAVAILABLE');
      effects.add(effect.key);
    }
    if(state.attempts.some(item=>(item.report.state==='APPLIED')!==effects.has(item.key)))throw Error('STORAGE_UNAVAILABLE');
    evidence?.validate(state);
    return state;
  };
  try{validateSaved(store.read());}catch(error){store.close();throw error;}
  const handle=body=>{
    try{
      const committed=store.transact(state=>{
        validateSaved(state);
        const before=capture(state);
        try {
        const {operation,payload}=body;
        let result;
        if(operation.startsWith('checkpoint-')){
          if(operation==='checkpoint-begin'){
            if(!same(payload.manifest?.view?.domain,domain)||payload.manifest?.view?.historyId!==historyId)refuse('CHECKPOINT_CONFLICT');
            checkpoints.begin(payload.manifest,payload.transferId,state.checkpoint?.reference??null);
            result={state:'CHECKPOINT_STAGED',transferId:payload.transferId};
          }else if(operation==='checkpoint-chunk'){
            checkpoints.chunk(payload.transferId,payload.index,payload.bytes);
            result={state:'CHECKPOINT_CHUNKED',transferId:payload.transferId,index:payload.index};
          }else if(operation==='checkpoint-abort'){
            checkpoints.abort(payload.transferId);result={state:'CHECKPOINT_ABORTED',transferId:payload.transferId};
          }else if(operation==='checkpoint-commit'){
            const received=authenticate(checkpoints.ready(payload.transferId)),replayed=stateOf(received),at=clock(state);
            if(!same(replayed.genesis.domain,domain)||at<replayed.head.canonicalTime)refuse('CHECKPOINT_CONFLICT');
            if(state.checkpoint){
              const prior=history(state.checkpoint);
              if(received.head.position<prior.head.position||received.view.events[prior.head.position]?.recordHash!==prior.head.hash)refuse('CHECKPOINT_CONFLICT');
              if(received.head.position===prior.head.position)return{state:before,result:{state:'CHECKPOINTED',head:state.checkpoint.head}};
            }
            checkpointHooks?.point?.('before-checkpoint-reference');
            state.checkpoint={reference:payload.transferId,head:replayed.head};state.lastTime=at;
            result={state:'CHECKPOINTED',head:replayed.head};
          }else refuse('INVALID_OPERATION');
        }else if(operation==='prepare'){
          if(!state.checkpoint)refuse('NO_CHECKPOINT');
          const at=clock(state),op=payload.operation,norm=normalized(historyEvents(state.checkpoint),op,at,state);
          const prior=state.attempts.find(item=>item.key===norm.idempotencyKey);
          if(prior){
            if(!same(prior.operation,op)||!same(prior.normalized,norm))refuse('OPERATION_CONFLICT');
            if(!same(prior.checkpointHead,state.checkpoint.head))refuse('CHECKPOINT_CHANGED');
            return{state,result:prior.report};
          }
          if(state.businessKeys.some(item=>item.businessKey===norm.businessKey))refuse('BUSINESS_KEY_CONFLICT');
          if(state.attempts.length>=256)refuse('CAPACITY_EXHAUSTED');
          const report={state:'PENDING',key:norm.idempotencyKey,fingerprint:norm.submissionFingerprint,
            intentId:norm.intentId,tool:norm.tool,businessKey:norm.businessKey,contractId:norm.contractId,checkpointHash:state.checkpoint.head.hash};
          state.attempts.push({key:norm.idempotencyKey,fingerprint:norm.submissionFingerprint,intentId:norm.intentId,
            operation:op,normalized:norm,checkpointHead:state.checkpoint.head,preparedAt:at,report});
          state.businessKeys.push({businessKey:norm.businessKey,key:norm.idempotencyKey,intentId:norm.intentId});
          state.lastTime=at;result=report;
        }else{
          const prior=state.attempts.find(item=>item.key===payload.key);
          if(!prior)return{state,result:{state:'UNKNOWN',key:payload.key}};
          if(operation==='status')return{state,result:prior.report};
          if(operation==='cancel'){
            if(prior.report.state==='APPLIED')return{state,result:{state:'TOO_LATE',report:prior.report}};
            if(prior.report.state==='CANCELLED')return{state,result:prior.report};
            // Cancellation reduces authority. A faulty clock cannot block it
            // or lower the floor used to admit future work.
            try{state.lastTime=Math.max(state.lastTime,integer(now()));}catch{}
            prior.report={...prior.report,state:'CANCELLED'};result=prior.report;
          }else if(operation==='commit'){
            if(prior.report.state!=='PENDING')return{state,result:prior.report};
            if(!state.checkpoint||!same(prior.checkpointHead,state.checkpoint.head))refuse('CHECKPOINT_CHANGED');
            const at=clock(state),norm=normalized(historyEvents(state.checkpoint),prior.operation,at,state);
            if(!same(norm,prior.normalized))refuse('OPERATION_CONFLICT');
            const effectId='effect:'+prior.key.slice(2);
            state.effects.push({effectId,key:prior.key,fingerprint:prior.fingerprint,tool:norm.tool,
              arguments:norm.arguments,businessKey:norm.businessKey,contractId:norm.contractId});
            prior.report={...prior.report,state:'APPLIED',effectId};state.lastTime=at;result=prior.report;
          }else refuse('INVALID_OPERATION');
        }
        validateSaved(state);return{state,result};
        }catch(error){
          if(!refusals.includes(error.code))throw error;
          // An observed later trusted time survives a refusal. Otherwise a
          // subsequent backward clock could revive an expired permission.
          return{state:{...before,lastTime:Math.max(before.lastTime,state.lastTime)},result:response('REFUSED',error.code)};
        }
      });
      if(body.operation==='checkpoint-commit'&&committed.result.state==='CHECKPOINTED')checkpointHooks?.point?.('checkpoint-reference-synced');
      return{sequence:committed.state.sequence,result:committed.result};
    }catch(error){
      const code=refusals.includes(error.code)?error.code:'STORAGE_UNAVAILABLE';
      return{sequence:store.read().sequence,result:response('REFUSED',code)};
    }
  };
  const sockets=new Set();let closing=false;
  const server=http.createServer(async(request,res)=>{
    if(request.method!=='POST'||request.url!=='/cooperative'){res.writeHead(404);res.end();return;}
    try{
      const envelope=decodeTransport(await requestBytes(request));
      const body=verifyRequest(envelope,coordinatorPublicKey,{serviceId});
      const result=handle(body);
      const receipt=signResponse({version:'continuity-cooperative-response/1',serviceId,requestDigest:canonicalDigest(body),...result},servicePrivateKey);
      res.writeHead(200,{'content-type':'application/json'});res.end(encodeTransport(receipt));
    }catch{if(!res.destroyed){res.writeHead(400);res.end();}}
  });
  server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  server.requestTimeout=5000;server.headersTimeout=5000;
  let reader;
  try{
    if(evidence)reader=await openEvidenceReader(evidence,()=>validateSaved(store.read()));
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',()=>{server.off('error',reject);resolve();});});
  }
  catch(error){await reader?.close();store.close();throw error;}
  return Object.freeze({
    url:`http://127.0.0.1:${server.address().port}`,
    ...(reader?{readerSocket:reader.socketPath}:{}),
    inspect(){return capture(validateSaved(store.read()));},
    async close(){if(closing)return;closing=true;await reader?.close();for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));store.close();},
  });
}
