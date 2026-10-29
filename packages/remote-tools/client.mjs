import {createHistoryTransfer} from '@ramex-labs/irontrellis/adapter';
import { randomBytes } from 'node:crypto';
import { capture, textId, hashId, encodeTransport, decodeTransport, canonicalDigest, signRequest, verifyResponse, MAX_WIRE_BYTES, publicKeyIdentity } from './wire.mjs';

/** Trusted application client. Transport failure never authorizes another effect. */
export function createCooperativeClient({url,serviceId,coordinatorPrivateKey,servicePublicKey,timeoutMs=2000}) {
  const endpoint=new URL(url);
  if(endpoint.protocol!=='http:'||endpoint.hostname!=='127.0.0.1'||!endpoint.port||endpoint.pathname!=='/'||
      endpoint.username||endpoint.password||endpoint.search||endpoint.hash)throw Error('LOOPBACK_URL_REQUIRED');
  textId(serviceId);publicKeyIdentity(servicePublicKey);publicKeyIdentity(coordinatorPrivateKey);
  if(coordinatorPrivateKey.type!=='private'||servicePublicKey.type!=='public')throw Error('INVALID_KEY_ROLE');
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<20||timeoutMs>10000)throw Error('INVALID_TIMEOUT');
  const inspectResponse=(envelope,expectedDigest)=>{
    hashId(expectedDigest);
    const stable=capture(envelope);
    const body=verifyResponse(stable,servicePublicKey,{serviceId,requestDigest:expectedDigest});
    return capture({sequence:body.sequence,result:body.result,receipt:stable});
  };
  const call=async(operation,payload)=>{
    const body=capture({version:'continuity-cooperative-request/1',serviceId,nonce:randomBytes(32).toString('hex'),operation,payload});
    const envelope=signRequest(body,coordinatorPrivateKey),expectedDigest=canonicalDigest(body);
    // Synchronous history replay can outlive an idle pooled socket. This local
    // profile opens a fresh connection per signed request; it never auto-retries.
    const response=await fetch(endpoint.origin+'/cooperative',{method:'POST',headers:{'content-type':'application/json',connection:'close'},
      body:encodeTransport(envelope),redirect:'manual',signal:AbortSignal.timeout(timeoutMs)});
    if(response.status!==200){await response.body?.cancel();throw Error('TRANSPORT_UNAVAILABLE');}
    const parts=[];let length=0;
    for await(const chunk of response.body??[]){length+=chunk.length;if(length>MAX_WIRE_BYTES)throw Error('RESPONSE_LIMIT');parts.push(chunk);}
    return inspectResponse(decodeTransport(Buffer.concat(parts)),expectedDigest);
  };
  return Object.freeze({
    checkpointBegin:(manifest,transferId)=>call('checkpoint-begin',{manifest,transferId}),
    checkpointChunk:(transferId,index,bytes)=>call('checkpoint-chunk',{transferId,index,bytes}),
    checkpointCommit:transferId=>call('checkpoint-commit',{transferId}),
    abortCheckpointTransfer:transferId=>call('checkpoint-abort',{transferId}),
    async checkpointHistory(history){
      const transfer=createHistoryTransfer(history), {transferId}=transfer;
      let reply=await call('checkpoint-begin',{manifest:transfer.manifest,transferId});
      if(reply.result.state!=='CHECKPOINT_STAGED')return reply;
      for(let index=0;index<transfer.chunks.length;index++){
        reply=await call('checkpoint-chunk',{transferId,index,bytes:transfer.chunks[index]});
        if(reply.result.state!=='CHECKPOINT_CHUNKED')return reply;
      }
      return call('checkpoint-commit',{transferId});
    },
    prepare:operation=>call('prepare',{operation}),
    commit:key=>call('commit',{key}),
    status:key=>call('status',{key}),
    cancel:key=>call('cancel',{key}),
    inspectResponse,
  });
}
