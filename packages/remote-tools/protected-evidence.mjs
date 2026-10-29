import http from 'node:http';
import {createHash,timingSafeEqual} from 'node:crypto';
import {lstatSync,realpathSync,openSync,fstatSync,readSync,closeSync,chmodSync,constants} from 'node:fs';
import {isAbsolute,dirname,join} from 'node:path';
import {canonicalDigest} from './wire.mjs';
import {createToolRegistry} from './validation.mjs';

const fail=()=>{throw Error('INVALID_EVIDENCE_CONFIGURATION');};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const ownDirectory=(path,modes)=>{
  if(typeof path!=='string'||!isAbsolute(path)||realpathSync(path)!==path)fail();
  const stat=lstatSync(path);
  if(!stat.isDirectory()||stat.uid!==process.getuid()||!modes.includes(stat.mode&0o777))fail();
};
/** Configuration is trusted host input, never an agent-selected path or tool schema. */
export function protectedEvidenceProfile(input) {
  if(!input||Object.keys(input).sort().join(',')!=='bundleDirectory,files,resource,reviewerTokenHash,socketPath')fail();
  const {bundleDirectory,resource,reviewerTokenHash,socketPath}=input;
  ownDirectory(bundleDirectory,[0o700]);
  if(typeof socketPath!=='string'||!isAbsolute(socketPath)||Buffer.byteLength(socketPath)>100)fail();
  ownDirectory(dirname(socketPath),[0o700,0o710]);
  if(typeof resource!=='string'||!/^evidence:[a-zA-Z0-9._-]{1,64}$/.test(resource)||!/^[a-f0-9]{64}$/.test(reviewerTokenHash))fail();
  if(!Array.isArray(input.files)||input.files.length<1||input.files.length>16)fail();
  const files=input.files.map(file=>{
    if(!file||Object.keys(file).sort().join(',')!=='bytes,name,sha256'||
      typeof file.name!=='string'||! /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/.test(file.name)||
      !/^[a-f0-9]{64}$/.test(file.sha256)||!Number.isSafeInteger(file.bytes)||file.bytes<1||file.bytes>65536)fail();
    return Object.freeze({...file});
  });
  if(new Set(files.map(f=>f.name)).size!==files.length||files.reduce((n,f)=>n+f.bytes,0)>65536)fail();
  const identity={version:'continuity-protected-evidence/1',resource,files,initialAccess:'reviewer',reviewerTokenHash};
  const serviceId='evidence:'+canonicalDigest(identity).slice(2);
  const registry=createToolRegistry({serviceId,account:'evidence-service',tools:[
    {id:'evidence.restrict',action:'restrict-evidence',resource,fields:{reason:'text'}},
    {id:'evidence.restore',action:'restore-evidence',resource,fields:{reason:'text'}},
  ]});
  const validate=state=>{
    if(state.serviceId!==serviceId)throw Error('EVIDENCE_PROFILE_MISMATCH');
    for(const attempt of state.attempts)registry.capture(attempt.operation);
    return state;
  };
  const access=state=>{
    validate(state);
    let result='reviewer';
    for(const effect of state.effects){
      if(effect.contractId!==registry.contractId||!['evidence.restrict','evidence.restore'].includes(effect.tool))throw Error('EVIDENCE_PROFILE_MISMATCH');
      result=effect.tool==='evidence.restrict'?'closed':'reviewer';
    }
    return result;
  };
  const read=()=>{
    ownDirectory(bundleDirectory,[0o700]);
    return files.map(file=>{
      const fd=openSync(join(bundleDirectory,file.name),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
      try{
        const stat=fstatSync(fd);
        if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o400||stat.size!==file.bytes)throw Error('BUNDLE_UNAVAILABLE');
        const bytes=Buffer.alloc(file.bytes);let position=0;
        while(position<bytes.length){const n=readSync(fd,bytes,position,bytes.length-position,position);if(n===0)throw Error('BUNDLE_UNAVAILABLE');position+=n;}
        const after=fstatSync(fd),named=lstatSync(join(bundleDirectory,file.name));
        if(after.size!==stat.size||after.mtimeMs!==stat.mtimeMs||after.ctimeMs!==stat.ctimeMs||after.nlink!==1||named.ino!==stat.ino||named.dev!==stat.dev||named.isSymbolicLink()||sha(bytes)!==file.sha256)throw Error('BUNDLE_UNAVAILABLE');
        return {name:file.name,sha256:file.sha256,bytes:bytes.length,base64:bytes.toString('base64')};
      }finally{closeSync(fd);}
    });
  };
  read(); // Refuse a bad bundle before opening either listener.
  return Object.freeze({registry,socketPath,validate,access,read,resource,
    authenticate(value){
      if(typeof value!=='string'||!/^Bearer [a-f0-9]{64}$/.test(value))return false;
      return timingSafeEqual(Buffer.from(sha(value.slice(7)),'hex'),Buffer.from(reviewerTokenHash,'hex'));
    }});
}

export async function openEvidenceReader(profile,currentState) {
  // A service-owned parent and OS group membership authenticate the local endpoint.
  // Never unlink an existing path or hold a transaction across network delivery.
  try{lstatSync(profile.socketPath);throw Error('READER_SOCKET_EXISTS');}catch(error){if(error.code!=='ENOENT')throw error;}
  const sockets=new Set();
  const server=http.createServer((request,response)=>{
    response.setHeader('cache-control','no-store');
    response.setHeader('content-type','application/json');
    if(request.method!=='GET'||request.url!=='/evidence'){response.writeHead(404);response.end('{"error":"NOT_FOUND"}');return;}
    if(!profile.authenticate(request.headers.authorization)){response.writeHead(401);response.end('{"error":"UNAUTHORIZED"}');return;}
    try{
      // Synchronous: no commit can interleave between the current-state check and
      // capture of immutable bytes. A delivery authorized before closure can finish later.
      const state=currentState();
      if(profile.access(state)!=='reviewer'){response.writeHead(403);response.end('{"error":"ACCESS_CLOSED"}');return;}
      const body=JSON.stringify({resource:profile.resource,sequence:state.sequence,files:profile.read()});
      response.writeHead(200);response.end(body);
    }catch{response.writeHead(503);response.end('{"error":"UNAVAILABLE"}');}
  });
  server.requestTimeout=5000;server.headersTimeout=5000;server.maxHeadersCount=16;
  server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  try{
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(profile.socketPath,()=>{server.off('error',reject);resolve();});});
    chmodSync(profile.socketPath,0o660);
  }catch(error){for(const s of sockets)s.destroy();await new Promise(resolve=>server.close(resolve));throw error;}
  let closed=false;
  return {socketPath:profile.socketPath,async close(){if(closed)return;closed=true;for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}};
}

/** For the configured reviewer only. Workers do not receive this credential. */
export function readProtectedEvidence({socketPath,token}) {
  return new Promise((resolve,reject)=>{
    const request=http.get({agent:false,socketPath,path:'/evidence',headers:{authorization:`Bearer ${token}`}},response=>{
      let size=0;const chunks=[];
      response.on('data',chunk=>{size+=chunk.length;if(size>100000)request.destroy(Error('RESPONSE_LIMIT'));else chunks.push(chunk);});
      response.on('error',reject);
      response.on('end',()=>{try{resolve({status:response.statusCode,body:JSON.parse(Buffer.concat(chunks).toString('utf8'))});}catch(error){reject(error);}});
    });
    request.setTimeout(5000,()=>request.destroy(Error('READER_TIMEOUT')));request.on('error',reject);
  });
}
