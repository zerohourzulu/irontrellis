import {assertSynchronous} from './access-http-guard.mjs';
import {sign,verify,randomBytes} from 'node:crypto';
import {readdirSync} from 'node:fs';
import {join} from 'node:path';
import {check,data,exact,privateDirectory,durableCreate} from './data.js';
import {parseStrictJson} from './strict-json.js';
import {digest,selectedHeaders} from './http-common.mjs';
const VERSION='irontrellis-private-request/1';
const channel=socket=>{check(socket.encrypted&&socket.authorized,'PRIVATE_CHANNEL_REQUIRED');return socket.exportKeyingMaterial(32,'EXPORTER-IronTrellis-Gateway-v1').toString('base64url');};
export const fingerprint=socket=>digest(socket.getPeerCertificate(true).raw);
function material({resource,method,path,headers,bytes,access,socket,now}){
 const at=now();check(Number.isSafeInteger(at)&&at>=0,'ACCESS_NOT_CURRENT');
 return {version:VERSION,resource,method,path,headers,bodyDigest:digest(bytes),identity:access.identity,expiresAt:access.expiresAt,
  tenant:access.binding.tenant,revision:access.binding.revision,at,nonce:randomBytes(32).toString('base64url'),channel:channel(socket)};
}
export function createRequestAssertion(input,key){
 check(key?.type==='private'&&key.asymmetricKeyType==='ed25519');assertSynchronous(input.access.assertCurrent);
 const bytes=Buffer.from(JSON.stringify(material(input))),signature=sign(null,bytes,key);
 assertSynchronous(input.access.assertCurrent);return bytes.toString('base64url')+'.'+signature.toString('base64url');
}
export function createAssertionVerifier({peerFingerprint,assertionPublicKey,nonceDirectory,resource,now=Date.now,servername}){
 check(/^[a-f0-9]{64}$/.test(peerFingerprint)&&assertionPublicKey?.type==='public'&&assertionPublicKey.asymmetricKeyType==='ed25519');
 const directory=privateDirectory(nonceDirectory);
 const assertPeer=socket=>{channel(socket);check(fingerprint(socket)===peerFingerprint,'PRIVATE_CHANNEL_REQUIRED');if(servername!==undefined)check(socket.servername===servername,'PRIVATE_CHANNEL_REQUIRED');};
 let last=0;
 return Object.freeze({assertPeer,verify(req,bytes,access){
  assertPeer(req.socket);assertSynchronous(access.assertCurrent);
  const header=req.headers['irontrellis-request-assertion'];check(typeof header==='string'&&header.length<=8192,'PRIVATE_ASSERTION_INVALID');
  const parts=header.split('.');check(parts.length===2&&parts.every(p=>/^[A-Za-z0-9_-]+$/.test(p)),'PRIVATE_ASSERTION_INVALID');
  const decoded=parts.map(p=>{const b=Buffer.from(p,'base64url');check(b.toString('base64url')===p,'PRIVATE_ASSERTION_INVALID');return b;});
  check(verify(null,decoded[0],assertionPublicKey,decoded[1]),'PRIVATE_ASSERTION_INVALID');
  const row=exact(parseStrictJson(decoded[0],{maxBytes:6144,maxDepth:8,maxNodes:128}),['version','resource','method','path','headers','bodyDigest','identity','expiresAt','tenant','revision','at','nonce','channel']);
  const at=now();check(Number.isSafeInteger(at)&&at>=last,'ACCESS_NOT_CURRENT');last=at;
  check(row.version===VERSION&&row.resource===resource&&row.method===req.method&&row.path===req.url&&row.bodyDigest===digest(bytes)&&row.channel===channel(req.socket),'PRIVATE_ASSERTION_INVALID');
  check(JSON.stringify(data(row.identity))===JSON.stringify(data(access.identity))&&row.expiresAt===access.expiresAt&&row.tenant===access.binding.tenant&&row.revision===access.binding.revision,'PRIVATE_ASSERTION_INVALID');
  check(JSON.stringify(data(row.headers))===JSON.stringify(data(selectedHeaders(req))),'PRIVATE_ASSERTION_INVALID');
  check(Number.isSafeInteger(row.at)&&row.at<=at&&at-row.at<=5000&&at<row.expiresAt*1000&&/^[A-Za-z0-9_-]{43}$/.test(row.nonce),'PRIVATE_ASSERTION_INVALID');
  privateDirectory(directory);check(readdirSync(directory).length<4096,'PRIVATE_NONCE_CAPACITY');
  // Durable create-exclusive replay custody survives restart. No live nonce is pruned.
  durableCreate(join(directory,row.nonce+'.json'),{version:VERSION,at:row.at,expiresAt:row.expiresAt});assertSynchronous(access.assertCurrent);
 }});
}
