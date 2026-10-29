import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import { captureData } from '@ramex-labs/irontrellis/adapter';
import { canonicalEncode } from '@ramex-labs/irontrellis/adapter';
import { parseStrictJson } from './strict-json.mjs';

export const MAX_WIRE_BYTES = 16 * 1024 * 1024;
const MAX_DATA_BYTES = 8 * 1024 * 1024;
const fail = code => { throw Object.assign(new Error(code), {code}); };
export const capture = value => captureData(value, MAX_DATA_BYTES, 300000, 96);
export function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value,key))) fail('INVALID_SHAPE');
  return value;
}
export function textId(value) {
  if (typeof value !== 'string' || !value || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) fail('INVALID_IDENTIFIER');
  return value;
}
export function hashId(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/.test(value)) fail('INVALID_HASH');
  return value;
}
export function integer(value) {
  if (!Number.isSafeInteger(value) || value < 0 || Object.is(value,-0)) fail('INVALID_INTEGER');
  return value;
}
export const canonicalDigest = value => '0x'+createHash('sha256').update(canonicalEncode(capture(value))).digest('hex');

// Every node is tagged, so an ordinary object resembling a bigint marker
// cannot become an integer during decoding. Object keys are sorted uniquely.
export function encodeTransport(value) {
  const stable = capture(value);
  const encode = node => {
    if (node === null) return ['null'];
    if (typeof node === 'bigint') return ['bigint',node.toString()];
    if (Array.isArray(node)) return ['array',node.map(encode)];
    if (typeof node === 'object') return ['object',Object.keys(node).sort().map(key => [key,encode(node[key])])];
    if (['string','number','boolean'].includes(typeof node)) return [typeof node,node];
    fail('INVALID_TRANSPORT_VALUE');
  };
  const bytes = Buffer.from(JSON.stringify(encode(stable)));
  if (bytes.length > MAX_WIRE_BYTES) fail('WIRE_LIMIT');
  return bytes;
}
export function decodeTransport(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('INVALID_TRANSPORT');
  const encoded = parseStrictJson(bytes,{maxBytes:MAX_WIRE_BYTES,maxDepth:256,maxNodes:1200000});
  let nodes=0;
  const decode = (node,depth=0) => {
    if (++nodes>300000 || depth>96 || !Array.isArray(node)) fail('TRANSPORT_LIMIT');
    if (node[0]==='null' && node.length===1) return null;
    if (node.length!==2) fail('INVALID_TRANSPORT');
    const [tag,value]=node;
    if (tag==='string' && typeof value==='string') return value;
    if (tag==='boolean' && typeof value==='boolean') return value;
    if (tag==='number' && typeof value==='number' && Number.isSafeInteger(value) && !Object.is(value,-0)) return value;
    if (tag==='bigint' && typeof value==='string' && /^(0|[1-9][0-9]{0,77})$/.test(value)) {
      const number=BigInt(value); if(number >= (1n<<256n)) fail('INVALID_BIGINT'); return number;
    }
    if (tag==='array' && Array.isArray(value)) return value.map(item=>decode(item,depth+1));
    if (tag==='object' && Array.isArray(value)) {
      const result=Object.create(null); let previous;
      for (const entry of value) {
        if (!Array.isArray(entry)||entry.length!==2||typeof entry[0]!=='string'||
            (previous!==undefined && previous>=entry[0])) fail('INVALID_TRANSPORT_OBJECT');
        previous=entry[0]; Object.defineProperty(result,entry[0],{value:decode(entry[1],depth+1),enumerable:true});
      }
      return result;
    }
    fail('INVALID_TRANSPORT');
  };
  return capture(decode(encoded));
}
export function publicKeyIdentity(key) {
  const publicKey=key?.type==='public'?key:createPublicKey(key);
  if(publicKey.asymmetricKeyType!=='ed25519') fail('UNSUPPORTED_KEY');
  return '0x'+createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex');
}
const assertKey = (key,privateRequired=false) => {
  if(key?.asymmetricKeyType!=='ed25519'||(privateRequired&&key.type!=='private')) fail('UNSUPPORTED_KEY');
};
export function validateOperationShape(value) {
  exact(value,['intentId','tool','arguments','businessKey','contractId']);
  for(const key of ['intentId','tool','businessKey','contractId']) textId(value[key]);
  if(!value.arguments||typeof value.arguments!=='object'||Array.isArray(value.arguments)) fail('INVALID_ARGUMENTS');
  return value;
}
function requestBody(body) {
  exact(body,['version','serviceId','nonce','operation','payload']);
  if(body.version!=='continuity-cooperative-request/1'||typeof body.nonce!=='string'||! /^[0-9a-f]{64}$/.test(body.nonce)) fail('INVALID_REQUEST');
  textId(body.serviceId);
  switch(body.operation) {
    case 'checkpoint-begin': exact(body.payload,['manifest','transferId']); if(typeof body.payload.transferId!=='string'||! /^0x[0-9a-f]{64}$/.test(body.payload.transferId))fail('INVALID_TRANSFER'); break;
    case 'checkpoint-chunk': exact(body.payload,['transferId','index','bytes']); if(typeof body.payload.transferId!=='string'||! /^0x[0-9a-f]{64}$/.test(body.payload.transferId)||!Array.isArray(body.payload.bytes)||body.payload.bytes.length<1||body.payload.bytes.length>683||body.payload.bytes.some(p=>typeof p!=='string'||p.length<1||p.length>4096))fail('INVALID_TRANSFER'); integer(body.payload.index); if(body.payload.index>=4096)fail('INVALID_TRANSFER');break;
    case 'checkpoint-abort': case 'checkpoint-commit': exact(body.payload,['transferId']); if(typeof body.payload.transferId!=='string'||! /^0x[0-9a-f]{64}$/.test(body.payload.transferId))fail('INVALID_TRANSFER');break;
    case 'prepare': exact(body.payload,['operation']); validateOperationShape(body.payload.operation); break;
    case 'commit': case 'status': case 'cancel': exact(body.payload,['key']);hashId(body.payload.key);break;
    default: fail('UNSUPPORTED_OPERATION');
  }
  return body;
}
export function validateReport(report) {
  const fields=['state','key','fingerprint','intentId','tool','businessKey','contractId','checkpointHash'];
  if(report?.state==='APPLIED') fields.push('effectId');
  exact(report,fields);
  if(!['PENDING','APPLIED','CANCELLED'].includes(report.state))fail('INVALID_REPORT');
  for(const key of ['key','fingerprint','checkpointHash'])hashId(report[key]);
  for(const key of ['intentId','tool','businessKey','contractId'])textId(report[key]);
  if(report.state==='APPLIED')textId(report.effectId);
  return report;
}
function responseBody(body) {
  exact(body,['version','serviceId','requestDigest','sequence','result']);
  if(body.version!=='continuity-cooperative-response/1') fail('INVALID_RESPONSE');
  textId(body.serviceId);hashId(body.requestDigest);integer(body.sequence);
  const result=body.result;
  if(result?.state==='CHECKPOINTED') {
    exact(result,['state','head']);exact(result.head,['hash','position','canonicalTime']);
    hashId(result.head.hash);integer(result.head.position);integer(result.head.canonicalTime);
  } else if((result?.state==='CHECKPOINT_STAGED'||result?.state==='CHECKPOINT_ABORTED')) {
    exact(result,['state','transferId']); if(typeof result.transferId!=='string'||! /^0x[0-9a-f]{64}$/.test(result.transferId))fail('INVALID_TRANSFER');
  } else if(result?.state==='CHECKPOINT_CHUNKED') {
    exact(result,['state','transferId','index']); if(typeof result.transferId!=='string'||! /^0x[0-9a-f]{64}$/.test(result.transferId))fail('INVALID_TRANSFER');integer(result.index);
  } else if(result?.state==='UNKNOWN') {exact(result,['state','key']);hashId(result.key);}
  else if(result?.state==='TOO_LATE') {exact(result,['state','report']);validateReport(result.report);if(result.report.state!=='APPLIED')fail('INVALID_REPORT');}
  else if(result?.state==='REFUSED') {
    exact(result,['state','code']);
    if(!['NO_CHECKPOINT','CHECKPOINT_CONFLICT','CHECKPOINT_CHANGED','OPERATION_CONFLICT','BUSINESS_KEY_CONFLICT',
      'AUTHORIZATION_REFUSED','CLOCK_INVALID','CAPACITY_EXHAUSTED','INVALID_OPERATION','STORAGE_UNAVAILABLE','UNSUPPORTED_HISTORY_PROFILE','TRANSFER_INVALID','TRANSFER_CONFLICT','TRANSFER_CHUNK_INVALID','TRANSFER_STORAGE_LIMIT','TRANSFER_INCOMPLETE','TRANSFER_STORAGE_INVALID'].includes(result.code))fail('INVALID_REFUSAL');
  } else validateReport(result);
  return body;
}
const signingBytes=(kind,body)=>Buffer.from(`continuity-cooperative-${kind}-signature/1\n${canonicalEncode(body)}`);
function signed(kind,body,key,validate) {
  assertKey(key,true);const stable=capture(body);validate(stable);
  return capture({body:stable,signature:sign(null,signingBytes(kind,stable),key).toString('hex')});
}
function verified(kind,envelope,key,validate) {
  assertKey(key);const stable=capture(envelope);exact(stable,['body','signature']);validate(stable.body);
  if(typeof stable.signature!=='string'||! /^[0-9a-f]{128}$/.test(stable.signature)||
      !verify(null,signingBytes(kind,stable.body),key,Buffer.from(stable.signature,'hex')))fail('INVALID_SIGNATURE');
  return stable.body;
}
export const signRequest=(body,key)=>signed('request',body,key,requestBody);
export const signResponse=(body,key)=>signed('response',body,key,responseBody);
export function verifyRequest(envelope,key,{serviceId}={}) {
  const body=verified('request',envelope,key,requestBody);
  if(serviceId!==undefined&&body.serviceId!==serviceId)fail('SERVICE_MISMATCH');
  return body;
}
export function verifyResponse(envelope,key,{serviceId,requestDigest}={}) {
  const body=verified('response',envelope,key,responseBody);
  if(serviceId!==undefined&&body.serviceId!==serviceId)fail('SERVICE_MISMATCH');
  if(requestDigest!==undefined&&body.requestDigest!==requestDigest)fail('REQUEST_MISMATCH');
  return body;
}
