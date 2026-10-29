// A158/A159 bytes and structural links only. No replay, authentication or installed profile.
import {createHash} from 'node:crypto';
import {canonical,parseStrict,MAX_U53,LIMITS,wellFormed} from './canonical.mjs';
import {encodeProfilePayload} from './profiles.mjs';
export const BODY_VERSION='irontrellis-body-descriptor/1';
export const ARTIFACT_VERSION='irontrellis-artifact-descriptor/1';
export const NAMESPACE_VERSION='irontrellis-anchor-namespace/1';
export const ARTIFACT_KINDS=Object.freeze(['HEAD_ATTESTATION','RECEIPT_ARTIFACT','PROFILE_MANIFEST']);
export class DescriptorError extends Error {constructor(reason){super(reason);this.name='DescriptorError';this.code='DESCRIPTOR_INVALID';}}
const fail=s=>{throw new DescriptorError(s)},need=(b,s)=>{if(!b)fail(s)};
const sha=b=>'0x'+createHash('sha256').update(b).digest('hex');
const typed=Object.getPrototypeOf(Uint8Array.prototype);
const len=Object.getOwnPropertyDescriptor(typed,'byteLength').get,buf=Object.getOwnPropertyDescriptor(typed,'buffer').get,off=Object.getOwnPropertyDescriptor(typed,'byteOffset').get;
function captureBytes(input,max=LIMITS.bytes){
 if(typeof input==='string'){need(input.length<=max && Buffer.byteLength(input,'utf8')<=max,'LOCAL_CAPTURE_LIMIT');wellFormed(input);return Buffer.from(input,'utf8')}
 need(input instanceof Uint8Array && [Uint8Array.prototype,Buffer.prototype].includes(Object.getPrototypeOf(input)),'BYTES_REQUIRED');
 const n=len.call(input),b=buf.call(input),o=off.call(input);need(n<=max,'LOCAL_CAPTURE_LIMIT');
 need(!(typeof SharedArrayBuffer!=='undefined' && b instanceof SharedArrayBuffer),'SHARED_INPUT_REFUSED');return Buffer.from(new Uint8Array(b,o,n));
}
const closed=(v,keys,p)=>need(v!==null && typeof v==='object' && !Array.isArray(v) && Object.keys(v).length===keys.length && keys.every(k=>Object.hasOwn(v,k)),p+':CLOSED_FIELDS');
const hash=(v,p)=>need(typeof v==='string' && v.length===66 && /^0x[0-9a-f]{64}$/.test(v),p+':CONTENT_HASH');
const u53=(v,p)=>need(typeof v==='number' && Number.isSafeInteger(v) && v>=0 && !Object.is(v,-0),p+':U53');
function protocol(v,p){need(typeof v==='string',p+':STRING');wellFormed(v);need(Buffer.byteLength(v,'utf8')<=4096,p+':PROTOCOL_STRING')}
function identifier(v,p){protocol(v,p);need(Buffer.byteLength(v,'utf8')>=1 && Buffer.byteLength(v,'utf8')<=256 && !/[\x00-\x1f\x7f]/.test(v),p+':IDENTIFIER')}
const optional=(v,f,p)=>{if(v!==null)f(v,p)};
function parse(input){return parseStrict(captureBytes(input))}
function wrap(f){try{return f()}catch(e){if(e instanceof DescriptorError)throw e;throw new DescriptorError(e instanceof Error?e.message:'INVALID_INPUT')}}
function chunkRows(d){
 need(Array.isArray(d.chunks),'chunks:ARRAY');let total=0n;
 for(const c of d.chunks){closed(c,['digest','length'],'chunk');hash(c.digest,'chunk.digest');u53(c.length,'chunk.length');total+=BigInt(c.length)}
 need(total===BigInt(d.byteLength),'CHUNK_LENGTH_SUM');
}
function body(input){const d=parse(input);closed(d,['version','namespaceId','position','previousHash','eventHash','recordHash','byteLength','chunks'],'body');
 need(d.version===BODY_VERSION,'BODY_VERSION');hash(d.namespaceId,'namespaceId');u53(d.position,'position');optional(d.previousHash,hash,'previousHash');
 need((d.position===0)===(d.previousHash===null),'POSITION_NULL_LINK');hash(d.eventHash,'eventHash');hash(d.recordHash,'recordHash');u53(d.byteLength,'byteLength');chunkRows(d);return d}
function artifact(input){const d=parse(input);closed(d,['version','namespaceId','kind','boundBy','byteLength','chunks'],'artifact');need(d.version===ARTIFACT_VERSION,'ARTIFACT_VERSION');
 hash(d.namespaceId,'namespaceId');need(ARTIFACT_KINDS.includes(d.kind),'ARTIFACT_KIND');hash(d.boundBy,'boundBy');u53(d.byteLength,'byteLength');chunkRows(d);return d}
function namespace(input){const n=parse(input);closed(n,['version','domain','historyId','genesisEventHash','profile','chain','publisher'],'namespace');need(n.version===NAMESPACE_VERSION,'NAMESPACE_VERSION');
 closed(n.domain,['protocol','version','deploymentId'],'domain');need(n.domain.protocol==='irontrellis'&&n.domain.version==='2','DOMAIN_LITERALS');identifier(n.domain.deploymentId,'domain.deploymentId');
 hash(n.historyId,'historyId');hash(n.genesisEventHash,'genesisEventHash');closed(n.profile,['id','manifestHash'],'profile');identifier(n.profile.id,'profile.id');hash(n.profile.manifestHash,'profile.manifestHash');
 closed(n.chain,['id'],'chain');protocol(n.chain.id,'chain.id');need(typeof n.publisher==='string'&&n.publisher.length===42&&/^0x[0-9a-f]{40}$/.test(n.publisher),'LOWERCASE_PUBLISHER');return n}
function encoded(value){const canonicalText=canonical(value);return Object.freeze({value,canonicalText,byteLength:Buffer.byteLength(canonicalText,'utf8'),digest:sha(Buffer.from(canonicalText,'utf8')),scope:'STRUCTURAL_CODEC_ONLY'})}
export const encodeBodyDescriptor=input=>wrap(()=>encoded(body(input)));
export const encodeArtifactDescriptor=input=>wrap(()=>encoded(artifact(input)));
export const encodeNamespace=input=>wrap(()=>{const x=encoded(namespace(input));return Object.freeze({...x,namespaceId:x.digest,installationConstructed:false,manifestBindingVerified:false})});
// SPEC §4.3; eventDigest is already sha256(canonical(event)), never hashed again here.
export function recordHashFromEventDigest(previous,eventDigest,position){return wrap(()=>{
 u53(position,'position');optional(previous,hash,'previousHash');need((position===0)===(previous===null),'POSITION_NULL_LINK');hash(eventDigest,'eventHash');
 const p=Buffer.alloc(8);p.writeBigUInt64BE(BigInt(position));
 return sha(Buffer.concat([Buffer.from('irontrellis-record/2','utf8'),Buffer.from([0]),previous===null?Buffer.alloc(32):Buffer.from(previous.slice(2),'hex'),Buffer.from(eventDigest.slice(2),'hex'),p]));
})}
function assemble(d,chunks){
 need(Array.isArray(chunks)&&Object.getPrototypeOf(chunks)===Array.prototype,'CHUNK_BYTES_ARRAY');
 need(chunks.length===d.chunks.length && Reflect.ownKeys(chunks).length===chunks.length+1,'CHUNK_COUNT');
 need(d.byteLength<=LIMITS.bytes,'LOCAL_CAPTURE_LIMIT');const captured=[];let total=0;
 for(let i=0;i<chunks.length;i++){
  const slot=Object.getOwnPropertyDescriptor(chunks,String(i));need(slot&&Object.hasOwn(slot,'value')&&slot.enumerable,'CHUNK_BYTES_ACCESSOR_OR_HOLE');
  const b=captureBytes(slot.value,LIMITS.bytes-total);need(b.length===d.chunks[i].length,'CHUNK_LENGTH');need(sha(b)===d.chunks[i].digest,'CHUNK_DIGEST');captured.push(b);total+=b.length;
 }
 need(total===d.byteLength,'BODY_LENGTH');return Buffer.concat(captured,total);
}
function canonicalPayload(bytes){const value=parseStrict(bytes),text=canonical(value);need(Buffer.from(text,'utf8').equals(bytes),'NONCANONICAL_PAYLOAD_BYTES');return {value,text}}
export function verifyBodyDescriptor(input,chunks){return wrap(()=>{
 const d=body(input),bytes=assemble(d,chunks);need(sha(bytes)===d.eventHash,'EVENT_HASH');
 const payload=canonicalPayload(bytes);closed(payload.value,['id','type','timestamp','data'],'event-envelope');identifier(payload.value.id,'event.id');identifier(payload.value.type,'event.type');u53(payload.value.timestamp,'event.timestamp');
 need(payload.value.data!==null&&typeof payload.value.data==='object'&&!Array.isArray(payload.value.data),'EVENT_DATA_RECORD');
 need(recordHashFromEventDigest(d.previousHash,d.eventHash,d.position)===d.recordHash,'RECORD_HASH');
 return Object.freeze({descriptor:d,descriptorCanonicalText:canonical(d),canonicalBodyText:payload.text,eventHash:d.eventHash,recordHash:d.recordHash,
   scope:'CANONICAL_ENVELOPE_AND_STRUCTURAL_HASHES',replayStatus:'NOT_EVALUATED',authenticationVerified:false,persistenceVerified:false});
})}
export function verifyArtifactDescriptor(input,chunks){return wrap(()=>{
 const d=artifact(input),bytes=assemble(d,chunks),payload=canonicalPayload(bytes),a=payload.value;
 need(a!==null&&typeof a==='object'&&!Array.isArray(a),'ARTIFACT_OBJECT');
 let commitment=sha(bytes),bindingAlgorithm='CANONICAL_OBJECT_SHA256',contentIntegrityVerified=false;
 if(d.kind==='HEAD_ATTESTATION')need(a.version==='irontrellis-head-attestation/2','HEAD_ATTESTATION_VERSION');
 if(d.kind==='PROFILE_MANIFEST')encodeProfilePayload(bytes); // A167.5: payload only, never trust-root envelope.
 if(d.kind==='RECEIPT_ARTIFACT'){
  // §8.5: this commitment is NOT the digest of the whole artifact. Only the
  // version/domain/content/signature projection is checked here, not Core's
  // complete receipt schema, signature verification or accepted inclusion.
  closed(a,['payload','contentHash','signature'],'receipt');hash(a.contentHash,'receipt.contentHash');
  const p=a.payload;need(p!==null&&typeof p==='object'&&!Array.isArray(p),'RECEIPT_PAYLOAD');
  need(p.schemaVersion==='irontrellis-receipt/2','RECEIPT_VERSION');
  closed(p.domain,['protocol','version','deploymentId'],'receipt.domain');need(p.domain.protocol==='irontrellis'&&p.domain.version==='2','RECEIPT_DOMAIN');identifier(p.domain.deploymentId,'receipt.domain.deploymentId');
  const size=p.signatureScheme==='ed25519'?128:p.signatureScheme==='eip191-personal-sign-keccak256'?130:0;
  need(size!==0&&typeof a.signature==='string'&&a.signature.length===size+2&&/^0x[0-9a-f]+$/.test(a.signature),'RECEIPT_SIGNATURE_LEXICAL');
  need(sha(Buffer.from(canonical(p),'utf8'))===a.contentHash,'RECEIPT_CONTENT_HASH');contentIntegrityVerified=true;
  commitment=sha(Buffer.from(canonical(['irontrellis-receipt-artifact-commitment/2',a.contentHash,a.signature]),'utf8'));bindingAlgorithm='RECEIPT_TAGGED_COMMITMENT_2';
 }
 need(commitment===d.boundBy,'ARTIFACT_BOUND_HASH');
 return Object.freeze({descriptor:d,descriptorCanonicalText:canonical(d),canonicalArtifactText:payload.text,
   bindingAlgorithm,contentIntegrityVerified,scope:'CANONICAL_BYTES_AND_KIND_SPECIFIC_COMMITMENT_ONLY',artifactSchemaVerified:false,signatureVerified:false,referenceInAcceptedHistoryVerified:false,persistenceVerified:false});
})}
// Synchronous, in-memory structural index starting at no head. Not contract, durable CAS or replay state.
export function createStructuralIndex(namespaceId){hash(namespaceId,'namespaceId');const entries=new Map();let head=null;
 function append(input,chunks){return wrap(()=>{
  const checked=verifyBodyDescriptor(input,chunks),d=checked.descriptor;need(d.namespaceId===namespaceId,'NAMESPACE_MISMATCH');
  const prior=entries.get(d.position);
  if(prior){need(prior.canonicalBodyText===checked.canonicalBodyText && prior.descriptor.previousHash===d.previousHash && prior.recordHash===d.recordHash,'POSITION_CONFLICT');return Object.freeze({status:'DUPLICATE',entry:prior,head})}
  if(head===null)need(d.position===0&&d.previousHash===null,'PREFIX_HOLE');
  else {need(head.position<MAX_U53&&d.position===head.position+1,'PREFIX_HOLE');need(d.previousHash===head.hash,'PREVIOUS_HASH_MISMATCH')}
  const next=Object.freeze({hash:d.recordHash,position:d.position});entries.set(d.position,checked);head=next;
  return Object.freeze({status:'APPENDED_STRUCTURAL',entry:checked,head});
 })}
 return Object.freeze({append,coverage(expectedHead){return wrap(()=>{const e=parse(expectedHead);closed(e,['hash','position'],'expectedHead');hash(e.hash,'expectedHead.hash');u53(e.position,'expectedHead.position');const entry=entries.get(e.position);return Object.freeze({expectedHead:e,structuralCoverage:entry!==undefined&&entry.recordHash===e.hash,replayStatus:'NOT_EVALUATED',availabilityVerified:false,persistenceVerified:false})})},snapshot(){return Object.freeze({namespaceId,head,entries:Object.freeze([...entries.values()]),scope:'IN_MEMORY_STRUCTURAL_PREFIX',replayStatus:'NOT_EVALUATED',persistenceVerified:false})}});
}
