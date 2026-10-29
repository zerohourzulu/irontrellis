#!/usr/bin/env node
// A159 conformance support, not a production store, replay or availability verifier.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,readdirSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalEncode,eventHash,recordHash,hashCanonical} from '../../packages/core/dist/index.js';
import {encodeBodyDescriptor,verifyBodyDescriptor,verifyArtifactDescriptor,createStructuralIndex} from './support/descriptors.mjs';
const here=dirname(fileURLToPath(import.meta.url)),root=join(here,'../..');
assert(process.argv.slice(2).every(x=>x==='--check'),'only --check supported');
const check=process.argv.includes('--check'),sha=b=>'0x'+createHash('sha256').update(b).digest('hex'),bytes=v=>Buffer.from(canonicalEncode(v));
const json=v=>Buffer.from(JSON.stringify(v,null,2)+'\n'),clone=v=>JSON.parse(JSON.stringify(v));
const vectorPath='conformance/anchor-statement/vector.json',vectorBytes=readFileSync(join(root,vectorPath)),vector=JSON.parse(vectorBytes);
const historyPath=vector.source.history,historyBytes=readFileSync(join(root,historyPath)),events=JSON.parse(historyBytes);
assert.equal(events.length,7);assert.equal(vector.statement.head.position,6);
const namespacePath='conformance/anchor-namespace/fixtures/namespace.json',namespaceBytes=readFileSync(join(root,namespacePath)),namespace=JSON.parse(namespaceBytes),namespaceId=hashCanonical(namespace,'sha256');
const manifestPath='conformance/anchor-namespace/fixtures/manifest.json',manifestBytes=readFileSync(join(root,manifestPath));
const split=b=>{const n=Math.max(1,Math.floor(b.length/3));return[b.subarray(0,n),b.subarray(n,2*n),b.subarray(2*n)].map(x=>Buffer.from(x))};
const chunkRows=c=>c.map(b=>({digest:sha(b),length:b.length}));
// Independent r4 §4.3 preimage, not a call to the descriptor implementation.
function hashRecord(previous,digest,position){const p=Buffer.alloc(8);p.writeBigUInt64BE(BigInt(position));const preimage=Buffer.concat([Buffer.from('irontrellis-record/2\0'),previous===null?Buffer.alloc(32):Buffer.from(previous.slice(2),'hex'),Buffer.from(digest.slice(2),'hex'),p]);assert.equal(preimage.length,93);return sha(preimage)}
const bodies=[];let previous=null;
for(const [position,event]of events.entries()){
 const b=bytes(event),chunks=split(b),eh=sha(b),rh=hashRecord(previous,eh,position);
 assert.equal(eh,eventHash(event));assert.equal(rh,recordHash(previous,event,position));
 const descriptor={version:'irontrellis-body-descriptor/1',namespaceId,position,previousHash:previous,eventHash:eh,recordHash:rh,byteLength:b.length,chunks:chunkRows(chunks)};
 const encoded=encodeBodyDescriptor(bytes(descriptor));assert.equal(encoded.canonicalText,canonicalEncode(descriptor));
 const verified=verifyBodyDescriptor(bytes(descriptor),chunks);assert.equal(verified.replayStatus,'NOT_EVALUATED');assert.equal(verified.recordHash,rh);
 bodies.push({descriptor,b,chunks});previous=rh;
}
assert.equal(previous,vector.statement.head.hash);assert.equal(bodies[0].descriptor.recordHash,vector.statement.historyId);
const index=createStructuralIndex(namespaceId);for(const b of bodies)assert.equal(index.append(bytes(b.descriptor),b.chunks).status,'APPENDED_STRUCTURAL');
const knownHead={hash:previous,position:6};assert.equal(index.coverage(bytes(knownHead)).structuralCoverage,true);assert.equal(index.coverage(bytes(knownHead)).availabilityVerified,false);
const retained=index.snapshot(),one=bodies[0],rechunk=clone(one.descriptor);rechunk.chunks=chunkRows([one.b]);
const duplicate=index.append(bytes(rechunk),[one.b]);assert.equal(duplicate.status,'DUPLICATE');assert.equal(duplicate.entry,retained.entries[0]);assert.equal(duplicate.head,retained.head);
const cases=[];
function refusal(name,descriptor,chunks,reason,append=false){const before=canonicalEncode(index.snapshot());let error;try{append?index.append(bytes(descriptor),chunks):verifyBodyDescriptor(bytes(descriptor),chunks)}catch(e){error=e}assert(error,name);assert.equal(error.code,'DESCRIPTOR_INVALID');assert.equal(error.message,reason);assert.equal(canonicalEncode(index.snapshot()),before);cases.push({name,operation:append?'appendToCompletePrefix':'verifyBody',descriptor,chunkHex:chunks.map(x=>x.toString('hex')),expected:{code:'DESCRIPTOR_INVALID',reason}})}
const six=bodies[6];
refusal('reordered-chunks',six.descriptor,[...six.chunks].reverse(),'CHUNK_LENGTH');
refusal('truncated-body',six.descriptor,[...six.chunks.slice(0,-1),six.chunks.at(-1).subarray(0,six.chunks.at(-1).length-1)],'CHUNK_LENGTH');
const wrongPrev=clone(six.descriptor);wrongPrev.previousHash='0x'+'00'.repeat(32);refusal('wrong-previousHash',wrongPrev,six.chunks,'RECORD_HASH');
const wrongRecord=clone(six.descriptor);wrongRecord.recordHash='0x'+'00'.repeat(32);refusal('wrong-recordHash',wrongRecord,six.chunks,'RECORD_HASH');
const omitted=clone(one.descriptor);delete omitted.previousHash;refusal('omitted-null-previousHash',omitted,one.chunks,'body:CLOSED_FIELDS');
const presentNull=clone(six.descriptor);presentNull.previousHash=null;refusal('null-at-nonzero-position',presentNull,six.chunks,'POSITION_NULL_LINK');
const foreign=clone(one.descriptor);foreign.namespaceId='0x'+'00'.repeat(32);refusal('foreign-namespace',foreign,one.chunks,'NAMESPACE_MISMATCH',true);
const conflictEvent=clone(events[0]);conflictEvent.id='synthetic-conflicting-genesis';const cb=bytes(conflictEvent),cc=split(cb),conflict={...clone(one.descriptor),eventHash:sha(cb),recordHash:hashRecord(null,sha(cb),0),byteLength:cb.length,chunks:chunkRows(cc)};refusal('conflicting-position',conflict,cc,'POSITION_CONFLICT',true);
const partial=createStructuralIndex(namespaceId);partial.append(bytes(one.descriptor),one.chunks);const before=canonicalEncode(partial.snapshot());
assert.throws(()=>partial.append(bytes(six.descriptor),six.chunks),e=>e.code==='DESCRIPTOR_INVALID'&&e.message==='PREFIX_HOLE');assert.equal(canonicalEncode(partial.snapshot()),before);
const missing=partial.coverage(bytes(knownHead));assert.equal(missing.structuralCoverage,false);assert.equal(missing.availabilityVerified,false);
cases.push({name:'hole-before-position-6',operation:'appendAfterPosition0',descriptor:six.descriptor,chunkHex:six.chunks.map(x=>x.toString('hex')),expected:{code:'DESCRIPTOR_INVALID',reason:'PREFIX_HOLE'}});
cases.push({name:'bodies-claim-with-missing-positions',operation:'coverageAfterPosition0',publisherAvailabilityClaim:'BODIES',expectedHead:knownHead,expected:{structuralCoverage:false,availabilityVerified:false}});
const rehashedPrevious=clone(bodies[1].descriptor);rehashedPrevious.previousHash='0x'+'00'.repeat(32);rehashedPrevious.recordHash=hashRecord(rehashedPrevious.previousHash,rehashedPrevious.eventHash,1);
assert.equal(verifyBodyDescriptor(bytes(rehashedPrevious),bodies[1].chunks).recordHash,rehashedPrevious.recordHash);
assert.throws(()=>partial.append(bytes(rehashedPrevious),bodies[1].chunks),e=>e.code==='DESCRIPTOR_INVALID'&&e.message==='PREVIOUS_HASH_MISMATCH');assert.equal(canonicalEncode(partial.snapshot()),before);
cases.push({name:'valid-hash-but-foreign-retained-predecessor',operation:'appendAfterPosition0',descriptor:rehashedPrevious,chunkHex:bodies[1].chunks.map(x=>x.toString('hex')),expected:{code:'DESCRIPTOR_INVALID',reason:'PREVIOUS_HASH_MISMATCH',standaloneDescriptorValid:true}});
const artifacts=[];
function artifact(kind,b,boundBy){const chunks=split(b),descriptor={version:'irontrellis-artifact-descriptor/1',namespaceId,kind,boundBy,byteLength:b.length,chunks:chunkRows(chunks)},checked=verifyArtifactDescriptor(bytes(descriptor),chunks);assert.equal(checked.signatureVerified,false);assert.equal(checked.persistenceVerified,false);artifacts.push({kind,descriptor,b,chunks});return descriptor}
artifact('HEAD_ATTESTATION',bytes(vector.source.attestation),vector.statement.attestationDigest);
artifact('PROFILE_MANIFEST',manifestBytes,namespace.profile.manifestHash);
const envelope=readFileSync(join(root,'conformance/anchor-namespace/fixtures/trust-root.json'));
let error;try{artifact('PROFILE_MANIFEST',envelope,sha(envelope))}catch(e){error=e}assert.equal(error?.code,'DESCRIPTOR_INVALID');
cases.push({name:'profile-envelope-is-not-payload',operation:'verifyArtifact',kind:'PROFILE_MANIFEST',payloadFile:'../anchor-namespace/fixtures/trust-root.json',expected:{code:'DESCRIPTOR_INVALID'}});
const files=new Map();for(const [i,b]of bodies.entries()){files.set(`body-${i}.json`,bytes(b.descriptor));files.set(`body-${i}.canonical.json`,b.b);files.set(`body-${i}.chunks.json`,json(b.chunks.map(x=>x.toString('hex'))))}
for(const a of artifacts){const n=a.kind.toLowerCase().replaceAll('_','-');files.set(`artifact-${n}.json`,bytes(a.descriptor));files.set(`artifact-${n}.canonical.json`,a.b);files.set(`artifact-${n}.chunks.json`,json(a.chunks.map(x=>x.toString('hex'))))}
files.set('cases.json',json({positiveBodies:7,positiveArtifacts:2,duplicateRechunkRetainsOriginal:true,head:knownHead,negative:cases,mode:'STRUCTURAL_ONLY',replayStatus:'NOT_EVALUATED',availabilityVerified:false}));
files.set('provenance.json',json({scope:'ACTUAL_RETAINED_BODY_BYTES_AND_PUBLIC_HEAD_ATTESTATION_STRUCTURAL_DESCRIPTOR_TEST',inputs:[
 {path:vectorPath,sha256:sha(vectorBytes)},{path:historyPath,sha256:sha(historyBytes)},{path:namespacePath,sha256:sha(namespaceBytes)},{path:manifestPath,sha256:sha(manifestBytes)}],
 hashDerivations:['reviewed descriptor implementation','actual Core eventHash/recordHash','explicit independent 93-byte record preimage'],
 noNewReplayOrSignatureVerification:true,noNetwork:true,noSigning:true,noContract:true,canonicalBodiesAreNotOriginalInputWhitespace:true}));
files.set('digests.json',json(Object.fromEntries([...files].map(([n,b])=>[n,{bytes:b.length,sha256:sha(b)}]))));
const out=join(here,'fixtures');if(check)assert.deepEqual(readdirSync(out).sort(),[...files.keys()].sort());else mkdirSync(out,{recursive:true});
for(const[n,b]of files){if(check)assert(readFileSync(join(out,n)).equals(b),'changed fixture '+n);else writeFileSync(join(out,n),b)}
assert(readFileSync(join(root,vectorPath)).equals(vectorBytes));assert(readFileSync(join(root,historyPath)).equals(historyBytes));
console.log(JSON.stringify({status:'PASS',mode:check?'CHECK':'GENERATE',files:files.size,positiveBodies:7,positiveArtifacts:2,negativeCases:cases.length,duplicateRechunk:1,qualifiedEvidence:false}));
