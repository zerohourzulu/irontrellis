#!/usr/bin/env node
// Pure A167 conformance: actual production helpers, no signer/node/contract.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,readdirSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {encodeProfilePayload,deriveNamespace,encodeTrustRoot,checkStatementBinding} from '../../packages/mcp-gateway/src/anchor-profile/index.ts';
import {canonicalEncode,hashCanonical} from '../../packages/core/dist/index.js';

const here=dirname(fileURLToPath(import.meta.url)),root=join(here,'../..');
assert(process.argv.slice(2).every(x=>x==='--check'),'only --check is supported');
const check=process.argv.includes('--check'),sha=b=>createHash('sha256').update(b).digest('hex');
const inputPath='conformance/anchor-statement/vector.json',original=readFileSync(join(root,inputPath));
const builder=JSON.parse(original),old=builder.statement;
const clone=x=>JSON.parse(JSON.stringify(x)),hex=c=>'0x'+c.repeat(64);
// Independent text derivation for these fixture values, including all control escapes.
function ref(v){
 if(v===null)return 'null';
 if(typeof v==='boolean')return String(v);
 if(typeof v==='number'){assert(Number.isSafeInteger(v)&&!Object.is(v,-0));return String(v)}
 if(typeof v==='string'){assert(v.isWellFormed());return '"'+[...v].map(c=>c==='"'?'\\"':c==='\\'?'\\\\':c.codePointAt(0)<32?'\\u'+c.codePointAt(0).toString(16).padStart(4,'0'):c).join('')+'"'}
 if(Array.isArray(v))return '['+v.map(ref).join(',')+']';
 return '{'+Object.keys(v).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(k=>ref(k)+':'+ref(v[k])).join(',')+'}';
}
const encoded=v=>Buffer.from(ref(v)),digest=v=>'0x'+sha(encoded(v));
function checkBytes(value,actual){assert.equal(actual,ref(value));assert.equal(canonicalEncode(value),actual);assert.equal(hashCanonical(value,'sha256'),digest(value));}
const manifest={version:'irontrellis-profile-manifest/1',id:'synthetic-a167-mainnet-uninstalled',
 domain:clone(old.domain),historyId:old.historyId,genesisEventHash:old.genesisEventHash,
 chain:{id:'eip155:42793'},publisher:'0x'+'44'.repeat(20),
 operatorKeys:[{keyId:'synthetic-public-basepoint',scheme:'ed25519',credential:'0x58'+'66'.repeat(31)}],
 nodes:{evm:{chainId:'eip155:42793',operator:'synthetic-evm-administration'},
 l1:{chainId:'tezos:synthetic-unenrolled',operator:'synthetic-l1-administration'},ownRollup:null},
 bodyStore:null,maxL1HeadLag:null,supersedes:null};
const payload=encodeProfilePayload(encoded(manifest));checkBytes(manifest,payload.canonicalText);
const expectedNamespace={version:'irontrellis-anchor-namespace/1',domain:manifest.domain,historyId:manifest.historyId,
 genesisEventHash:manifest.genesisEventHash,profile:{id:manifest.id,manifestHash:digest(manifest)},chain:{id:manifest.chain.id},publisher:manifest.publisher};
const namespace=deriveNamespace(encoded(manifest));checkBytes(expectedNamespace,namespace.canonicalText);assert.equal(namespace.namespaceId,digest(expectedNamespace));
const trustRoot={version:'irontrellis-profile-trust-root/1',manifest,manifestHash:digest(manifest),namespaceId:namespace.namespaceId,destination:'0x'+'55'.repeat(20)};
const trusted=encodeTrustRoot(encoded(trustRoot));checkBytes(trustRoot,trusted.canonicalText);
assert.deepEqual(trusted.checks,{T1:true,T2:true,T3:true,T4:true,T5:false});
const statement={...clone(old),profile:{id:manifest.id,manifestHash:trustRoot.manifestHash},chain:{id:manifest.chain.id,destination:trustRoot.destination},availability:'ANCHOR_ONLY'};
assert.equal(statement.sequence,0);assert.equal(statement.predecessor,null);assert.equal(statement.previousHead,null);
const positive=checkStatementBinding(encoded(trustRoot),encoded(statement),manifest.publisher);
assert.equal(positive.bindingsMatch,true);assert.equal(Object.keys(positive.equalities).length,8);
assert(Object.values(positive.equalities).every(x=>x===true));checkBytes(statement,canonicalEncode(statement));
for(const result of [payload,namespace,trusted,positive]){assert.equal(result.mode,'UNVERIFIED');assert.equal(result.dispatchAllowed,false);assert.equal(result.instanceImmutablesVerified,false)}
const negative=[];
function refused(name,operation,value,expectedCheck){
 let caught;try{operation==='payload'?encodeProfilePayload(encoded(value)):encodeTrustRoot(encoded(value))}catch(e){caught=e}
 assert(caught,name+' must refuse');assert.equal(caught.code,'TRUST_ROOT_INVALID');assert.equal(caught.check,expectedCheck);
 negative.push({name,operation,input:value,expected:{status:'REFUSED',code:'TRUST_ROOT_INVALID',check:expectedCheck}});
}
function rootMutation(name,fn,stage){const v=clone(trustRoot);fn(v);refused(name,'trustRoot',v,stage)}
rootMutation('manifest-hash-mismatch',v=>v.manifestHash=hex('0'),'T2');
rootMutation('namespace-id-mismatch',v=>v.namespaceId=hex('0'),'T3');
rootMutation('payload-unknown-field',v=>v.manifest.extra=true,'T1');
rootMutation('payload-missing-bodyStore',v=>delete v.manifest.bodyStore,'T1');
rootMutation('namespaceId-inside-payload',v=>v.manifest.namespaceId=v.namespaceId,'T1');
rootMutation('destination-inside-payload',v=>v.manifest.destination=v.destination,'T1');
rootMutation('uppercase-destination',v=>v.destination='0x'+'AB'.repeat(20),'T4');
rootMutation('missing-explicit-null-supersedes',v=>delete v.manifest.supersedes,'T1');
rootMutation('operator-key-id-duplicate',v=>v.manifest.operatorKeys.push(clone(v.manifest.operatorKeys[0])),'T1');
function mismatch(name,key,fn,sender=manifest.publisher){const s=clone(statement);fn(s);const r=checkStatementBinding(encoded(trustRoot),encoded(s),sender);assert.equal(r.bindingsMatch,false);assert.deepEqual(Object.entries(r.equalities).filter(([,v])=>!v).map(([k])=>k),[key]);assert.equal(r.reportProduced,false);negative.push({name,operation:'statementBinding',trustRoot,statement:s,sender,expected:{bindingsMatch:false,failedEqualities:[key],reportProduced:false}})}
mismatch('foreign-manifestHash','manifestHash',s=>s.profile.manifestHash=hex('0'));
mismatch('foreign-destination','destination',s=>s.chain.destination='0x'+'66'.repeat(20));
mismatch('foreign-profileId','profileId',s=>s.profile.id='synthetic-foreign');
mismatch('foreign-domain','domain',s=>s.domain.deploymentId='synthetic-other-domain');
mismatch('foreign-historyId','historyId',s=>s.historyId=hex('1'));
mismatch('foreign-genesisEventHash','genesisEventHash',s=>s.genesisEventHash=hex('2'));
mismatch('foreign-chainId','chainId',s=>s.chain.id='eip155:127823');
mismatch('foreign-publisher','publisher',()=>{},'0x'+'77'.repeat(20));
// Explicit zero is a value distinct from null; it changes the manifest/namespace bytes.
const zeroManifest={...clone(manifest),maxL1HeadLag:0},zeroNamespace=deriveNamespace(encoded(zeroManifest));
assert.notEqual(zeroNamespace.namespaceId,namespace.namespaceId);assert.equal(encodeProfilePayload(encoded(zeroManifest)).value.maxL1HeadLag,0);
const files=new Map([['manifest.json',encoded(manifest)],['trust-root.json',encoded(trustRoot)],['namespace.json',encoded(expectedNamespace)],['statement.json',encoded(statement)],['manifest-maxLag-zero.json',encoded(zeroManifest)]]);
const json=v=>Buffer.from(JSON.stringify(v,null,2)+'\n');
files.set('digests.json',json({manifestHash:trustRoot.manifestHash,namespaceId:trustRoot.namespaceId,
 statementDigest:positive.statementDigest,trustRootEnvelopeDigestDiagnosticOnly:trusted.digest,
 canonicalFiles:Object.fromEntries([...files].map(([n,b])=>[n,{bytes:b.length,sha256:'0x'+sha(b)}]))}));
files.set('cases.json',json({positive:{bindingsMatch:true,equalities:positive.equalities,checks:trusted.checks,
 mode:'UNVERIFIED',dispatchAllowed:false,transactionSenderAuthenticated:false},negative,
 nullVersusZero:{nullNamespaceId:namespace.namespaceId,zeroNamespaceId:zeroNamespace.namespaceId}}));
const modules=['types.ts','common.ts','tezos-identifiers.ts','report.ts','profiles.ts','index.ts'];
files.set('provenance.json',json({scope:'SYNTHETIC_UNINSTALLED_PROFILE_OVER_RETAINED_BUILDER_STATEMENT_BINDINGS',
 source:{path:inputPath,sha256:sha(original)},
 changedStatementFields:['profile.id','profile.manifestHash','chain.destination'],
 retainedStatementFieldsAreNotFreshReplayEvidence:true,
 publicCredential:'Standard public Ed25519 basepoint encoding; no key generation or private material.',
 liveQualification:false,T5:false,contractDeployed:false,signaturesGenerated:0,
 productionSources:modules.map(n=>{const path='packages/mcp-gateway/src/anchor-profile/'+n,b=readFileSync(join(root,path));return{path,sha256:sha(b),bytes:b.length}})}));
const out=join(here,'fixtures');
if(check)assert.deepEqual(readdirSync(out).sort(),[...files.keys()].sort(),'fixture census');else mkdirSync(out,{recursive:true});
for(const[name,b]of files){if(check)assert(readFileSync(join(out,name)).equals(b),'changed fixture '+name);else writeFileSync(join(out,name),b)}
assert(readFileSync(join(root,inputPath)).equals(original),'frozen input changed');
console.log(JSON.stringify({status:'PASS',mode:check?'CHECK':'GENERATE',files:files.size,positiveBinding:1,negativeCases:negative.length,nullVersusZero:1,qualifiedEvidence:false}));
