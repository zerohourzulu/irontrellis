// A-185.2 (DEVIATIONS 55): before enqueueing, the outbox applies A-111.3's signer test to the statement's `/2` attestation and
// refuses an unqualified signer with ATTESTATION_SIGNER_UNQUALIFIED. The anchor-attempt fixture history has no owner policy
// (every key HUMAN), so its enqueue tests are unchanged; this file builds an ATTESTED history whose owner:1 lapses.
import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync,mkdtempSync,readdirSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createPrivateKey,sign as nodeSign} from 'node:crypto';
import {attestHeadSync,canonicalEncode,createLocalDomain,createLocalOwner,eventHash,hashCanonical,historyIdOfGenesis,humanAttestationHash,keyPairFromPrivateKey,projectionHeadAt,replay,rootAt} from '@ramex-labs/irontrellis';
import {deriveNamespace} from '@ramex-labs/irontrellis-mcp-gateway';
import {publicOperator,publicPublisher} from '../../../conformance/anchor-attempt/synthetic-signing-generator.mjs';
import {validateAttestationSigner} from '../src/validation.ts';
import {openAnchorOutboxInternalForTests,SYNTHETIC_TEST_PAIR} from '../src/internal.ts';
const pair=(keyId,n)=>keyPairFromPrivateKey('ed25519',keyId,`0x${n.toString(16).padStart(64,'0')}`);
const pub=p=>({keyId:p.keyId,scheme:'ed25519',credential:p.credential});
// Core's ed25519 signature over the 32 hash bytes (crypto/suites.ts), synchronous so attestHeadSync can use it.
const signSync=p=>{const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(p.privateKey.slice(2),'hex')]),format:'der',type:'pkcs8'});
  return h=>`0x${nodeSign(null,Buffer.from(h.slice(2),'hex'),key).toString('hex')}`;};
const signer=p=>{const sign=signSync(p);return Object.freeze({keyId:p.keyId,scheme:'ed25519',credential:p.credential,signHash:async h=>sign(h),signHashSync:sign});};
const O1=pair('owner:1',0x8001),O2=pair('owner:2',0x8002),AT1=pair('attester:1',0x8301),AT2=pair('attester:2',0x8302);
const human=(domain,subject,attester,expiresAt)=>{
  const body={version:'irontrellis-human-attestation/1',audience:domain,subject:pub(subject),profile:'phl:ceremony/1',attesterKeyId:attester.keyId,evidenceDigest:`0x${'cd'.repeat(32)}`,notBefore:0,expiresAt};
  return {...body,signature:signSync(attester)(humanAttestationHash({...body,signature:''}))};
};
test('A-185.2: an attestation signed by a LAPSED key under ATTESTED is ATTESTATION_SIGNER_UNQUALIFIED; the same key while HUMAN passes',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'irontrellis-outbox-signer-'));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const domain=createLocalDomain();let tick=1000;
  const ownerPolicy={threshold:1,byType:{STATE_CHECKPOINT:1},humanFloor:'ATTESTED',attesters:[pub(AT1),pub(AT2)],attestations:[human(domain,O1,AT1,1500),human(domain,O2,AT2,5000)]};
  const owner=await createLocalOwner({historyFile:join(dir,'history.jsonl'),domain,owner:'operations',controller:'operator',now:()=>tick,signer:signer(O1),witness:false,coOwnerKeys:[pub(O2)],ownerPolicy});
  await owner.createAgent({id:'bea'});
  tick=5000;await owner.advanceEpoch({agent:'bea',from:1,to:2}); // owner:1 LAPSED since 1500; PR_eff admits it up to the horizon
  const state=replay(owner.exportHistory()).state;
  const headAt=position=>({hash:state.eventHistoryHashes[position],position,canonicalTime:state.events[position].timestamp});
  const attest=(p,position)=>attestHeadSync(signer(p),domain,headAt(position),'sha256',{stateRoot:rootAt(state,position),projectionHead:projectionHeadAt(state,position)});
  const statementAt=position=>({head:headAt(position)});
  const late=state.head.position,early=late-1;
  assert.equal(headAt(late).canonicalTime,5000);assert.equal(headAt(early).canonicalTime,1000);
  assert.throws(()=>validateAttestationSigner(statementAt(late),attest(O1,late),state),e=>e.code==='ATTESTATION_SIGNER_UNQUALIFIED','owner:1 is LAPSED at 5000');
  assert.doesNotThrow(()=>validateAttestationSigner(statementAt(early),attest(O1,early),state),'owner:1 is HUMAN at 1000');
  assert.doesNotThrow(()=>validateAttestationSigner(statementAt(early),attest(O2,early),state),'owner:2 is HUMAN at 1000');
});

// J77-07 / J78-11: the same refusal through the outbox's own enqueueAnchor, for both branches of A-111.3's test, with the
// outbox directory unchanged by the refused call; a qualified signer at the same head enqueues, so the signer is the only cause.
const canonical=v=>Buffer.from(canonicalEncode(v));
const listing=dir=>readdirSync(dir,{recursive:true}).map(String).sort();
async function enqueueAt(t,history,state,position){
  const dir=mkdtempSync(join(realpathSync(tmpdir()),'irontrellis-outbox-enqueue-'));chmodSync(dir,0o700);
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const operator=publicOperator(),genesis=state.events[0];
  const manifest={version:'irontrellis-profile-manifest/1',id:SYNTHETIC_TEST_PAIR.profileId,domain:state.genesis.domain,historyId:historyIdOfGenesis(genesis),genesisEventHash:eventHash(genesis),
    chain:{id:SYNTHETIC_TEST_PAIR.chainId},publisher:publicPublisher().address.toLowerCase(),operatorKeys:[{keyId:operator.keyId,scheme:'ed25519',credential:operator.credential}],
    nodes:{evm:{chainId:SYNTHETIC_TEST_PAIR.chainId,operator:'synthetic-evm'},l1:{chainId:'synthetic-l1',operator:'synthetic-l1'},ownRollup:null},bodyStore:null,maxL1HeadLag:null,supersedes:null};
  const derived=deriveNamespace(canonicalEncode(manifest));
  const root={version:'irontrellis-profile-trust-root/1',manifest,manifestHash:derived.manifestHash,namespaceId:derived.namespaceId,destination:'0x00000000000000000000000000000000000a0144'};
  const refused=async()=>{throw new Error('no callback is expected');};
  const outbox=await openAnchorOutboxInternalForTests({directory:dir,trustRootBytes:canonical(root),adapterIdentity:'synthetic-raw-publish-bytes-v1',feePolicy:'fixed-synthetic-fee; no replacement',
    historySource:()=>history,observeImmutables:async()=>canonical({destination:root.destination,namespaceId:root.namespaceId,publisher:manifest.publisher,chainId:manifest.chain.id}),
    connector:{encodeStatementCall:()=>{throw new Error('no callback is expected');},submitOnce:refused,reconcile:refused,reconcileClearance:refused},signTransaction:refused,assertCurrent:()=>{}});
  const head={hash:state.eventHistoryHashes[position],position,canonicalTime:state.events[position].timestamp};
  return {dir,outbox,enqueue(p){
    const attestation=attestHeadSync(signer(p),state.genesis.domain,head,'sha256',{stateRoot:rootAt(state,position),projectionHead:projectionHeadAt(state,position)});
    const statement={version:'irontrellis-anchor-statement/1',domain:state.genesis.domain,historyId:manifest.historyId,genesisEventHash:manifest.genesisEventHash,
      profile:{id:manifest.id,manifestHash:root.manifestHash},head,stateRoot:rootAt(state,position),projectionHead:projectionHeadAt(state,position),attestationDigest:hashCanonical(attestation,'sha256'),
      sequence:0,predecessor:null,previousHead:null,chain:{id:manifest.chain.id,destination:root.destination},evidence:{manifestDigest:null,certificateDigest:null,checkpointEventId:null},availability:'ANCHOR_ONLY'};
    return outbox.enqueueAnchor({statementBytes:canonical(statement),attestationBytes:canonical(attestation)});
  }};
}
async function refusedThenQualified(t,history,unqualified,qualified){
  const state=replay(history).state,f=await enqueueAt(t,history,state,state.head.position),before=listing(f.dir);
  assert.throws(()=>f.enqueue(unqualified),e=>e.code==='ATTESTATION_SIGNER_UNQUALIFIED');
  assert.deepEqual(listing(f.dir),before,'the refused enqueue wrote nothing');
  assert.equal(before.some(n=>n.startsWith('jobs')&&n!=='jobs'),false);
  const job=f.enqueue(qualified);assert.equal(job.statement.head.position,state.head.position);
  assert.notDeepEqual(listing(f.dir),before,'the qualified enqueue wrote its job');
}
test('J77-07 / J78-11 (DECLARED): enqueueAnchor refuses an attestation signed by an AGENT-class owner key with ATTESTATION_SIGNER_UNQUALIFIED and persists nothing; a HUMAN key at the same head enqueues',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'irontrellis-outbox-declared-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const domain=createLocalDomain();
  const owner=await createLocalOwner({historyFile:join(dir,'history.jsonl'),domain,owner:'operations',controller:'operator',now:()=>1000,signer:signer(O1),witness:false,coOwnerKeys:[pub(O2)],
    ownerPolicy:{threshold:1,byType:{STATE_CHECKPOINT:1},keyClasses:{'owner:2':'AGENT'}}});
  await owner.createAgent({id:'bea'});
  await refusedThenQualified(t,owner.exportHistory(),O2,O1);
});
test('J77-07 / J78-11 (ATTESTED): enqueueAnchor refuses an attestation signed by a LAPSED owner key with ATTESTATION_SIGNER_UNQUALIFIED and persists nothing; a HUMAN key at the same head enqueues',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'irontrellis-outbox-attested-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const domain=createLocalDomain();let tick=1000;
  const ownerPolicy={threshold:1,byType:{STATE_CHECKPOINT:1},humanFloor:'ATTESTED',attesters:[pub(AT1),pub(AT2)],attestations:[human(domain,O1,AT1,1500),human(domain,O2,AT2,5000)]};
  const owner=await createLocalOwner({historyFile:join(dir,'history.jsonl'),domain,owner:'operations',controller:'operator',now:()=>tick,signer:signer(O1),witness:false,coOwnerKeys:[pub(O2)],ownerPolicy});
  await owner.createAgent({id:'bea'});
  tick=4000;await owner.advanceEpoch({agent:'bea',from:1,to:2}); // owner:1 LAPSED since 1500; owner:2 HUMAN until 5000
  await refusedThenQualified(t,owner.exportHistory(),O1,O2);
});
