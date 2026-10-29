import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,chmodSync,readdirSync,linkSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {canonicalEncode,hashCanonical} from '@ramex-labs/irontrellis';
import {signSyntheticClearance} from '../../../conformance/anchor-attempt/synthetic-signing-generator.mjs';
import {keccak256,serializeTransaction} from 'viem';
import {openAnchorOutbox,encodeRawStatementCall,decodeClearance,createSingleHttpSender} from '../src/index.ts';
import {openAnchorOutboxInternalForTests} from '../src/internal.ts'; // CR-A195-01: the fixture is the synthetic test pair
const HERE=dirname(fileURLToPath(import.meta.url)),ROOT=resolve(HERE,'../../..');
const f=JSON.parse(readFileSync(resolve(ROOT,'conformance/anchor-attempt/vector.json'),'utf8'));
const history=JSON.parse(readFileSync(resolve(ROOT,f.provenance.history),'utf8')),canonical=v=>Buffer.from(canonicalEncode(v));
const tx={...f.transaction,gas:BigInt(f.transaction.gas),gasPrice:BigInt(f.transaction.gasPrice),value:BigInt(f.transaction.value)};
const directory=()=>{const d=mkdtempSync(join(realpathSync(tmpdir()),'irontrellis-synthetic-outbox-'));chmodSync(d,0o700);return d;};
const zeroObservation={accountNonce:0,txAtNonce:null,bytesMatchOurs:null,includedStatementDigest:null,l1Level:null,observedAt:0};
function setup(overrides={}) {
 const counts={sign:0,send:0,reconcile:0,nonceRead:0,immutableRead:0};
 const control={halt:false,hook:()=>{},signResult:f.signedTransaction,observed:zeroObservation,
  submit:{status:'UNKNOWN',transactionHash:f.transactionHash,reason:'SYNTHETIC_AMBIGUOUS'},
  reconcile:{status:'PENDING',transactionHash:f.transactionHash,reason:'SYNTHETIC_PENDING'}};
 const d=overrides.directory??directory();
 const options={directory:d,trustRootBytes:canonical(f.trustRoot),adapterIdentity:f.identity.adapterIdentity,feePolicy:'fixed-synthetic-fee; no replacement',
  historySource:()=>history,observeImmutables:async()=>{counts.immutableRead++;return canonical({destination:f.trustRoot.destination,namespaceId:f.trustRoot.namespaceId,publisher:f.trustRoot.manifest.publisher,chainId:f.trustRoot.manifest.chain.id});},
  connector:{encodeStatementCall:encodeRawStatementCall,submitOnce:async()=>{counts.send++;return control.submit;},
   reconcile:async()=>{counts.reconcile++;return control.reconcile;},reconcileClearance:async()=>{counts.nonceRead++;return canonical(control.observed);}},
  signTransaction:async()=>{counts.sign++;return control.signResult;},assertCurrent:()=>{if(control.halt)throw new Error('SYNTHETIC_STOPPED');},
  boundaryHook:p=>control.hook(p),...overrides};
 return {counts,control,options,d,open:()=>openAnchorOutboxInternalForTests(options)};
}
const enqueue=o=>o.enqueueAnchor({statementBytes:canonical(f.statement),attestationBytes:canonical(f.attestation)});
const claim=o=>o.claimAttempt({statementDigest:f.identity.statementDigest,transaction:tx});
const refuse=(fn,code)=>assert.throws(fn,e=>e.code===code),refuseAsync=(fn,code)=>assert.rejects(fn,e=>e.code===code);
function fault(s,target){s.control.hook=p=>{if(p===target){s.control.hook=()=>{};throw new Error('SYNTHETIC_CRASH');}};}
const signedClearance=signSyntheticClearance;

test('SYNTHETIC fixture independent statement and closed-eight identity hashes',()=>{
 assert.equal(f.scope,'SYNTHETIC_TEST_ONLY');assert.equal(f.dispatchAllowed,false);assert.equal(tx.chainId,31337);
 assert.equal('0x'+createHash('sha256').update(canonical(f.statement)).digest('hex'),f.identity.statementDigest);
 assert.equal('0x'+createHash('sha256').update(canonical(f.identity)).digest('hex'),f.attemptId);
 assert.equal(keccak256(serializeTransaction(tx)),f.identity.unsignedTxDigest);assert.equal(keccak256(f.signedTransaction),f.transactionHash);
 assert.equal(canonical(f.statement).toString('hex'),f.canonicalStatement);
});
test('replay-bound idempotence and real signed custody first-send/no-resend',async()=>{
 const s=setup(),o=await s.open();assert.deepEqual(enqueue(o),enqueue(o));assert.equal(claim(o).attemptId,f.attemptId);
 const result=await o.advanceAttempt(f.attemptId);assert.equal(result.mode,'UNVERIFIED');assert.equal(result.dispatchAllowed,false);
 assert.deepEqual([s.counts.sign,s.counts.send,s.counts.reconcile],[1,1,0]);
 await o.advanceAttempt(f.attemptId);assert.deepEqual([s.counts.sign,s.counts.send,s.counts.reconcile],[1,1,1]);
});
test('closed configuration and T5 failures precede signer/send',async()=>{
 const s=setup({observeImmutables:async()=>canonical(zeroObservation)});await refuseAsync(()=>s.open(),'INVALID_INPUT');
 assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
 let calls=0;const x=setup();Object.defineProperty(x.options,'adapterIdentity',{enumerable:true,get(){calls++;return 'fake';}});
 await refuseAsync(()=>x.open(),'INVALID_INPUT');assert.equal(calls,0);
});
for(const [field,value] of [['stateRoot','0x'+'ee'.repeat(32)],['attestationDigest','0x'+'ee'.repeat(32)],['head',{...f.statement.head,hash:'0x'+'ee'.repeat(32)}],
 ['profile',{...f.statement.profile,manifestHash:'0x'+'ee'.repeat(32)}],['domain',{...f.statement.domain,deploymentId:'foreign'}]])
 test('enqueue rejects actual replay substitution '+field,async()=>{
  const s=setup(),o=await s.open();assert.throws(()=>o.enqueueAnchor({statementBytes:canonical({...f.statement,[field]:value}),attestationBytes:canonical(f.attestation)}));
  assert.deepEqual(readdirSync(join(s.d,'jobs')),[]);assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
 });
for(const suffix of ['\n',' ','\r\n'])test('exact statement bytes refuse suffix '+JSON.stringify(suffix),async()=>{
 const s=setup(),o=await s.open();refuse(()=>o.enqueueAnchor({statementBytes:Buffer.concat([canonical(f.statement),Buffer.from(suffix)]),attestationBytes:canonical(f.attestation)}),'INVALID_CANONICAL_BYTES');
});
test('one account claim wins for two independent cores',async()=>{
 const s=setup(),a=await s.open(),b=await s.open();enqueue(a);
 const results=await Promise.allSettled([Promise.resolve().then(()=>claim(a)),Promise.resolve().then(()=>claim(b))]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
for(const label of ['JOB','SEQUENCE_INDEX','PREDECESSOR_INDEX'])for(const side of ['before','after'])
 test('enqueue fault '+side+':'+label+' is completable without callbacks',async()=>{
  const s=setup(),o=await s.open();fault(s,side+':'+label);assert.throws(()=>enqueue(o));const resumed=await s.open();enqueue(resumed);claim(resumed);
  assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
 });
for(const label of ['ACCOUNT_RESERVATION','NONCE_RESERVATION','ATTEMPT'])for(const side of ['before','after'])
 test('claim fault '+side+':'+label+' recovers exact reservation',async()=>{
  const s=setup(),o=await s.open();enqueue(o);fault(s,side+':'+label);assert.throws(()=>claim(o));const resumed=await s.open();
  if(label==='ACCOUNT_RESERVATION'&&side==='before')claim(resumed);
  await resumed.advanceAttempt(f.attemptId);assert.deepEqual([s.counts.sign,s.counts.send],[1,1]);
 });
for(const [label,side,expected] of [
 ['SIGN_STARTED','before',[1,1,0]],['SIGN_STARTED','after',[0,0,0]],
 ['SIGNED','before',[1,0,0]],['SIGNED','after',[1,1,0]],
 ['SUBMISSION_STARTED','before',[1,1,0]],['SUBMISSION_STARTED','after',[1,0,1]],
 ['OBSERVATION','before',[1,1,1]],['OBSERVATION','after',[1,1,1]]
])test('callback ladder fault '+side+':'+label+' exact counts',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);fault(s,side+':'+label);await assert.rejects(()=>o.advanceAttempt(f.attemptId));
 const resumed=await s.open();await resumed.advanceAttempt(f.attemptId);assert.deepEqual([s.counts.sign,s.counts.send,s.counts.reconcile],expected);
});
test('stop after SIGN_STARTED fsync prevents signer',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);s.control.hook=p=>{if(p==='after:SIGN_STARTED')s.control.halt=true;};
 await assert.rejects(()=>o.advanceAttempt(f.attemptId));assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
test('stop after SUBMISSION_STARTED fsync leaves unknown with zero send',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);s.control.hook=p=>{if(p==='after:SUBMISSION_STARTED')s.control.halt=true;};
 assert.equal((await o.advanceAttempt(f.attemptId)).status,'OUTCOME_UNKNOWN');assert.deepEqual([s.counts.sign,s.counts.send],[1,0]);
});
test('substituted signer bytes halt and never sign again',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);s.control.signResult=f.signedTransaction.slice(0,-2)+'00';
 await refuseAsync(()=>o.advanceAttempt(f.attemptId),'SIGNER_RESULT_INVALID');await refuseAsync(()=>o.advanceAttempt(f.attemptId),'OUTBOX_HALTED');
 assert.deepEqual([s.counts.sign,s.counts.send],[1,0]);
});
test('single-link custody refusal before send',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);fault(s,'after:SIGNED');await assert.rejects(()=>o.advanceAttempt(f.attemptId));
 const path=join(s.d,'jobs',f.identity.statementDigest,'attempt-1.signed.json');linkSync(path,path+'.extra-link');
 await assert.rejects(()=>o.advanceAttempt(f.attemptId));assert.deepEqual([s.counts.sign,s.counts.send],[1,0]);
});
for(const vector of f.clearances)test('clearance primitive real signature '+vector.record.disposition,async()=>{
 const s=setup(),o=await s.open();assert.deepEqual(decodeClearance(canonical(vector.record),o.selectedProfile),vector.record);
 refuse(()=>decodeClearance(canonical({...vector.record,operatorKeyId:'publisher-not-an-operator'}),o.selectedProfile),'CLEARANCE_SIGNATURE_INVALID');
});
test('A169 presence/disposition negatives cannot append',async()=>{
 const s=setup(),o=await s.open(),base=f.clearances[0].record;
 for(const change of [{keyExposure:'KNOWN_OWN_USE'},{disposition:'NONCE_FOREIGN_CONSUMED'},{observed:{...base.observed,bytesMatchOurs:false}},{extra:true}])
  assert.throws(()=>decodeClearance(canonical({...base,...change}),o.selectedProfile));
 const {keyExposure,...omitted}=base;assert.throws(()=>decodeClearance(canonical(omitted),o.selectedProfile));assert.deepEqual(readdirSync(join(s.d,'clearances')),[]);
});
async function uncertainty(s,o){enqueue(o);claim(o);fault(s,'after:SIGN_STARTED');await assert.rejects(()=>o.advanceAttempt(f.attemptId));await o.advanceAttempt(f.attemptId);}
test('clearance requires own read agreement; mismatched signed evidence remains appended',async()=>{
 const s=setup(),o=await s.open();await uncertainty(s,o);s.control.observed={...zeroObservation,accountNonce:1,txAtNonce:'0x'+'cc'.repeat(32),bytesMatchOurs:false,l1Level:1};
 assert.equal((await o.clearHalt({clearanceBytes:canonical(f.clearances[0].record)})).status,'CLEARANCE_OBSERVATION_MISMATCH');
 assert.equal(o.status(f.attemptId).status,'HALTED');assert.equal(s.counts.nonceRead,1);
 assert.equal(readdirSync(join(s.d,'clearances',f.identity.chainId,f.identity.publisherAddress)).length,1);
});
test('one-time same-nonce same-statement reclaim',async()=>{
 const s=setup(),o=await s.open();await uncertainty(s,o);
 assert.equal((await o.clearHalt({clearanceBytes:canonical(f.clearances[0].record)})).status,'CLEARED');
 assert.equal(claim(o).identity.statementDigest,f.identity.statementDigest);
 await o.advanceAttempt(f.attemptId);assert.deepEqual([s.counts.sign,s.counts.send],[1,1]);
});
for(const label of ['CLEARANCE','RECLAIM','TERMINAL','HALT_RESOLVED'])for(const side of ['before','after'])
 test('clearance fault '+side+':'+label+' never automatically calls signer/send',async()=>{
  const s=setup(),o=await s.open();await uncertainty(s,o);fault(s,side+':'+label);await assert.rejects(()=>o.clearHalt({clearanceBytes:canonical(f.clearances[0].record)}));
  const resumed=await s.open();
  if(side==='after'&&label==='HALT_RESOLVED')assert.equal(resumed.status(f.attemptId).status,'CLEARED_RECLAIM');
  else assert.equal((await resumed.clearHalt({clearanceBytes:canonical(f.clearances[0].record)})).status,'CLEARED');
  assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
 });
test('foreign consumed known-own allows next nonce; compromise stays exposed',async()=>{
 for(const exposure of ['KNOWN_OWN_USE','COMPROMISE_SUSPECTED']){
  const s=setup(),o=await s.open();enqueue(o);claim(o);s.control.submit={status:'CONSUMED_BY_OTHER',transactionHash:f.transactionHash,reason:'SYNTHETIC_FOREIGN'};
  await o.advanceAttempt(f.attemptId);s.control.observed=f.clearances[1].record.observed;
  await o.clearHalt({clearanceBytes:canonical(await signedClearance({...f.clearances[1].record,keyExposure:exposure}))});
  assert.equal(o.status(f.attemptId).status,'FAILED_NONCE_CONSUMED');
  if(exposure==='COMPROMISE_SUSPECTED')refuse(()=>o.claimAttempt({statementDigest:f.identity.statementDigest,transaction:{...tx,nonce:1}}),'PUBLISHER_EXPOSED');
  else assert.equal(o.claimAttempt({statementDigest:f.identity.statementDigest,transaction:{...tx,nonce:1}}).identity.nonce,1);
 }
});
test('conflict survivor supersedes losing local job',async()=>{
 const s=setup(),o=await s.open();enqueue(o);const changed={...f.statement,evidence:{...f.statement.evidence,checkpointEventId:'loser'}};
 refuse(()=>o.enqueueAnchor({statementBytes:canonical(changed),attestationBytes:canonical(f.attestation)}),'OUTBOX_CONFLICT');
 assert.equal((await o.clearHalt({clearanceBytes:canonical(f.clearances[2].record)})).status,'CLEARED');
 refuse(()=>o.claimAttempt({statementDigest:hashCanonical(changed),transaction:{...tx,data:encodeRawStatementCall(canonical(changed))}}),'SUPERSEDED_LOCAL');
 claim(o);assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
test('real viem retry path uses one fetch for each error',async()=>{
 for(const kind of ['throw','429','503','-32603','-32005','bad-json']){
  let count=0;const fetchFn=async(_url,init)=>{count++;assert.equal(init.redirect,'error');assert.equal(init.credentials,'omit');const request=JSON.parse(init.body);
   assert.equal(request.method,'eth_sendRawTransaction');assert.deepEqual(request.params,[f.signedTransaction]);
   if(kind==='throw')throw new Error('synthetic-network');if(kind==='bad-json')return new Response('bad',{status:200});
   if(['429','503'].includes(kind))return new Response('{}',{status:Number(kind)});
   return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,error:{code:Number(kind),message:'synthetic'}}),{status:200});};
  const sender=createSingleHttpSender({endpoint:'http://127.0.0.1/',fetchFn});
  assert.equal((await sender.submitOnce({signedTransaction:f.signedTransaction,transactionHash:f.transactionHash})).status,'UNKNOWN');assert.equal(count,1);
 }
});
test('cross-process O_EXCL account claim exactly one winner and zero callbacks',async()=>{
 const {spawn}=await import('node:child_process');const s=setup(),o=await s.open();enqueue(o);
 const worker=resolve(HERE,'claim-worker.mjs'),fixture=resolve(ROOT,'conformance/anchor-attempt/vector.json'),historyPath=resolve(ROOT,f.provenance.history);
 const launch=()=>new Promise((yes,no)=>{let text='';const child=spawn(process.execPath,['--experimental-strip-types',worker,s.d,fixture,historyPath],{stdio:['ignore','pipe','pipe']});
  child.stdout.on('data',x=>text+=x);child.on('error',no);child.on('exit',status=>{if(status!==0)no(Error('WORKER_FAILED'));else yes(JSON.parse(text.trim()));});});
 const results=await Promise.all(Array.from({length:8},launch));assert.equal(results.filter(x=>x.won).length,1);
 assert.equal(results.reduce((n,x)=>n+x.signerCalls+x.sendCalls,0),0);
});
for(const label of ['PROFILE','PROFILE_OBSERVATION'])for(const side of ['before','after'])
 test('profile durable fault '+side+':'+label+' performs no signer/send',async()=>{
 const s=setup();fault(s,side+':'+label);await assert.rejects(()=>s.open());await s.open();assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
test('signed compromise evidence remains monotone after crash before exposure marker',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);s.control.submit={status:'CONSUMED_BY_OTHER',transactionHash:f.transactionHash,reason:'SYNTHETIC_FOREIGN'};
 await o.advanceAttempt(f.attemptId);s.control.observed=f.clearances[1].record.observed;
 const c=await signedClearance({...f.clearances[1].record,keyExposure:'COMPROMISE_SUSPECTED'});fault(s,'before:PUBLISHER_EXPOSED');
 await assert.rejects(()=>o.clearHalt({clearanceBytes:canonical(c)}));const resumed=await s.open();assert.equal(resumed.status(f.attemptId).publisherExposed,true);
 await resumed.clearHalt({clearanceBytes:canonical(await signedClearance({...f.clearances[1].record,keyExposure:'KNOWN_OWN_USE'}))});
 refuse(()=>resumed.claimAttempt({statementDigest:f.identity.statementDigest,transaction:{...tx,nonce:1}}),'PUBLISHER_EXPOSED');
});
test('clearance signature cannot authorize a second reclaim for a nonce',async()=>{
 const s=setup(),o=await s.open();await uncertainty(s,o);await o.clearHalt({clearanceBytes:canonical(f.clearances[0].record)});claim(o);
 fault(s,'after:SIGN_STARTED');await assert.rejects(()=>o.advanceAttempt(f.attemptId));await o.advanceAttempt(f.attemptId);
 const second=await signedClearance({...f.clearances[0].record,observed:{...zeroObservation,observedAt:1}});await refuseAsync(()=>o.clearHalt({clearanceBytes:canonical(second)}),'RECLAIM_ALREADY_USED');
 assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
test('conflict clearance with reserved unsigned loser allows only canonical statement',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);const survivor={...f.statement,evidence:{...f.statement.evidence,checkpointEventId:'survivor'}},survivorDigest=hashCanonical(survivor);
 refuse(()=>o.enqueueAnchor({statementBytes:canonical(survivor),attestationBytes:canonical(f.attestation)}),'OUTBOX_CONFLICT');
 const c=await signedClearance({...f.clearances[2].record,attemptId:f.attemptId,canonicalStatementDigest:survivorDigest});await o.clearHalt({clearanceBytes:canonical(c)});
 refuse(()=>claim(o),'SUPERSEDED_LOCAL');
 const a=o.claimAttempt({statementDigest:survivorDigest,transaction:{...tx,data:encodeRawStatementCall(canonical(survivor))}});assert.equal(a.identity.statementDigest,survivorDigest);
 assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
test('same-publisher payload/destination migration validates historical terminal generation',async()=>{
 const {deriveNamespace}=await import('@ramex-labs/irontrellis-mcp-gateway');
 const s=setup(),old=await s.open();enqueue(old);claim(old);await old.advanceAttempt(f.attemptId);
 s.control.reconcile={status:'INCLUDED_SUCCESS',transactionHash:f.transactionHash,reason:'SYNTHETIC_INCLUDED'};
 s.control.observed={accountNonce:1,txAtNonce:f.transactionHash,bytesMatchOurs:true,includedStatementDigest:f.identity.statementDigest,l1Level:77,observedAt:0};
 assert.equal((await old.reconcileAttempt(f.attemptId)).status,'INCLUDED_SUCCESS');
 // CR-A195-01: the migrated profile keeps the synthetic test pair's id (its payload and destination change).
 const payload={...f.trustRoot.manifest,supersedes:{namespaceId:f.trustRoot.namespaceId,destination:f.trustRoot.destination,lastStatementDigest:f.identity.statementDigest,lastHead:{hash:f.statement.head.hash,position:f.statement.head.position}}};
 const derived=deriveNamespace(canonical(payload)),root={version:'irontrellis-profile-trust-root/1',manifest:payload,manifestHash:derived.manifestHash,namespaceId:derived.namespaceId,destination:'0x000000000000000000000000000000000000beef'};
 const options={...s.options,trustRootBytes:canonical(root),observeImmutables:async()=>canonical({destination:root.destination,namespaceId:root.namespaceId,publisher:payload.publisher,chainId:payload.chain.id})};
 const next=await openAnchorOutboxInternalForTests(options),st={...f.statement,profile:{id:payload.id,manifestHash:root.manifestHash},chain:{id:payload.chain.id,destination:root.destination}};
 const job=next.enqueueAnchor({statementBytes:canonical(st),attestationBytes:canonical(f.attestation)}),prepared=next.prepareTransaction({statementDigest:job.statementDigest,nonce:1,gas:tx.gas,gasPrice:tx.gasPrice});
 assert.equal(next.claimAttempt({statementDigest:job.statementDigest,transaction:prepared.transaction}).identity.nonce,1);
 assert.equal(next.status(f.attemptId).status,'INCLUDED_SUCCESS');assert.deepEqual([s.counts.sign,s.counts.send],[1,1]);
});
test('A167 malformed/mismatched immutable values never configure profile',async()=>{
 for(const field of ['destination','namespaceId','publisher','chainId']){
  const actual={destination:f.trustRoot.destination,namespaceId:f.trustRoot.namespaceId,publisher:f.trustRoot.manifest.publisher,chainId:f.trustRoot.manifest.chain.id};
  const s=setup({observeImmutables:async()=>canonical({...actual,[field]:'wrong'})});await refuseAsync(()=>s.open(),'TRUST_ROOT_INVALID:T5');assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
 }
});
test('configured operator cannot reuse an actual replay owner credential',async()=>{
 const {deriveNamespace}=await import('@ramex-labs/irontrellis-mcp-gateway');
 const key=history[0].data.ownerKeys[0],payload={...f.trustRoot.manifest,operatorKeys:[{keyId:'clashing-history-owner',scheme:'ed25519',credential:key.credential}]};
 const derived=deriveNamespace(canonical(payload)),root={...f.trustRoot,manifest:payload,manifestHash:derived.manifestHash,namespaceId:derived.namespaceId};
 const s=setup({trustRootBytes:canonical(root)});await refuseAsync(()=>s.open(),'OPERATOR_CREDENTIAL_CLASH');assert.equal(s.counts.immutableRead,0);
});
test('async configuration intake keeps original own-data callback/path snapshot',async()=>{
 const other=directory(),s=setup();let replacedCalls=0;
 s.options.observeImmutables=async()=>{
  s.options.directory=other;s.options.historySource=()=>[];s.options.signTransaction=async()=>{replacedCalls++;throw Error('REPLACED');};
  s.options.connector.submitOnce=async()=>{replacedCalls++;throw Error('REPLACED');};
  s.options.trustRootBytes.fill(0);s.options.feePolicy='replaced';
  return canonical({destination:f.trustRoot.destination,namespaceId:f.trustRoot.namespaceId,publisher:f.trustRoot.manifest.publisher,chainId:f.trustRoot.manifest.chain.id});
 };
 const o=await s.open();assert.equal(o.directory,s.d);assert.equal(readdirSync(other).length,0);enqueue(o);claim(o);await o.advanceAttempt(f.attemptId);
 assert.equal(replacedCalls,0);assert.deepEqual([s.counts.sign,s.counts.send],[1,1]);assert.equal(o.selectedProfile.feePolicy,'fixed-synthetic-fee; no replacement');
});
for(const side of ['before','after'])test('included terminal fault '+side+' never resends',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);await o.advanceAttempt(f.attemptId);
 s.control.reconcile={status:'INCLUDED_SUCCESS',transactionHash:f.transactionHash,reason:'SYNTHETIC_INCLUDED'};
 s.control.observed={accountNonce:1,txAtNonce:f.transactionHash,bytesMatchOurs:true,includedStatementDigest:f.identity.statementDigest,l1Level:77,observedAt:0};
 fault(s,side+':TERMINAL');await assert.rejects(()=>o.reconcileAttempt(f.attemptId));const resumed=await s.open();
 assert.equal((await resumed.advanceAttempt(f.attemptId)).status,'INCLUDED_SUCCESS');assert.deepEqual([s.counts.sign,s.counts.send],[1,1]);
 assert.equal(s.counts.reconcile,side==='before'?2:1);
});
for(const label of ['SUPERSEDED','SURVIVOR','CONFLICT_REUSE'])for(const side of ['before','after'])
 test('conflict effect fault '+side+':'+label+' recovers without callbacks',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);const survivor={...f.statement,evidence:{...f.statement.evidence,checkpointEventId:'survivor'}},survivorDigest=hashCanonical(survivor);
 refuse(()=>o.enqueueAnchor({statementBytes:canonical(survivor),attestationBytes:canonical(f.attestation)}),'OUTBOX_CONFLICT');
 const c=await signedClearance({...f.clearances[2].record,attemptId:f.attemptId,canonicalStatementDigest:survivorDigest});fault(s,side+':'+label);
 await assert.rejects(()=>o.clearHalt({clearanceBytes:canonical(c)}));const resumed=await s.open();await resumed.clearHalt({clearanceBytes:canonical(c)});
 resumed.claimAttempt({statementDigest:survivorDigest,transaction:{...tx,data:encodeRawStatementCall(canonical(survivor))}});assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
test('operator signature is required; publisher and owner signatures refuse',async()=>{
 const s=setup(),o=await s.open(),c=f.clearances[0].record;
 for(const signature of ['0x'+'00'.repeat(65),f.attestation.signature])refuse(()=>decodeClearance(canonical({...c,signature}),o.selectedProfile),'CLEARANCE_SIGNATURE_INVALID');
});
test('same-statement reclaim refuses any gas/fee transaction replacement',async()=>{
 const s=setup(),o=await s.open();await uncertainty(s,o);await o.clearHalt({clearanceBytes:canonical(f.clearances[0].record)});
 refuse(()=>o.claimAttempt({statementDigest:f.identity.statementDigest,transaction:{...tx,gasPrice:2n}}),'RECLAIM_BYTES_INVALID');assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
test('old signer callback is fenced after same-identity authorized reclaim',async()=>{
 const s=setup();let release,started;const start=new Promise(yes=>started=yes);
 s.options.signTransaction=async()=>{s.counts.sign++;if(s.counts.sign===1){started();return new Promise(yes=>release=yes);}return f.signedTransaction;};
 const o=await s.open();enqueue(o);claim(o);const pending=o.advanceAttempt(f.attemptId);await start;
 await o.advanceAttempt(f.attemptId);await o.clearHalt({clearanceBytes:canonical(f.clearances[0].record)});claim(o);
 await o.advanceAttempt(f.attemptId);release(f.signedTransaction);await refuseAsync(()=>pending,'ATTEMPT_TERMINAL');assert.deepEqual([s.counts.sign,s.counts.send],[2,1]);
});

for(const side of ['before','after'])test('new directory sync fault '+side+' recovers with zero callbacks',async()=>{
 const s=setup();fault(s,side+':DIRECTORY_SYNC');await assert.rejects(()=>s.open());await s.open();assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
for(const side of ['before','after'])test('durable foreign observation restores ACCOUNT_HALT after '+side+' crash',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);s.control.submit={status:'CONSUMED_BY_OTHER',transactionHash:f.transactionHash,reason:'SYNTHETIC_FOREIGN'};
 fault(s,side+':ACCOUNT_HALT');await assert.rejects(()=>o.advanceAttempt(f.attemptId));const resumed=await s.open();
 await refuseAsync(()=>resumed.advanceAttempt(f.attemptId),'OUTBOX_HALTED');
 assert.equal(resumed.status(f.attemptId).accountHalt.haltCode,'CONSUMED_BY_OTHER');assert.deepEqual([s.counts.sign,s.counts.send,s.counts.reconcile],[1,1,0]);
});
for(const side of ['before','after'])test('SIGNING_UNCERTAIN ACCOUNT_HALT fault '+side+' never signs',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);fault(s,'after:SIGN_STARTED');await assert.rejects(()=>o.advanceAttempt(f.attemptId));
 fault(s,side+':ACCOUNT_HALT');await assert.rejects(()=>o.advanceAttempt(f.attemptId));const resumed=await s.open();
 if(side==='after')await refuseAsync(()=>resumed.advanceAttempt(f.attemptId),'OUTBOX_HALTED');else assert.equal((await resumed.advanceAttempt(f.attemptId)).status,'HALTED');
 assert.deepEqual([s.counts.sign,s.counts.send,s.counts.reconcile],[0,0,0]);
});
for(const side of ['before','after'])test('HISTORY_HALT conflict fault '+side+' preserves both candidates and zero callbacks',async()=>{
 const s=setup(),o=await s.open();enqueue(o);const changed={...f.statement,evidence:{...f.statement.evidence,checkpointEventId:'loser'}};
 fault(s,side+':HISTORY_HALT');assert.throws(()=>o.enqueueAnchor({statementBytes:canonical(changed),attestationBytes:canonical(f.attestation)}));
 const resumed=await s.open();assert.throws(()=>resumed.enqueueAnchor({statementBytes:canonical(changed),attestationBytes:canonical(f.attestation)}));
 assert.equal(readdirSync(join(s.d,'jobs')).length,2);assert.deepEqual([s.counts.sign,s.counts.send],[0,0]);
});
for(const side of ['before','after'])test('NONCE_RECLAIM fault '+side+' resumes only authorized identical transaction',async()=>{
 const s=setup(),o=await s.open();await uncertainty(s,o);await o.clearHalt({clearanceBytes:canonical(f.clearances[0].record)});
 fault(s,side+':NONCE_RECLAIM');assert.throws(()=>claim(o));const resumed=await s.open();await resumed.advanceAttempt(f.attemptId);assert.deepEqual([s.counts.sign,s.counts.send],[1,1]);
});
test('PUBLISHER_EXPOSED after-create crash remains monotone',async()=>{
 const s=setup(),o=await s.open();enqueue(o);claim(o);s.control.submit={status:'CONSUMED_BY_OTHER',transactionHash:f.transactionHash,reason:'SYNTHETIC_FOREIGN'};await o.advanceAttempt(f.attemptId);
 s.control.observed=f.clearances[1].record.observed;const c=await signedClearance({...f.clearances[1].record,keyExposure:'COMPROMISE_SUSPECTED'});
 fault(s,'after:PUBLISHER_EXPOSED');await assert.rejects(()=>o.clearHalt({clearanceBytes:canonical(c)}));const resumed=await s.open();await resumed.clearHalt({clearanceBytes:canonical(c)});
 refuse(()=>resumed.claimAttempt({statementDigest:f.identity.statementDigest,transaction:{...tx,nonce:1}}),'PUBLISHER_EXPOSED');assert.deepEqual([s.counts.sign,s.counts.send],[1,1]);
});
// ---------------------------------------------------------------- A-195.2 T6 and CR-A195-01
async function onPair(chainId,profileId){
 const {deriveNamespace}=await import('@ramex-labs/irontrellis-mcp-gateway');
 const manifest={...f.trustRoot.manifest,id:profileId,chain:{id:chainId}},derived=deriveNamespace(canonical(manifest));
 const root={version:'irontrellis-profile-trust-root/1',manifest,manifestHash:derived.manifestHash,namespaceId:derived.namespaceId,destination:f.trustRoot.destination};
 return setup({trustRootBytes:canonical(root),observeImmutables:async()=>{return canonical({destination:root.destination,namespaceId:root.namespaceId,publisher:manifest.publisher,chainId});}});
}
test('A-195.2 T6: the public openAnchorOutbox refuses the synthetic fixture pair before the instance read, and opens a pair of the class table',async()=>{
 const {PRODUCTION_ANCHORING_PROFILE,TEST_ANCHORING_PROFILE}=await import('@ramex-labs/irontrellis');
 const s=setup();await refuseAsync(()=>openAnchorOutbox(s.options),'TRUST_ROOT_INVALID:T6');assert.equal(s.counts.immutableRead,0);
 for(const pair of [PRODUCTION_ANCHORING_PROFILE,TEST_ANCHORING_PROFILE]){const p=await onPair(pair.chainId,pair.profileId);assert.ok(await openAnchorOutbox(p.options),pair.profileId);}
});
test('CR-A195-01: the internal test entry admits only the exact synthetic pair; any other pair outside the table is TRUST_ROOT_INVALID:T6 there too',async()=>{
 const {PRODUCTION_ANCHORING_PROFILE}=await import('@ramex-labs/irontrellis');
 const {SYNTHETIC_TEST_PAIR}=await import('../src/internal.ts');
 assert.deepEqual(SYNTHETIC_TEST_PAIR,{chainId:f.trustRoot.manifest.chain.id,profileId:f.trustRoot.manifest.id});
 for(const [chainId,profileId] of [['eip155:31337','synthetic-other'],['eip155:31337',PRODUCTION_ANCHORING_PROFILE.profileId],['eip155:1','synthetic-local-anchor']]){
  const p=await onPair(chainId,profileId);await refuseAsync(()=>openAnchorOutboxInternalForTests(p.options),'TRUST_ROOT_INVALID:T6');assert.equal(p.counts.immutableRead,0,`${chainId} ${profileId}`);
 }
});
