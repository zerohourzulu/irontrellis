import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,chmodSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalEncode} from '@ramex-labs/irontrellis';
import {parseTransaction,keccak256,serializeTransaction} from 'viem';
import {encodeRawStatementCall,createObservedConnector} from '../src/index.ts';
import {openAnchorOutboxInternalForTests as openAnchorOutbox} from '../src/internal.ts'; // CR-A195-01
import {verifySigned} from '../src/transaction.ts';
import {bindObservedTransaction} from '../src/reconciliation.ts';
const HERE=dirname(fileURLToPath(import.meta.url)),ROOT=resolve(HERE,'../../..');
const f=JSON.parse(readFileSync(resolve(ROOT,'conformance/anchor-attempt/vector.json'),'utf8')),canonical=v=>Buffer.from(canonicalEncode(v));
const history=JSON.parse(readFileSync(resolve(ROOT,f.provenance.history),'utf8'));
const tx={...f.transaction,gas:BigInt(f.transaction.gas),gasPrice:BigInt(f.transaction.gasPrice),value:BigInt(f.transaction.value)};
const d=mkdtempSync(join(realpathSync(tmpdir()),'irontrellis-synthetic-connector-'));chmodSync(d,0o700);
const o=await openAnchorOutbox({directory:d,trustRootBytes:canonical(f.trustRoot),adapterIdentity:f.identity.adapterIdentity,feePolicy:'synthetic-fixed; no replacement',
 historySource:()=>history,observeImmutables:async()=>canonical({destination:f.trustRoot.destination,namespaceId:f.trustRoot.namespaceId,publisher:f.trustRoot.manifest.publisher,chainId:f.trustRoot.manifest.chain.id}),
 connector:{encodeStatementCall:encodeRawStatementCall,submitOnce:async()=>{},reconcile:async()=>{},reconcileClearance:async()=>{}},
 signTransaction:async()=>{throw new Error('NO_TEST_SIGNING');},assertCurrent:()=>{}});
const p=o.selectedProfile,q=n=>'0x'+BigInt(n).toString(16),blockHash='0x'+'bb'.repeat(32);
function rpc(raw,mined=true){
 const t=parseTransaction(raw);
 return {type:'0x0',hash:keccak256(raw),from:p.publisher,nonce:q(t.nonce),to:t.to.toLowerCase(),input:t.data??'0x',chainId:q(t.chainId),
  gas:q(t.gas),gasPrice:q(t.gasPrice),value:q(t.value??0n),r:t.r,s:t.s,v:q(t.v),blockHash:mined?blockHash:null,blockNumber:mined?'0x5':null};
}
const submission={attemptId:f.attemptId,statementDigest:f.identity.statementDigest,transactionHash:f.transactionHash,signedTransaction:f.signedTransaction,publisher:p.publisher,nonce:0};
function setup(){
 const counts={fetch:0,tx:0,receipt:0,nonce:0,index:0,l1:0,retained:0};
 const controls={byHash:rpc(f.signedTransaction),receipt:{transactionHash:f.transactionHash,blockHash,blockNumber:'0x5',status:'0x1'},
  nonce:1,index:rpc(f.signedTransaction),retained:f.identity.statementDigest};
 const reads={transactionByHash:async()=>{counts.tx++;return canonical(controls.byHash);},receiptByHash:async()=>{counts.receipt++;return canonical(controls.receipt);},
  latestNonce:async()=>{counts.nonce++;return canonical({accountNonce:controls.nonce,observedAt:3});},
  minedTransactionAtNonce:async()=>{counts.index++;return canonical(controls.index);},l1Level:async()=>{counts.l1++;return canonical({level:77});},
  retainedStatementDigest:async()=>{counts.retained++;return canonical({digest:controls.retained});}};
 const fetchFn=async(_url,init)=>{counts.fetch++;const request=JSON.parse(init.body);assert.equal(request.method,'eth_sendRawTransaction');assert.equal(init.redirect,'error');
  return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,result:f.transactionHash}),{status:200});};
 return {counts,controls,connector:createObservedConnector({profile:p,endpoint:'http://127.0.0.1/',fetchFn,reads})};
}
test('prepare raw ABI discloses fee policy; actual Core diagnostic cannot dispatch',()=>{
 o.enqueueAnchor({statementBytes:canonical(f.statement),attestationBytes:canonical(f.attestation)});
 const prepared=o.prepareTransaction({statementDigest:f.identity.statementDigest,nonce:0,gas:tx.gas,gasPrice:tx.gasPrice});
 assert.deepEqual(prepared.transaction,tx);assert.equal(prepared.replacementAllowed,false);
 const result=o.verifyAnchor({statementDigest:f.identity.statementDigest});assert.equal(result.prefixReplayVerified,true);
 assert.equal(result.reportProduced,false);assert.equal(result.l1FinalityVerified,false);assert.equal(result.mode,'UNVERIFIED');assert.equal(result.dispatchAllowed,false);
 assert.throws(()=>o.verifyAnchor({statementDigest:f.identity.statementDigest,finalityVerified:true}));
});
test('integrated new raw-anchor signed submission uses exactly one actual viem request',async()=>{
 const s=setup(),result=await s.connector.submitOnce(submission);assert.equal(s.counts.fetch,1);assert.equal(result.status,'UNKNOWN');assert.equal(result.dispatchAllowed,false);
});
for(const [field,value] of [['attemptId','0x'+'ff'.repeat(32)],['statementDigest','0x'+'ff'.repeat(32)],['transactionHash','0x'+'ff'.repeat(32)],['publisher','0x'+'ff'.repeat(20)],['nonce',1],['signedTransaction',f.signedSubstitutions.data]])
 test('submit joins reserved signed bytes before request '+field,async()=>{
  const s=setup();await assert.rejects(()=>s.connector.submitOnce({...submission,[field]:value}));assert.equal(s.counts.fetch,0);
 });
test('closed submission rejects callback and caller-auth assertions',async()=>{
 const s=setup();let invoked=0;const x={...submission};Object.defineProperty(x,'nonce',{enumerable:true,get(){invoked++;return 0;}});
 await assert.rejects(()=>s.connector.submitOnce(x));assert.equal(invoked,0);assert.equal(s.counts.fetch,0);
 await assert.rejects(()=>s.connector.submitOnce({...submission,authenticated:true}));assert.equal(s.counts.fetch,0);
});
for(const field of Object.keys(f.signedSubstitutions))test('real signer validation rejects substituted '+field,async()=>{
 await assert.rejects(()=>verifySigned(tx,f.signedSubstitutions[field]),e=>e.code==='SIGNER_RESULT_INVALID');
});
test('real low-s/canonical signature gate',async()=>{
 const sig=parseTransaction(f.signedTransaction),order=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
 const highS=serializeTransaction(tx,{v:sig.v===BigInt(tx.chainId)*2n+35n?sig.v+1n:sig.v-1n,r:sig.r,s:('0x'+(order-BigInt(sig.s)).toString(16).padStart(64,'0'))});
 await assert.rejects(()=>verifySigned(tx,highS));await assert.rejects(()=>verifySigned(tx,f.signedTransaction+'00'));
});
test('full matching RPC bytes and receipt is an unqualified included observation',async()=>{
 const s=setup(),r=await s.connector.reconcile(submission);assert.equal(r.status,'INCLUDED_SUCCESS');assert.equal(r.mode,'UNVERIFIED');assert.equal(r.dispatchAllowed,false);
 assert.deepEqual([s.counts.fetch,s.counts.tx,s.counts.receipt],[0,1,1]);
});
for(const [field,value] of [['to','0x'+'ee'.repeat(20)],['input','0x1234'],['value','0x1'],['gas','0x1'],['gasPrice','0x2'],['chainId','0x1'],['type','0x2'],['maxFeePerGas','0x1']])
 test('rich byte reconciliation rejects contradictory '+field,async()=>{
  const s=setup();s.controls.byHash={...s.controls.byHash,[field]:value};assert.equal((await s.connector.reconcile(submission)).status,'CONFLICT');
  assert.equal(s.counts.fetch,0);assert.equal(s.counts.receipt,0);
 });
test('incomplete hash projection never claims a byte match',async()=>{
 const s=setup();s.controls.byHash={hash:f.transactionHash,from:p.publisher,nonce:'0x0'};assert.equal((await s.connector.reconcile(submission)).status,'UNKNOWN');
});
test('latest consumed nonce with absent mined lookup remains UNKNOWN',async()=>{
 const s=setup();s.controls.byHash=null;s.controls.index=null;assert.equal((await s.connector.reconcile(submission)).status,'UNKNOWN');assert.equal(s.counts.fetch,0);
});
test('proven canonical other signed bytes plus latest mined nonce is conflict only',async()=>{
 const s=setup();s.controls.byHash=null;s.controls.index=rpc(f.signedSubstitutions.data);s.controls.retained=null;
 assert.equal((await s.connector.reconcile(submission)).status,'CONSUMED_BY_OTHER');assert.equal(s.counts.fetch,0);
});
test('indexed matching bytes still require a receipt status',async()=>{
 const s=setup();s.controls.byHash=null;s.controls.receipt={...s.controls.receipt,status:'0x0'};
 assert.equal((await s.connector.reconcile(submission)).status,'INCLUDED_REVERTED');
 s.controls.receipt={...s.controls.receipt,blockHash:'0x'+'ee'.repeat(32)};assert.equal((await s.connector.reconcile(submission)).status,'UNKNOWN');
});
test('clearance read uses retained raw custody and separate L1 level',async()=>{
 const s=setup(),r=JSON.parse(Buffer.from(await s.connector.reconcileClearance({namespaceId:p.trustRoot.namespaceId,publisher:p.publisher,nonce:0,
  attemptId:f.attemptId,transactionHash:f.transactionHash,signedTransaction:f.signedTransaction,statementDigest:f.identity.statementDigest,destination:p.destination})).toString());
 assert.equal(r.bytesMatchOurs,true);assert.equal(r.l1Level,77);assert.notEqual(r.l1Level,5);assert.equal(r.includedStatementDigest,f.identity.statementDigest);assert.equal(s.counts.fetch,0);
});
test('clearance consumed nonce without raw custody refuses byte equality',async()=>{
 const s=setup();await assert.rejects(()=>s.connector.reconcileClearance({namespaceId:p.trustRoot.namespaceId,publisher:p.publisher,nonce:0,
  attemptId:f.attemptId,transactionHash:null,signedTransaction:null,statementDigest:f.identity.statementDigest,destination:p.destination}));
 assert.equal(s.counts.fetch,0);
});
test('direct rich binder refuses getters and proxies without executing them',()=>{
 let calls=0;const x=rpc(f.signedTransaction);Object.defineProperty(x,'type',{enumerable:true,get(){calls++;return '0x0';}});
 assert.equal(bindObservedTransaction(x,tx,f.signedTransaction,f.transactionHash),'INCOMPLETE');assert.equal(calls,0);
 const proxy=new Proxy(x,{ownKeys(){calls++;return Reflect.ownKeys(x);}});
 assert.equal(bindObservedTransaction(proxy,tx,f.signedTransaction,f.transactionHash),'INCOMPLETE');assert.equal(calls,0);
});
test('connector diagnostic profile equality path cannot return a qualified report',()=>{
 const s=setup(),r=s.connector.verifyAnchor({statementBytes:canonical(f.statement)});
 assert.equal(r.report,null);assert.equal(r.mode,'UNVERIFIED');assert.equal(r.dispatchAllowed,false);assert.equal(r.prefixReplayVerified,false);
 assert.equal(r.transactionSenderAuthenticated,false);assert.deepEqual([s.counts.fetch,s.counts.tx,s.counts.receipt],[0,0,0]);
 assert.throws(()=>s.connector.verifyAnchor({statementBytes:canonical(f.statement),verified:true}));
});
test('transport type checks refuse coercion and getter callbacks before request',async()=>{
 const {createSingleHttpSender}=await import('../src/index.ts');let calls=0;
 const endpoint={toString(){calls++;return 'http://127.0.0.1/';}};
 assert.throws(()=>createSingleHttpSender({endpoint,fetchFn:async()=>{calls++;}}));assert.equal(calls,0);
 const sender=createSingleHttpSender({endpoint:'http://127.0.0.1/',fetchFn:async()=>{calls++;throw Error('UNEXPECTED');}});
 const x={signedTransaction:f.signedTransaction};Object.defineProperty(x,'transactionHash',{enumerable:true,get(){calls++;return f.transactionHash;}});
 await assert.rejects(()=>sender.submitOnce(x));assert.equal(calls,0);
});
