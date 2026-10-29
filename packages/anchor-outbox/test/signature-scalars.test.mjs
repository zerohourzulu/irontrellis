// OUTBOX-RS-01: rich-byte reconciliation reads a transaction's signature scalars r and s by value. A node may report each as a
// 32-byte word or as a canonical QUANTITY; viem's parseTransaction gives them without leading zero bytes. Before this fix a
// signature whose r or s begins with a zero byte (about 1 in 128 for s, 1 in 256 for r) reconciled as CONFLICT, and every
// quantity shorter than 64 digits as INCOMPLETE. The vectors are deterministic signatures of the public test key 0x…03.
import test from 'node:test';
import assert from 'node:assert/strict';
import {parseTransaction,keccak256} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';
import {bindObservedTransaction,observedLegacy} from '../src/reconciliation.ts';

const account=privateKeyToAccount('0x'+'00'.repeat(31)+'03'),from=account.address.toLowerCase(),to='0x'+'11'.repeat(20);
const profile={publisher:from,chainId:'eip155:31337'},q=n=>'0x'+BigInt(n).toString(16),word=n=>'0x'+BigInt(n).toString(16).padStart(64,'0');
const digits=x=>BigInt(x).toString(16).length;
// nonce → [hex digits of r, of s] (RLP minimal): 126 both full; 127 a 31-byte s; 168 a 31-byte r; 89486 both 31 bytes;
// 5 and 14 an odd-length quantity (63 digits) for s and for r.
const VECTORS={126:[64,64],127:[64,62],168:[62,64],89486:[62,62],5:[64,63],14:[63,64]};
async function vector(nonce){
 const expected={type:'legacy',chainId:31337,nonce,from,to,data:'0x',gas:21000n,gasPrice:1n,value:0n};
 const raw=await account.signTransaction(expected),t=parseTransaction(raw),hash=keccak256(raw);
 assert.deepEqual([digits(t.r),digits(t.s)],VECTORS[nonce],`nonce ${nonce}: the vector's r and s lengths`);
 const rpc=(r,s)=>({type:'0x0',hash,from,to,nonce:q(nonce),chainId:q(31337),gas:q(21000),gasPrice:q(1),value:'0x0',v:q(t.v),r,s,input:'0x',blockHash:'0x'+'22'.repeat(32),blockNumber:'0x5'});
 return {expected,raw,hash,t,rpc};
}

for(const nonce of Object.keys(VECTORS).map(Number)){
 test(`nonce ${nonce}: r and s as words or quantities MATCH, and observedLegacy rebuilds the signed bytes`,async()=>{
  const {expected,raw,hash,t,rpc}=await vector(nonce);
  for(const [form,f] of [['word',word],['quantity',q]]){
   assert.equal(bindObservedTransaction(rpc(f(t.r),f(t.s)),expected,raw,hash),'MATCH',form);
   assert.equal(observedLegacy(rpc(f(t.r),f(t.s)),profile).raw,raw,`observedLegacy, ${form}`);
  }
  assert.equal(bindObservedTransaction(rpc(word(t.r),q(t.s)),expected,raw,hash),'MATCH','mixed forms');
 });
}

test('a different r or s is a CONFLICT, in either form',async()=>{
 for(const nonce of [127,168,89486]){
  const {expected,raw,hash,t,rpc}=await vector(nonce);
  for(const f of [word,q]){
   assert.equal(bindObservedTransaction(rpc(f(BigInt(t.r)+1n),f(t.s)),expected,raw,hash),'CONFLICT',`nonce ${nonce} r+1`);
   assert.equal(bindObservedTransaction(rpc(f(t.r),f(BigInt(t.s)-1n)),expected,raw,hash),'CONFLICT',`nonce ${nonce} s-1`);
  }
 }
});

test('any other spelling of r or s stays INCOMPLETE, in both readers',async()=>{
 const {expected,raw,hash,t,rpc}=await vector(127);
 const shortS=q(t.s);
 // shortS has 62 digits: one more zero digit is a non-minimal quantity; a zero byte in front of 60 digits is neither form.
 const bad={'a leading zero digit':['0x0'+shortS.slice(2),word(t.r)],'a leading zero byte, shorter than a word':['0x00'+shortS.slice(4),word(t.r)],
  'a 33-byte value':['0x00'+word(t.s).slice(2),word(t.r)],'uppercase':[word(t.s).toUpperCase().replace('0X','0x'),word(t.r)],
  'an empty value':['0x',word(t.r)],'a number':[Number(BigInt(t.s)%1000n),word(t.r)]};
 for(const [name,[s,r]] of Object.entries(bad)){
  assert.equal(bindObservedTransaction(rpc(r,s),expected,raw,hash),'INCOMPLETE',name);
  assert.throws(()=>observedLegacy(rpc(r,s),profile),/READ_OBSERVATION_INCOMPLETE/,`observedLegacy, ${name}`);
 }
 const missing=rpc(word(t.r),word(t.s));delete missing.r;
 assert.equal(bindObservedTransaction(missing,expected,raw,hash),'INCOMPLETE','a missing r');
 // A missing field fails observedLegacy's shape check first (INVALID_INPUT, unchanged); its caller reads any throw as UNKNOWN.
 assert.throws(()=>observedLegacy(missing,profile),/INVALID_INPUT/,'observedLegacy, a missing r');
});
