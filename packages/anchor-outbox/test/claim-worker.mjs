import {readFileSync} from 'node:fs';
import {canonicalEncode} from '@ramex-labs/irontrellis';
import {encodeRawStatementCall} from '../src/index.ts';
import {openAnchorOutboxInternalForTests as openAnchorOutbox} from '../src/internal.ts'; // CR-A195-01
const f=JSON.parse(readFileSync(process.argv[3],'utf8')),history=JSON.parse(readFileSync(process.argv[4],'utf8')),canonical=v=>Buffer.from(canonicalEncode(v));
let signerCalls=0,sendCalls=0;
try{
 const o=await openAnchorOutbox({directory:process.argv[2],trustRootBytes:canonical(f.trustRoot),adapterIdentity:f.identity.adapterIdentity,feePolicy:'fixed-synthetic-fee; no replacement',
  historySource:()=>history,observeImmutables:async()=>canonical({destination:f.trustRoot.destination,namespaceId:f.trustRoot.namespaceId,publisher:f.trustRoot.manifest.publisher,chainId:f.trustRoot.manifest.chain.id}),
  connector:{encodeStatementCall:encodeRawStatementCall,submitOnce:async()=>{sendCalls++;},reconcile:async()=>{},reconcileClearance:async()=>{}},
  signTransaction:async()=>{signerCalls++;throw Error('NO_SIGNING');},assertCurrent:()=>{}});
 o.claimAttempt({statementDigest:f.identity.statementDigest,transaction:{...f.transaction,gas:BigInt(f.transaction.gas),gasPrice:BigInt(f.transaction.gasPrice),value:BigInt(f.transaction.value)}});
 console.log(JSON.stringify({won:true,signerCalls,sendCalls}));
}catch(e){console.log(JSON.stringify({won:false,code:e.code??'SAFE_RACE_REFUSAL',signerCalls,sendCalls}));}
