import { canonicalEncode, isU53, type ContentHash } from "@ramex-labs/irontrellis";
import { decodeFunctionData, parseTransaction, type Hex } from "viem";
import { checkStatementBinding, encodeTrustRoot } from "@ramex-labs/irontrellis-mcp-gateway";
import { RAW_STATEMENT_ABI, encodeRawStatementCall } from "./call.ts";
import { createSingleHttpSender } from "./transport.ts";
import { captureTransaction, unsignedDigest, verifySigned, type LegacyTransaction } from "./transaction.ts";
import { canonicalInput, digest, fields, hash, LIMITS, need, profile, type SelectedProfile } from "./validation.ts";
import { bindObservedTransaction, observedLegacy } from "./reconciliation.ts";
import type { Submission, Connector } from "./outbox.ts";
type ReadRequest=Readonly<{chainId:string;publisher:Hex;nonce:number;transactionHash:Hex}>;
/** Install-selected observations, not proof/caller-success hooks. Captured
 * canonical bytes and all report flags remain UNVERIFIED. No invented RPC method. */
export type ReadAdapters=Readonly<{
 transactionByHash(request:ReadRequest):Promise<unknown>;
 receiptByHash(request:ReadRequest):Promise<unknown>;
 latestNonce(request:Readonly<{chainId:string;publisher:Hex}>):Promise<unknown>;
 minedTransactionAtNonce(request:Readonly<{chainId:string;publisher:Hex;nonce:number}>):Promise<unknown>;
 l1Level(request:Readonly<{transactionHash:Hex}>):Promise<unknown>;
 retainedStatementDigest(request:Readonly<{destination:Hex;transactionHash:Hex}>):Promise<unknown>;
}>;
async function captureSubmission(input:unknown,p:SelectedProfile):Promise<Readonly<{submission:Submission;transaction:LegacyTransaction}>> {
 const s=fields(input,["attemptId","statementDigest","transactionHash","signedTransaction","publisher","nonce"]);
 need(hash(s.attemptId)&&hash(s.statementDigest)&&hash(s.transactionHash)&&s.publisher===p.publisher&&isU53(s.nonce)&&
  typeof s.signedTransaction==="string"&&s.signedTransaction.length<=LIMITS.rawTransactionBytes*2+2,"SUBMISSION_INVALID");
 const raw=s.signedTransaction as Hex,parsed=parseTransaction(raw);
 const transaction=captureTransaction({type:parsed.type,chainId:parsed.chainId,nonce:parsed.nonce,from:p.publisher,to:parsed.to?.toLowerCase(),
  gas:parsed.gas,gasPrice:parsed.gasPrice,value:parsed.value??0n,data:parsed.data},p);
 const verified=await verifySigned(transaction,raw);need(verified.transactionHash===s.transactionHash&&transaction.nonce===s.nonce,"SUBMISSION_INVALID");
 const call=decodeFunctionData({abi:RAW_STATEMENT_ABI,data:transaction.data});
 need(call.functionName==="publish","SUBMISSION_INVALID");
 const statementBytes=Buffer.from(call.args[0].slice(2),"hex"),value=canonicalInput(statementBytes,LIMITS.statementBytes);
 need(encodeRawStatementCall(statementBytes)===transaction.data&&digest(value)===s.statementDigest&&
  checkStatementBinding(Buffer.from(canonicalEncode(p.trustRoot)),statementBytes,p.publisher).bindingsMatch,"SUBMISSION_INVALID");
 const identity={statementDigest:s.statementDigest,profileManifestHash:p.manifestHash,adapterIdentity:p.adapterIdentity,chainId:p.chainId,
  destination:p.destination,publisherAddress:p.publisher,nonce:s.nonce,unsignedTxDigest:unsignedDigest(transaction)};
 need(digest(identity)===s.attemptId,"SUBMISSION_INVALID");
 return {submission:s as unknown as Submission,transaction};
}
/** The connector `createObservedConnector` returns: a Connector whose `verifyAnchor` is always present. */
export type ObservedConnector = Connector & Required<Pick<Connector,"verifyAnchor">>;
export function createObservedConnector(options:Readonly<{profile:SelectedProfile;endpoint:string;fetchFn:typeof fetch;reads:ReadAdapters}>):ObservedConnector {
 const c=fields(options,["profile","endpoint","fetchFn","reads"]),p=profile(c.profile),root=encodeTrustRoot(Buffer.from(canonicalEncode(p.trustRoot))).value;
 need(p.id===root.manifest.id&&p.manifestHash===root.manifestHash&&p.publisher===root.manifest.publisher&&p.chainId===root.manifest.chain.id&&p.destination===root.destination,"PROFILE_BINDING_INVALID");
 const adapters=fields(c.reads,["transactionByHash","receiptByHash","latestNonce","minedTransactionAtNonce","retainedStatementDigest","l1Level"]);
 need(Object.values(adapters).every(v=>typeof v==="function"),"READ_ADAPTER_INVALID");
 const reads=adapters as unknown as ReadAdapters,sender=createSingleHttpSender({endpoint:c.endpoint as string,fetchFn:c.fetchFn as typeof fetch});
 const observed=(status:string,transactionHash:Hex,reason:string)=>Object.freeze({status,transactionHash,reason,mode:"UNVERIFIED",dispatchAllowed:false});
 async function nonceObservation(nonce:number,expected:Readonly<{raw:Hex;transactionHash:Hex}>|null) {
  const request=Object.freeze({chainId:p.chainId,publisher:p.publisher}),n=fields(canonicalInput(await reads.latestNonce(request),16384),["accountNonce","observedAt"]);
  need(isU53(n.accountNonce)&&isU53(n.observedAt),"READ_OBSERVATION_INCOMPLETE");
  if(n.accountNonce<=nonce)return {accountNonce:n.accountNonce,txAtNonce:null,bytesMatchOurs:null,includedStatementDigest:null,l1Level:null,observedAt:n.observedAt,sourceBlock:null};
  const input=canonicalInput(await reads.minedTransactionAtNonce({...request,nonce}),131072),tx=observedLegacy(input,p),verified=await verifySigned(tx.transaction,tx.raw);
  need(tx.transaction.nonce===nonce&&verified.transactionHash===tx.transactionHash,"READ_OBSERVATION_INCOMPLETE");
  need(expected!==null,"READ_BYTE_BINDING_UNAVAILABLE");
  const l1=fields(canonicalInput(await reads.l1Level({transactionHash:tx.transactionHash}),16384),["level"]);need(isU53(l1.level),"READ_OBSERVATION_INCOMPLETE");
  let included:ContentHash|null=null;
  if(tx.transaction.to===p.destination){const retained=fields(canonicalInput(await reads.retainedStatementDigest({destination:p.destination,transactionHash:tx.transactionHash}),16384),["digest"]);
   need(retained.digest===null||hash(retained.digest),"READ_OBSERVATION_INCOMPLETE");
   if(retained.digest!==null){const call=decodeFunctionData({abi:RAW_STATEMENT_ABI,data:tx.transaction.data}),rawStatement=Buffer.from(call.args[0].slice(2),"hex");
    need(encodeRawStatementCall(rawStatement)===tx.transaction.data&&digest(canonicalInput(rawStatement,LIMITS.statementBytes))===retained.digest,"READ_OBSERVATION_INCOMPLETE");}
   included=retained.digest as ContentHash|null;}
  return {accountNonce:n.accountNonce,txAtNonce:tx.transactionHash,bytesMatchOurs:expected!==null&&tx.raw===expected.raw,
   includedStatementDigest:included,l1Level:l1.level,observedAt:n.observedAt,sourceBlock:{hash:tx.blockHash,number:tx.blockNumber}};
 }
 return Object.freeze({encodeStatementCall:encodeRawStatementCall,
  verifyAnchor(input:Readonly<{statementBytes:Uint8Array}>){
   const x=fields(input,["statementBytes"]),value=canonicalInput(x.statementBytes,LIMITS.statementBytes),raw=Buffer.from(canonicalEncode(value));
   encodeRawStatementCall(raw);
   need(checkStatementBinding(Buffer.from(canonicalEncode(p.trustRoot)),raw,p.publisher).bindingsMatch,"PROFILE_BINDING_INVALID");
   return Object.freeze({statementDigest:digest(value),report:null,reportProduced:false,mode:"UNVERIFIED",qualifiedFinalityLabel:null,dispatchAllowed:false,refutationResidual:"OPEN",
    prefixReplayVerified:false,attestationVerified:false,transactionSenderAuthenticated:false,l1FinalityVerified:false,
    missingEvidence:["INSTALLER_AUTHENTICATION","ACTUAL_CORE_PREFIX_REPLAY","ATTESTATION","OBSERVED_NODE_IDENTITY","DEPLOYED_RAW_ABI_EQUIVALENCE","CHAIN_INCLUSION","KERNEL_EVIDENCE","L1_FINALITY","PRODUCTION_PROFILE"]});
  },
  async submitOnce(input:Submission){const {submission}=await captureSubmission(input,p);return sender.submitOnce({signedTransaction:submission.signedTransaction,transactionHash:submission.transactionHash});},
  async reconcile(input:Submission){
   const {submission:s,transaction}=await captureSubmission(input,p),request=Object.freeze({chainId:p.chainId,publisher:p.publisher,nonce:s.nonce,transactionHash:s.transactionHash});
   try{
    const tx=canonicalInput(await reads.transactionByHash(request),131072);
    if(tx!==null){const bound=bindObservedTransaction(tx,transaction,s.signedTransaction,s.transactionHash);
     if(bound==="CONFLICT")return observed("CONFLICT",s.transactionHash,"RPC_TRANSACTION_BYTES_CONTRADICT");
     if(bound==="INCOMPLETE")return observed("UNKNOWN",s.transactionHash,"RPC_TRANSACTION_BYTES_INCOMPLETE");
     const o=fields(tx,["blockHash","blockNumber"],Reflect.ownKeys(tx as object).filter((k):k is string=>typeof k==="string"&&!["blockHash","blockNumber"].includes(k)));
     if(o.blockHash===null)return observed("PENDING",s.transactionHash,"MATCHING_SIGNED_BYTES_PENDING");
     const receipt=fields(canonicalInput(await reads.receiptByHash(request),16384),["transactionHash","blockHash","blockNumber","status"]);
     if(receipt.transactionHash!==s.transactionHash||receipt.blockHash!==o.blockHash||receipt.blockNumber!==o.blockNumber||!["0x0","0x1"].includes(receipt.status as string))
      return observed("UNKNOWN",s.transactionHash,"RECEIPT_INCOMPLETE_OR_CONTRADICTORY");
     return observed(receipt.status==="0x1"?"INCLUDED_SUCCESS":"INCLUDED_REVERTED",s.transactionHash,"MATCHING_SIGNED_BYTES_RPC_INCLUDED");
    }
    const own=await nonceObservation(s.nonce,{raw:s.signedTransaction,transactionHash:s.transactionHash});
    if(own.txAtNonce!==null){
     if(!own.bytesMatchOurs)return observed("CONSUMED_BY_OTHER",s.transactionHash,"MINED_OTHER_SIGNED_BYTES_RPC_OBSERVED");
     const receipt=fields(canonicalInput(await reads.receiptByHash(request),16384),["transactionHash","blockHash","blockNumber","status"]);
     if(receipt.transactionHash!==s.transactionHash||receipt.blockHash!==own.sourceBlock?.hash||receipt.blockNumber!=="0x"+own.sourceBlock?.number.toString(16)||!["0x0","0x1"].includes(receipt.status as string))
      return observed("UNKNOWN",s.transactionHash,"CONSUMED_BY_SELF_RECEIPT_INCOMPLETE");
     return observed(receipt.status==="0x1"?"INCLUDED_SUCCESS":"INCLUDED_REVERTED",s.transactionHash,"CONSUMED_BY_SELF_RPC_OBSERVED");
    }
    return observed("UNKNOWN",s.transactionHash,"EXACT_HASH_ABSENT_NONCE_NOT_MINED");
   }catch{return observed("UNKNOWN",s.transactionHash,"READ_OBSERVATION_INCOMPLETE");}
  },
  async reconcileClearance(input){
   const x=fields(input,["namespaceId","publisher","nonce","attemptId","transactionHash","signedTransaction","statementDigest","destination"]);
   need(x.namespaceId===p.trustRoot.namespaceId&&x.publisher===p.publisher&&x.destination===p.destination&&isU53(x.nonce)&&
    (x.attemptId===null||hash(x.attemptId))&&(x.transactionHash===null||hash(x.transactionHash)),"CLEARANCE_READ_INVALID");
   // With no retained raw expected bytes, boolean byte equality cannot be
   // inferred from a hash or account-nonce alone. A separate caller cannot set it.
   let expected:Readonly<{raw:Hex;transactionHash:Hex}>|null=null;
   if(x.signedTransaction!==null){const bound=await captureSubmission({attemptId:x.attemptId,statementDigest:x.statementDigest,transactionHash:x.transactionHash,
     signedTransaction:x.signedTransaction,publisher:x.publisher,nonce:x.nonce},p);expected={raw:bound.submission.signedTransaction,transactionHash:bound.submission.transactionHash};}
   else need(x.transactionHash===null,"CLEARANCE_READ_INVALID");
   const own=await nonceObservation(x.nonce as number,expected);
   const {sourceBlock,...record}=own;return Buffer.from(canonicalEncode(record));
  }});
}
