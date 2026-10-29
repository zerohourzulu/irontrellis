import { types } from "node:util";
import { parseTransaction, serializeTransaction, type Hex } from "viem";
import { fields, hash, need, type SelectedProfile } from "./validation.ts";
import type { LegacyTransaction } from "./transaction.ts";
const required=["hash","from","nonce","to","input","chainId","gas","gasPrice","value","r","s","v","blockHash","blockNumber"];
const nonLegacy=["maxFeePerGas","maxPriorityFeePerGas","accessList","maxFeePerBlobGas","blobVersionedHashes","authorizationList"];
const quantity=(x:unknown):x is Hex=>typeof x==="string"&&x.length<=66&&/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/.exec(x)?.[0]===x;
/** A signature scalar r or s: a 32-byte word, or a canonical QUANTITY (no leading zero digit), the form most nodes report.
 * Compared by value; the serialization below binds it to the exact signed bytes (OUTBOX-RS-01). */
const scalar=(x:unknown):x is Hex=>hash(x)||quantity(x);
/** Deliberate adaptation of the reviewed R8 rich-byte projection. Extra unknown
 * RPC metadata is accepted as own data, never claimed universally validated. */
export function bindObservedTransaction(input:unknown,expected:LegacyTransaction,raw:Hex,txHash:Hex):"MATCH"|"CONFLICT"|"INCOMPLETE" {
 let o:Record<string,unknown>;
 try{need(input!==null&&typeof input==="object"&&!types.isProxy(input),"READ_OBSERVATION_INCOMPLETE");const keys=input!==null&&typeof input==="object"?Reflect.ownKeys(input):[];
  o=fields(input,required,keys.filter((k):k is string=>typeof k==="string"&&!required.includes(k)));
 }catch{return "INCOMPLETE";}
 if((Object.hasOwn(o,"type")&&o.type!=="0x0")||nonLegacy.some(k=>Object.hasOwn(o,k)))return "CONFLICT";
 if(!hash(o.hash)||typeof o.from!=="string"||typeof o.to!=="string"||
  ![o.nonce,o.chainId,o.gas,o.gasPrice,o.value,o.v].every(quantity)||!scalar(o.r)||!scalar(o.s)||
  typeof o.input!=="string"||!/^0x(?:[0-9a-f]{2})*$/.test(o.input)||o.input.length>98306||
  !((o.blockHash===null&&o.blockNumber===null)||(hash(o.blockHash)&&quantity(o.blockNumber))))return "INCOMPLETE";
 const sig=parseTransaction(raw);
 const match=o.hash===txHash&&o.from.toLowerCase()===expected.from&&o.to.toLowerCase()===expected.to&&o.input===expected.data&&
  BigInt(o.nonce as string)===BigInt(expected.nonce)&&BigInt(o.chainId as string)===BigInt(expected.chainId)&&
  BigInt(o.gas as string)===expected.gas&&BigInt(o.gasPrice as string)===expected.gasPrice&&BigInt(o.value as string)===expected.value&&
  BigInt(o.v as string)===sig.v&&sig.r!==undefined&&sig.s!==undefined&&BigInt(o.r as string)===BigInt(sig.r)&&BigInt(o.s as string)===BigInt(sig.s)&&
  serializeTransaction(expected,{v:BigInt(o.v as string),r:o.r as Hex,s:o.s as Hex})===raw;
 return match?"MATCH":"CONFLICT";
}
export function observedLegacy(input:unknown,p:SelectedProfile):Readonly<{transaction:LegacyTransaction;raw:Hex;transactionHash:Hex;blockNumber:number;blockHash:Hex}> {
 need(input!==null&&typeof input==="object"&&!types.isProxy(input),"READ_OBSERVATION_INCOMPLETE");
 const keys=Reflect.ownKeys(input);
 const o=fields(input,required,keys.filter((k):k is string=>typeof k==="string"&&!required.includes(k)));
 need((!Object.hasOwn(o,"type")||o.type==="0x0")&&!nonLegacy.some(k=>Object.hasOwn(o,k))&&
  [o.nonce,o.chainId,o.gas,o.gasPrice,o.value,o.v,o.blockNumber].every(quantity)&&scalar(o.r)&&scalar(o.s)&&hash(o.hash)&&hash(o.blockHash)&&
  typeof o.to==="string"&&/^0x[0-9a-f]{40}$/.test(o.to)&&typeof o.from==="string"&&o.from.toLowerCase()===p.publisher&&
  typeof o.input==="string"&&/^0x(?:[0-9a-f]{2})*$/.test(o.input)&&o.input.length<=98306,"READ_OBSERVATION_INCOMPLETE");
 const nonce=Number(BigInt(o.nonce as string)),chainId=Number(BigInt(o.chainId as string)),blockNumber=Number(BigInt(o.blockNumber as string));
 need(Number.isSafeInteger(nonce)&&Number.isSafeInteger(chainId)&&Number.isSafeInteger(blockNumber)&&"eip155:"+chainId===p.chainId,"READ_OBSERVATION_INCOMPLETE");
 const transaction:LegacyTransaction={type:"legacy",chainId,nonce,from:p.publisher,to:o.to as Hex,data:o.input as Hex,
  gas:BigInt(o.gas as string),gasPrice:BigInt(o.gasPrice as string),value:BigInt(o.value as string)};
 const raw=serializeTransaction(transaction,{v:BigInt(o.v as string),r:o.r as Hex,s:o.s as Hex});
 return {transaction,raw,transactionHash:o.hash as Hex,blockNumber,blockHash:o.blockHash as Hex};
}
