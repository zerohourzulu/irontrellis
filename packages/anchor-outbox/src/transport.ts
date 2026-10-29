import { http, type Hex } from "viem";
import { fields, hash, LIMITS, need } from "./validation.ts";
/** A single real viem HTTP request path; trusted fetch integration for offline tests.
 * No fallback, wallet, signing action, batching, redirects or caller retry options.
 * Header timeout is not a complete response-body deadline.
 */
export function createSingleHttpSender(input: Readonly<{endpoint:string;fetchFn:typeof fetch}>) {
  const c=fields(input,["endpoint","fetchFn"]);need(typeof c.endpoint==="string"&&typeof c.fetchFn==="function","TRANSPORT_CONFIG_INVALID");
  const url=new URL(c.endpoint);
  need(url.href===c.endpoint && !url.username && !url.password && !url.search && !url.hash && url.pathname==="/" &&
    (url.protocol==="https:" || (url.protocol==="http:" && ["localhost","127.0.0.1","[::1]"].includes(url.hostname))),"TRANSPORT_CONFIG_INVALID");
  const t=http(c.endpoint,{retryCount:0,batch:false,fetchFn:c.fetchFn as typeof fetch,fetchOptions:{redirect:"error",credentials:"omit"},timeout:1000,maxResponseBodySize:1048576})({retryCount:0});
  return Object.freeze({async submitOnce(input:Readonly<{signedTransaction:Hex;transactionHash:Hex}>) {
    const s=fields(input,["signedTransaction","transactionHash"]);need(typeof s.signedTransaction==="string"&&s.signedTransaction.length<=LIMITS.rawTransactionBytes*2+2&&
      /^0x(?:[0-9a-f]{2})+$/.exec(s.signedTransaction)?.[0]===s.signedTransaction&&hash(s.transactionHash),"SUBMISSION_INVALID");
    let status:"UNKNOWN"|"CONFLICT"="UNKNOWN",reason="AMBIGUOUS_TRANSPORT_FAILURE";
    try {const ack=await t.request({method:"eth_sendRawTransaction",params:[s.signedTransaction as Hex]},{retryCount:0,dedupe:false});
      if (ack===s.transactionHash) reason="HASH_ACKNOWLEDGED_NOT_INCLUDED";
      else {status="CONFLICT";reason="HASH_ACKNOWLEDGEMENT_MISMATCH";}
    } catch { /* Never retry or echo server/endpoint exception text. */ }
    return Object.freeze({status,transactionHash:s.transactionHash,reason,mode:"UNVERIFIED",dispatchAllowed:false});
  }});
}
