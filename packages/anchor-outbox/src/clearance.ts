import { isIdentifier, isProtocolString, isU53, suiteFor, type ContentHash, type HexSignature } from "@ramex-labs/irontrellis";
import { canonicalInput, digest, fields, hash, need, type SelectedProfile } from "./validation.ts";
export type ClearanceObservation=Readonly<{accountNonce:number;txAtNonce:string|null;bytesMatchOurs:boolean|null;includedStatementDigest:ContentHash|null;l1Level:number|null;observedAt:number}>;
export type Clearance=Readonly<{version:"irontrellis-outbox-clearance/1";namespaceId:ContentHash;chainId:string;publisher:string;nonce:number;attemptId:ContentHash|null;
 haltCode:"SIGNING_UNCERTAIN"|"CONSUMED_BY_OTHER"|"OUTBOX_CONFLICT";observed:ClearanceObservation;
 disposition:"RECLAIM_SAME_NONCE_SAME_BYTES"|"NONCE_FOREIGN_CONSUMED"|"CONFLICT_RESOLVED";keyExposure:"KNOWN_OWN_USE"|"COMPROMISE_SUSPECTED"|null;
 canonicalStatementDigest:ContentHash|null;operatorKeyId:string;signature:HexSignature}>;
export function observation(input:unknown,nonce:number):ClearanceObservation {
 const o=fields(input,["accountNonce","txAtNonce","bytesMatchOurs","includedStatementDigest","l1Level","observedAt"]);
 need(isU53(o.accountNonce)&&isU53(o.observedAt)&&(o.txAtNonce===null||isProtocolString(o.txAtNonce))&&(o.bytesMatchOurs===null||typeof o.bytesMatchOurs==="boolean")&&
  (o.includedStatementDigest===null||hash(o.includedStatementDigest))&&(o.l1Level===null||isU53(o.l1Level)),"CLEARANCE_OBSERVED_INVALID");
 need((o.txAtNonce!==null)===(Number(o.accountNonce)>nonce)&&(o.bytesMatchOurs!==null)===(o.txAtNonce!==null)&&(o.l1Level!==null)===(o.txAtNonce!==null)&&
  (o.includedStatementDigest===null||o.txAtNonce!==null),"CLEARANCE_OBSERVED_INVALID");
 return o as unknown as ClearanceObservation;
}
export function decodeClearance(raw:unknown,p:SelectedProfile):Clearance {
 const c=fields(canonicalInput(raw,16384),["version","namespaceId","chainId","publisher","nonce","attemptId","haltCode","observed","disposition","keyExposure","canonicalStatementDigest","operatorKeyId","signature"]);
 need(c.version==="irontrellis-outbox-clearance/1"&&c.namespaceId===p.trustRoot.namespaceId&&c.chainId===p.chainId&&c.publisher===p.publisher&&isU53(c.nonce)&&
  (c.attemptId===null||hash(c.attemptId))&&(c.canonicalStatementDigest===null||hash(c.canonicalStatementDigest))&&isIdentifier(c.operatorKeyId),"CLEARANCE_INVALID");
 observation(c.observed,c.nonce as number);
 const o=c.observed as ClearanceObservation;
 if(c.haltCode==="SIGNING_UNCERTAIN") need(c.disposition==="RECLAIM_SAME_NONCE_SAME_BYTES"&&c.attemptId!==null&&o.bytesMatchOurs!==false&&c.keyExposure===null&&c.canonicalStatementDigest===null,"CLEARANCE_DISPOSITION_INVALID");
 else if(c.haltCode==="CONSUMED_BY_OTHER") need(c.disposition==="NONCE_FOREIGN_CONSUMED"&&c.attemptId!==null&&o.txAtNonce!==null&&o.bytesMatchOurs===false&&
  ["KNOWN_OWN_USE","COMPROMISE_SUSPECTED"].includes(c.keyExposure as string)&&c.canonicalStatementDigest===null,"CLEARANCE_DISPOSITION_INVALID");
 else need(c.haltCode==="OUTBOX_CONFLICT"&&c.disposition==="CONFLICT_RESOLVED"&&c.canonicalStatementDigest!==null&&
  (o.includedStatementDigest===null||c.canonicalStatementDigest===o.includedStatementDigest)&&c.keyExposure===null,"CLEARANCE_DISPOSITION_INVALID");
 const key=p.trustRoot.manifest.operatorKeys.find(k=>k.keyId===c.operatorKeyId),suite=suiteFor("ed25519"),{signature,...unsigned}=c;
 need(key!==undefined&&suite.isSignature(signature)&&suite.verify(digest(unsigned),signature,key.credential),"CLEARANCE_SIGNATURE_INVALID");
 return c as unknown as Clearance;
}
