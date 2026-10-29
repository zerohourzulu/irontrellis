import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { canonicalEncode, isU53, type ContentHash } from "@ramex-labs/irontrellis";
import { data, durableCreate, exact, privateDirectory, readPrivate, syncDirectory } from "@ramex-labs/irontrellis-mcp-gateway/data";
import { bytes, canonicalInput, chunks, digest, fields, hash, LIMITS, need, OutboxError, profile, replaySnapshot, statement, unchunk,
  validateAttestationSigner, validateReplayBindings, validateRoleSeparation, type SelectedProfile, type Statement } from "./validation.ts";
import { captureTransaction, restoreTransaction, storedTransaction, unsignedDigest, verifySigned, type LegacyTransaction, type StoredTransaction } from "./transaction.ts";
import { encodeRawStatementCall } from "./call.ts";
import type { Hex } from "viem";
import { loadProfile, restoreProfile, type ProfileLoad } from "./profile.ts";
import { decodeClearance, observation, type ClearanceObservation } from "./clearance.ts";

export type BoundaryHook = (point: string) => void;
export type CurrencyCheck = Readonly<{ phase: "BEFORE_SIGN"|"AFTER_SIGN"|"BEFORE_SEND"; statementDigest: ContentHash; attemptId: ContentHash; namespaceId: ContentHash; publisher: Hex; nonce: number }>;
export type Observation = Readonly<{status:"UNKNOWN"|"PENDING"|"INCLUDED_SUCCESS"|"INCLUDED_REVERTED"|"CONSUMED_BY_OTHER"|"CONFLICT";transactionHash:Hex;reason:string}>;
export type Submission = Readonly<{attemptId:ContentHash;statementDigest:ContentHash;transactionHash:Hex;signedTransaction:Hex;publisher:Hex;nonce:number}>;
/** The executable connector is install-selected, not a caller proof authority.
 * The raw-canonical call encoder's deployed-contract agreement remains a separate gate.
 */
export type Connector = Readonly<{
  encodeStatementCall(statementBytes:Uint8Array):Hex;
  /** Optional: the anchor check (`createObservedConnector` provides it); it produces no verification report in this release. */
  verifyAnchor?(input:Readonly<{statementBytes:Uint8Array}>):Readonly<Record<string,unknown>>;
  submitOnce(input:Submission):Promise<unknown>;
  reconcile(input:Submission):Promise<unknown>;
  reconcileClearance(input:Readonly<{namespaceId:ContentHash;publisher:Hex;nonce:number;attemptId:ContentHash|null;transactionHash:Hex|null;signedTransaction:Hex|null;statementDigest:ContentHash|null;destination:Hex}>):Promise<unknown>;
}>;
export type OutboxOptions = Readonly<{directory:string;trustRootBytes:Uint8Array;adapterIdentity:string;feePolicy:string;historySource:()=>unknown;
  observeImmutables:(request:Readonly<{destination:string;chainId:string}>)=>Promise<unknown>;
  connector:Connector;signTransaction:(transaction:LegacyTransaction)=>Promise<unknown>;assertCurrent:(request:CurrencyCheck)=>void;
  boundaryHook?:BoundaryHook}>;
export type Job = Readonly<{statementDigest:ContentHash;namespaceId:ContentHash;statement:Statement;feePolicy:string;replacementAllowed:false}>;
export type AttemptIdentity = Readonly<{statementDigest:ContentHash;profileManifestHash:ContentHash;adapterIdentity:string;chainId:string;destination:Hex;publisherAddress:Hex;nonce:number;unsignedTxDigest:Hex}>;
export type Attempt = Readonly<{attemptId:ContentHash;identity:AttemptIdentity;transaction:LegacyTransaction;feePolicy:string;replacementAllowed:false}>;
type JobRecord = Readonly<{version:"irontrellis-anchor-outbox-job/1";statementDigest:ContentHash;namespaceId:ContentHash;statementChunks:readonly string[];attestation:unknown}>;
type AttemptRecord = Readonly<{version:"irontrellis-anchor-outbox-attempt/1";attemptId:ContentHash;identity:AttemptIdentity;namespaceId:ContentHash;transaction:StoredTransaction;attemptNumber:number;accountGeneration:number}>;
type SignedRecord = Readonly<{version:"irontrellis-anchor-outbox-signed/1";attemptId:ContentHash;transactionHash:Hex;rawChunks:readonly string[]}>;
type CapturedJob = Readonly<{record:JobRecord;statement:Statement;raw:Buffer}>;
const publicState = Object.freeze({mode:"UNVERIFIED",qualifiedFinalityLabel:null,dispatchAllowed:false,refutationResidual:"OPEN"});
const code = (e:unknown):string|undefined => e!==null && typeof e==="object" && typeof (e as {code?:unknown}).code==="string" ? (e as {code:string}).code : undefined;

export class AnchorOutbox {
  readonly directory:string;
  readonly selectedProfile:SelectedProfile;
  #source:()=>unknown; #connector:Connector; #sign:(transaction:LegacyTransaction)=>Promise<unknown>; #current:(request:CurrencyCheck)=>void; #hook:BoundaryHook|undefined;
  /** Factory token is private to this module; no direct selected-profile bypass. */
  constructor(token:symbol,input:OutboxOptions,loaded:ProfileLoad) {
    need(token===factoryToken,"FACTORY_REQUIRED");
    const c=fields(input,["directory","trustRootBytes","adapterIdentity","feePolicy","historySource","observeImmutables","connector","signTransaction","assertCurrent"],["boundaryHook"]);
    need(typeof c.directory==="string" && typeof c.historySource==="function" && typeof c.signTransaction==="function" && typeof c.assertCurrent==="function" &&
      (c.boundaryHook===undefined || typeof c.boundaryHook==="function"),"INVALID_INPUT");
    this.directory=privateDirectory(c.directory as string);this.selectedProfile=loaded.selected;
    const connector=fields(c.connector,["encodeStatementCall","submitOnce","reconcile","reconcileClearance"],["verifyAnchor"]);
    need(Object.values(connector).every(v=>typeof v==="function"),"CONNECTOR_INVALID");
    this.#connector=connector as unknown as Connector;this.#source=c.historySource as ()=>unknown;this.#sign=c.signTransaction as (transaction:LegacyTransaction)=>Promise<unknown>;
    this.#current=c.assertCurrent as (request:CurrencyCheck)=>void;this.#hook=c.boundaryHook as BoundaryHook|undefined;
    for (const sub of ["jobs","accounts","reservations","histories","clearances","profiles"]) this.#directory(join(this.directory,sub));
    this.#sameCreate(join(this.directory,"profiles",this.selectedProfile.trustRoot.namespaceId,"trust-root.json"),
      {version:"irontrellis-outbox-profile/1",rootChunks:chunks(loaded.rootBytes),adapterIdentity:this.selectedProfile.adapterIdentity,feePolicy:this.selectedProfile.feePolicy},"PROFILE");
    const dir=this.#directory(join(this.directory,"profiles",this.selectedProfile.trustRoot.namespaceId,"observations"));
    this.#append(dir,{version:"irontrellis-outbox-profile-observation/1",observationChunks:chunks(loaded.observationBytes),
      observationDigest:loaded.observationDigest,mode:"UNVERIFIED"},"PROFILE_OBSERVATION");
    this.#refreshExposure();
  }
  #clearanceRecords():ReturnType<typeof decodeClearance>[] {
    const dir=join(this.directory,"clearances",this.selectedProfile.chainId,this.selectedProfile.publisher);
    if(!existsSync(dir))return [];
    const records:ReturnType<typeof decodeClearance>[]=[];
    const names=readdirSync(privateDirectory(dir));need(names.length<=4096,"CLEARANCE_LIMIT");
    for(const name of names){need(/^(0|[1-9][0-9]*)-(0|[1-9][0-9]*)\.json$/.test(name),"CLEARANCE_RECORD_INVALID");
      const record=readPrivate(join(dir,name)),c=fields(record,["version","namespaceId","chainId","publisher","nonce","attemptId","haltCode","observed","disposition","keyExposure","canonicalStatementDigest","operatorKeyId","signature"]);
      need(hash(c.namespaceId),"CLEARANCE_RECORD_INVALID");
      const historical=restoreProfile(readPrivate(join(this.directory,"profiles",c.namespaceId,"trust-root.json")));
      const valid=decodeClearance(Buffer.from(canonicalEncode(c)),historical);
      need(valid.chainId===this.selectedProfile.chainId&&valid.publisher===this.selectedProfile.publisher&&valid.nonce===Number(name.split("-")[0]),"CLEARANCE_RECORD_INVALID");
      records.push(valid);
    }return records;
  }
  #refreshExposure():void {
    for(const valid of this.#clearanceRecords())if(valid.keyExposure==="COMPROMISE_SUSPECTED")this.#sameCreate(join(this.#account(),"publisher-exposed.json"),
      {version:"irontrellis-publisher-exposed/1",namespaceId:valid.namespaceId,publisher:valid.publisher},"PUBLISHER_EXPOSED");
  }
  #directory(path:string):string {
    need(path===this.directory||path.startsWith(this.directory+"/"),"STORAGE_PATH_INVALID");
    const created=mkdirSync(path,{recursive:true,mode:0o700}),canonical=privateDirectory(path);
    if(created!==undefined)this.#hook?.("before:DIRECTORY_SYNC");
    // Persist each parent entry as well as the file's immediate directory.
    // Reopening repeats this even when a crash left an existing new directory.
    for(let current=canonical;;current=dirname(current)){syncDirectory(current);if(current===this.directory)break;}
    if(created!==undefined)this.#hook?.("after:DIRECTORY_SYNC");
    return canonical;
  }
  #write(path:string,value:unknown,label:string):void {
    this.#directory(dirname(path));this.#hook?.(`before:${label}`);durableCreate(path,value);this.#hook?.(`after:${label}`);
  }
  #sameCreate(path:string,value:unknown,label:string):void {
    try {this.#write(path,value,label);} catch(e) {if(code(e)!=="EEXIST") throw e;need(digest(readPrivate(path))===digest(value),"JOURNAL_CONFLICT");}
  }
  #jobPath(d:ContentHash):string {return join(this.directory,"jobs",d,"job.json");}
  #historyPath(namespace:ContentHash):string {return join(this.directory,"histories",namespace);}
  #account():string {return join(this.directory,"accounts",this.selectedProfile.chainId,this.selectedProfile.publisher);}
  #numbered(dir:string,prefix:string):number[] {
    if(!existsSync(dir))return [];
    const numbers=readdirSync(privateDirectory(dir)).filter(n=>new RegExp("^"+prefix+"-[1-9][0-9]*\\.json$").test(n)).map(n=>Number(n.slice(prefix.length+1,-5))).sort((a,b)=>a-b);
    need(numbers.length<=4096 && numbers.every((n,i)=>Number.isSafeInteger(n)&&n===i+1),"JOURNAL_CENSUS_INVALID");return numbers;
  }
  #generation():number {return this.#numbered(this.#account(),"active").length;}
  #active(generation=this.#generation()):string {return join(this.#account(),"active-"+generation+".json");}
  #terminal(r:AttemptRecord):string {return join(this.#account(),"terminal-"+r.accountGeneration+".json");}
  #terminalRecord(r:AttemptRecord):Record<string,unknown>|null {
    if(!existsSync(this.#terminal(r)))return null;
    const t=fields(readPrivate(this.#terminal(r)),["version","attemptId","accountGeneration","status","nextNonce","reclaimStatementDigest","clearanceDigest"]);
    need(t.version==="irontrellis-anchor-outbox-terminal/1"&&t.attemptId===r.attemptId&&t.accountGeneration===r.accountGeneration&&isU53(t.nextNonce)&&
      ["INCLUDED_SUCCESS","INCLUDED_REVERTED","CONSUMED_BY_SELF","CLEARED_RECLAIM","FAILED_NONCE_CONSUMED","CLEARED_CONFLICT","SUPERSEDED_LOCAL"].includes(t.status as string)&&
      (t.reclaimStatementDigest===null||hash(t.reclaimStatementDigest))&&(t.clearanceDigest===null||hash(t.clearanceDigest)),"TERMINAL_RECORD_INVALID");
    return t;
  }
  #append(dir:string,value:unknown,label:string):string {
    this.#directory(dir);
    for(let n=0;n<LIMITS.observations;n++){const path=join(dir,n+".json");if(existsSync(path)){readPrivate(path);continue;}try{this.#write(path,value,label);return path;}catch(e){if(code(e)!=="EEXIST")throw e;}}
    throw new OutboxError("JOURNAL_LIMIT");
  }
  #reservation(nonce:number):string {return join(this.directory,"reservations",this.selectedProfile.chainId,this.selectedProfile.publisher,`${nonce}.json`);}
  #haltDir(namespace?:ContentHash):string {return namespace===undefined?this.#account():this.#historyPath(namespace);}
  #haltPath(namespace?:ContentHash):string {return join(this.#haltDir(namespace),"halt-"+this.#numbered(this.#haltDir(namespace),"halt").length+".json");}
  #unresolved(namespace?:ContentHash):Readonly<{path:string;record:Record<string,unknown>}>|null {
    const dir=this.#haltDir(namespace),count=this.#numbered(dir,"halt").length;if(count===0)return null;
    const path=join(dir,"halt-"+count+".json"),record=fields(readPrivate(path),["version","haltCode","attemptId","namespaceId"]);
    need(record.version==="irontrellis-anchor-outbox-halt/1","HALT_RECORD_INVALID");
    const resolved=path+".resolved.json";
    if(existsSync(resolved)){const r=fields(readPrivate(resolved),["version","haltDigest","clearanceDigest"]);need(r.version==="irontrellis-outbox-halt-resolution/1"&&r.haltDigest===digest(record)&&hash(r.clearanceDigest),"HALT_RECORD_INVALID");return null;}
    return {path,record};
  }
  #readJob(d:ContentHash):CapturedJob {
    need(hash(d),"INVALID_INPUT");const j=exact(data(readPrivate(this.#jobPath(d))),["version","statementDigest","namespaceId","statementChunks","attestation"]);
    need(j.version==="irontrellis-anchor-outbox-job/1" && j.statementDigest===d && hash(j.namespaceId),"JOB_RECORD_INVALID");
    const raw=unchunk(j.statementChunks,LIMITS.statementBytes),s=statement(canonicalInput(raw,LIMITS.statementBytes));need(digest(s)===d,"JOB_RECORD_INVALID");
    return {record:j as unknown as JobRecord,statement:s,raw};
  }
  #validateJob(d:ContentHash):CapturedJob {
    const job=this.#readJob(d),state=replaySnapshot(this.#source());
    need(validateReplayBindings(job.statement,job.record.attestation,state,this.selectedProfile)===job.record.namespaceId,"NAMESPACE_BINDING_INVALID");
    need(!existsSync(join(this.directory,"jobs",d,"superseded.json")),"SUPERSEDED_LOCAL");this.#notHalted(job.record.namespaceId);return job;
  }
  #notHalted(namespace?:ContentHash):void {need(this.#unresolved()===null && (namespace===undefined || this.#unresolved(namespace)===null),"OUTBOX_HALTED");}
  #halt(reason:string,attemptId:ContentHash|null,namespace?:ContentHash):void {
    if(this.#unresolved(namespace)!==null)return;
    const dir=this.#haltDir(namespace),n=this.#numbered(dir,"halt").length+1,path=join(dir,"halt-"+n+".json");
    const record={version:"irontrellis-anchor-outbox-halt/1",haltCode:reason,attemptId,namespaceId:namespace??this.selectedProfile.trustRoot.namespaceId};
    try {this.#write(path,record,namespace===undefined?"ACCOUNT_HALT":"HISTORY_HALT");} catch(e) {if(code(e)!=="EEXIST") throw e;readPrivate(path);}
  }
  enqueueAnchor(input:Readonly<{statementBytes:Uint8Array;attestationBytes:Uint8Array}>):Job {
    const v=fields(input,["statementBytes","attestationBytes"]),raw=bytes(v.statementBytes,LIMITS.statementBytes),s=statement(canonicalInput(raw,LIMITS.statementBytes));
    const attestation=canonicalInput(v.attestationBytes,LIMITS.attestationBytes),state=replaySnapshot(this.#source());
    const namespaceId=validateReplayBindings(s,attestation,state,this.selectedProfile),statementDigest=digest(s);
    validateAttestationSigner(s,attestation as {keyId:string},state); // A-185.2: nothing unqualified is published
    this.#notHalted(namespaceId);
    const migration=this.selectedProfile.trustRoot.manifest.supersedes;
    if(s.sequence===0&&migration!==null){const old=this.#readJob(migration.lastStatementDigest),previous=restoreProfile(readPrivate(join(this.directory,"profiles",migration.namespaceId,"trust-root.json")));
      need(validateReplayBindings(old.statement,old.record.attestation,state,previous)===migration.namespaceId,"MIGRATION_BINDING_INVALID");
      need(old.record.namespaceId===migration.namespaceId&&old.statement.chain.destination===migration.destination&&old.statement.head.hash===migration.lastHead.hash&&
        old.statement.head.position===migration.lastHead.position&&state.eventHistoryHashes[old.statement.head.position]===old.statement.head.hash&&s.head.position>=old.statement.head.position,"MIGRATION_BINDING_INVALID");}
    if (s.predecessor!==null) {
      const old=this.#readJob(s.predecessor);
      need(validateReplayBindings(old.statement,old.record.attestation,state,this.selectedProfile)===old.record.namespaceId,"PREDECESSOR_BINDING_INVALID");
      need(old.record.namespaceId===namespaceId && old.statement.sequence+1===s.sequence &&
        old.statement.head.hash===s.previousHead!.hash && old.statement.head.position===s.previousHead!.position &&
        state.eventHistoryHashes[old.statement.head.position]===old.statement.head.hash && s.head.position>=old.statement.head.position && s.head.canonicalTime>=old.statement.head.canonicalTime,"PREDECESSOR_BINDING_INVALID");
    }
    const record:JobRecord={version:"irontrellis-anchor-outbox-job/1",statementDigest,namespaceId,statementChunks:chunks(raw),attestation};
    this.#sameCreate(this.#jobPath(statementDigest),record,"JOB");
    const index={version:"irontrellis-anchor-outbox-index/1",statementDigest,namespaceId};
    for (const [path,label] of [[join(this.#historyPath(namespaceId),`sequence-${s.sequence}.json`),"SEQUENCE_INDEX"],
      [join(this.#historyPath(namespaceId),`predecessor-${s.predecessor??"GENESIS"}.json`),"PREDECESSOR_INDEX"]] as const) {
      try {const resolved=join(this.#historyPath(namespaceId),"survivor-"+s.sequence+".json");
        if(existsSync(resolved)){const selected=fields(readPrivate(resolved),["version","statementDigest","clearanceDigest"]);need(selected.version==="irontrellis-outbox-survivor/1"&&selected.statementDigest===statementDigest,"SUPERSEDED_LOCAL");}
        else this.#sameCreate(path,index,label);} catch(e) {if(e instanceof OutboxError && e.code==="JOURNAL_CONFLICT") {this.#halt("OUTBOX_CONFLICT",null,namespaceId);throw new OutboxError("OUTBOX_CONFLICT");}throw e;}
    }
    // Matching partial index/job records are completable only before any callback.
    return Object.freeze({statementDigest,namespaceId,statement:s,feePolicy:this.selectedProfile.feePolicy,replacementAllowed:false});
  }
  prepareTransaction(input:Readonly<{statementDigest:ContentHash;nonce:number;gas:bigint;gasPrice:bigint}>):Readonly<{transaction:LegacyTransaction;feePolicy:string;replacementAllowed:false}> {
    const v=fields(input,["statementDigest","nonce","gas","gasPrice"]);need(hash(v.statementDigest),"INVALID_INPUT");
    const job=this.#validateJob(v.statementDigest),transaction=captureTransaction({type:"legacy",chainId:Number(this.selectedProfile.chainId.slice(7)),
      nonce:v.nonce,from:this.selectedProfile.publisher,to:this.selectedProfile.destination,gas:v.gas,gasPrice:v.gasPrice,value:0n,data:encodeRawStatementCall(job.raw)},this.selectedProfile);
    return Object.freeze({transaction,feePolicy:this.selectedProfile.feePolicy,replacementAllowed:false});
  }
  verifyAnchor(input:Readonly<{statementDigest:ContentHash}>):Readonly<Record<string,unknown>> {
    const v=fields(input,["statementDigest"]);need(hash(v.statementDigest),"INVALID_INPUT");const job=this.#validateJob(v.statementDigest);
    return Object.freeze({statementDigest:v.statementDigest,namespaceId:job.record.namespaceId,prefixReplayVerified:true,rootBindingsVerified:true,attestationVerified:true,
      source:"ACTUAL_CORE_REPLAY",T5:"UNVERIFIED_RECORDED_VALUES_MATCH",anchorInclusionVerified:false,nodeIdentityAuthenticated:false,
      kernelEvidenceVerified:false,l1FinalityVerified:false,report:null,reportProduced:false,
      missingEvidence:["INSTALLER_AUTHENTICATION","OBSERVED_NODE_IDENTITY","DEPLOYED_RAW_ABI_EQUIVALENCE","CHAIN_INCLUSION","KERNEL_EVIDENCE","L1_FINALITY","PRODUCTION_PROFILE"],...publicState});
  }
  claimAttempt(input:Readonly<{statementDigest:ContentHash;transaction:LegacyTransaction}>):Attempt {
    const v=fields(input,["statementDigest","transaction"]);need(hash(v.statementDigest),"INVALID_INPUT");const job=this.#validateJob(v.statementDigest as ContentHash);
    const transaction=captureTransaction(v.transaction,this.selectedProfile),call=this.#connector.encodeStatementCall(Buffer.from(job.raw));
    need(typeof call==="string" && transaction.data===call && call===encodeRawStatementCall(job.raw) && call!=="0x","CALLDATA_BINDING_INVALID");
    const identity:AttemptIdentity=Object.freeze({statementDigest:v.statementDigest as ContentHash,profileManifestHash:this.selectedProfile.manifestHash,
      adapterIdentity:this.selectedProfile.adapterIdentity,chainId:this.selectedProfile.chainId,destination:this.selectedProfile.destination,
      publisherAddress:this.selectedProfile.publisher,nonce:transaction.nonce,unsignedTxDigest:unsignedDigest(transaction)});
    const attemptId=digest(identity),record:AttemptRecord={version:"irontrellis-anchor-outbox-attempt/1",attemptId,identity,namespaceId:job.record.namespaceId,
      transaction:storedTransaction(transaction),attemptNumber:this.#numbered(join(this.directory,"jobs",identity.statementDigest),"attempt").length+1,accountGeneration:this.#generation()+1};
    this.#refreshExposure();need(!existsSync(join(this.#account(),"publisher-exposed.json")),"PUBLISHER_EXPOSED");
    if(record.accountGeneration>1){const previous=this.#readAttempt(readPrivate(this.#active(record.accountGeneration-1)));
      need(existsSync(this.#terminal(previous)),"ACCOUNT_BUSY");
      const terminal=this.#terminalRecord(previous)!;
      need(terminal.version==="irontrellis-anchor-outbox-terminal/1"&&terminal.attemptId===previous.attemptId&&terminal.accountGeneration===previous.accountGeneration&&terminal.nextNonce===transaction.nonce,"NONCE_BINDING_INVALID");
      if(terminal.reclaimStatementDigest!==null)need(terminal.reclaimStatementDigest===identity.statementDigest&&transaction.nonce===previous.identity.nonce,"RECLAIM_BYTES_INVALID");
    }
    if(existsSync(this.#reservation(transaction.nonce))){
      const original=this.#readAttempt(readPrivate(this.#reservation(transaction.nonce)));
      const permit=existsSync(join(this.#account(),"reclaim-"+transaction.nonce+".json"))?join(this.#account(),"reclaim-"+transaction.nonce+".json"):join(this.#account(),"conflict-reuse-"+transaction.nonce+".json");
      need(existsSync(permit)&&record.accountGeneration>1&&(record.attemptNumber>1||permit.includes("conflict-reuse-")),"NONCE_ALREADY_RESERVED");
      const allowed=fields(readPrivate(permit),["version","statementDigest","originalAttemptId","clearanceDigest","unsignedTxDigest"]);
      need(["irontrellis-outbox-reclaim/1","irontrellis-outbox-conflict-reuse/1"].includes(allowed.version as string)&&allowed.statementDigest===identity.statementDigest&&allowed.originalAttemptId===original.attemptId&&hash(allowed.clearanceDigest)&&(allowed.unsignedTxDigest===null||allowed.unsignedTxDigest===identity.unsignedTxDigest),"RECLAIM_BYTES_INVALID");
      need(!existsSync(this.#reservation(transaction.nonce)+".reclaimed.json"),"RECLAIM_ALREADY_USED");
    }
    // One account-wide create wins, before either nonce reservation or job attempt.
    try {this.#write(this.#active(record.accountGeneration),record,"ACCOUNT_RESERVATION");} catch(e) {if(code(e)==="EEXIST") throw new OutboxError("ACCOUNT_BUSY");throw e;}
    this.#reserveNonce(record);
    this.#sameCreate(this.#attemptPath(record),record,"ATTEMPT");
    return Object.freeze({attemptId,identity,transaction,feePolicy:this.selectedProfile.feePolicy,replacementAllowed:false});
  }
  #attemptPath(r:AttemptRecord,suffix=""):string {return join(this.directory,"jobs",r.identity.statementDigest,`attempt-${r.attemptNumber}${suffix}.json`);}
  #readAttempt(input:unknown):AttemptRecord {
    const r=exact(data(input),["version","attemptId","identity","namespaceId","transaction","attemptNumber","accountGeneration"]);
    need(r.version==="irontrellis-anchor-outbox-attempt/1" && hash(r.attemptId) && hash(r.namespaceId) && isU53(r.attemptNumber) && Number(r.attemptNumber)>0&&Number(r.attemptNumber)<=4096 && isU53(r.accountGeneration)&&Number(r.accountGeneration)>0&&Number(r.accountGeneration)<=4096,"ATTEMPT_FENCED");
    const identity=exact(r.identity,["statementDigest","profileManifestHash","adapterIdentity","chainId","destination","publisherAddress","nonce","unsignedTxDigest"]);
    need(hash(r.namespaceId),"ATTEMPT_BINDING_INVALID");
    const historical=restoreProfile(readPrivate(join(this.directory,"profiles",r.namespaceId,"trust-root.json")));
    const tx=restoreTransaction(r.transaction,historical);
    need(hash(identity.statementDigest) && digest(identity)===r.attemptId && identity.profileManifestHash===historical.manifestHash && identity.adapterIdentity===historical.adapterIdentity &&
      identity.chainId===historical.chainId && identity.chainId===this.selectedProfile.chainId && identity.destination===historical.destination && identity.publisherAddress===historical.publisher&&identity.publisherAddress===this.selectedProfile.publisher && identity.nonce===tx.nonce && identity.unsignedTxDigest===unsignedDigest(tx),"ATTEMPT_BINDING_INVALID");
    return r as unknown as AttemptRecord;
  }
  #activeRecord(attemptId:ContentHash):AttemptRecord {
    need(hash(attemptId),"INVALID_INPUT");const r=this.#readAttempt(readPrivate(this.#active()));need(r.attemptId===attemptId&&r.accountGeneration===this.#generation()&&r.namespaceId===this.selectedProfile.trustRoot.namespaceId,"ATTEMPT_FENCED");return r;
  }
  #reserveNonce(r:AttemptRecord):void {
    const path=this.#reservation(r.identity.nonce);
    if(existsSync(path)&&digest(readPrivate(path))!==digest(r))this.#sameCreate(path+".reclaimed.json",r,"NONCE_RECLAIM");
    else this.#sameCreate(path,r,"NONCE_RESERVATION");
  }
  #resumeReservation(attemptId:ContentHash):AttemptRecord {
    const r=this.#activeRecord(attemptId);this.#validateJob(r.identity.statementDigest);
    this.#reserveNonce(r);this.#sameCreate(this.#attemptPath(r),r,"ATTEMPT");return r;
  }
  #currency(r:AttemptRecord,phase:CurrencyCheck["phase"]):void {
    need(!existsSync(this.#terminal(r)),"ATTEMPT_TERMINAL");need(!existsSync(join(this.#account(),"publisher-exposed.json")),"PUBLISHER_EXPOSED");this.#notHalted(r.namespaceId);need(this.#activeRecord(r.attemptId).accountGeneration===r.accountGeneration,"ATTEMPT_FENCED");this.#validateJob(r.identity.statementDigest);
    const result=this.#current(Object.freeze({phase,statementDigest:r.identity.statementDigest,attemptId:r.attemptId,namespaceId:r.namespaceId,publisher:r.identity.publisherAddress,nonce:r.identity.nonce}));
    need(result===undefined,"CURRENCY_CHECK_INVALID");
    need(this.#activeRecord(r.attemptId).accountGeneration===r.accountGeneration,"ATTEMPT_FENCED");this.#validateJob(r.identity.statementDigest);this.#notHalted(r.namespaceId);
  }
  async #signed(r:AttemptRecord):Promise<Readonly<{raw:Hex;transactionHash:Hex}>> {
    const s=exact(data(readPrivate(this.#attemptPath(r,".signed"))),["version","attemptId","transactionHash","rawChunks"]);
    need(s.version==="irontrellis-anchor-outbox-signed/1" && s.attemptId===r.attemptId && hash(s.transactionHash),"SIGNED_RECORD_INVALID");
    const verified=await verifySigned(restoreTransaction(r.transaction,this.selectedProfile),`0x${unchunk(s.rawChunks,LIMITS.rawTransactionBytes).toString("hex")}`);
    need(verified.transactionHash===s.transactionHash,"SIGNED_RECORD_INVALID");return verified;
  }
  async advanceAttempt(attemptId:ContentHash):Promise<unknown> {
    const r=this.#activeRecord(attemptId);if(existsSync(this.#terminal(r)))return this.status(attemptId);this.#recoverObservedHalt(r);this.#resumeReservation(attemptId);const signPath=this.#attemptPath(r,".sign-started"),signedPath=this.#attemptPath(r,".signed"),sendPath=this.#attemptPath(r,".submission-started");
    if (!existsSync(signedPath)) {
      if (existsSync(signPath)) {this.#halt("SIGNING_UNCERTAIN",attemptId);return this.status(attemptId);}
      this.#currency(r,"BEFORE_SIGN");
      try {this.#write(signPath,{version:"irontrellis-anchor-outbox-sign-started/1",attemptId},"SIGN_STARTED");}
      catch(e) {if(code(e)==="EEXIST") return this.status(attemptId);throw e;}
      this.#currency(r,"BEFORE_SIGN");
      let raw:unknown;
      try {raw=await this.#sign(restoreTransaction(r.transaction,this.selectedProfile));}
      catch {this.#halt("SIGNING_UNCERTAIN",attemptId);throw new OutboxError("SIGNING_UNCERTAIN");}
      this.#currency(r,"AFTER_SIGN");
      let verified;
      try {verified=await verifySigned(restoreTransaction(r.transaction,this.selectedProfile),raw);}
      catch {this.#halt("SIGNER_RESULT_INVALID",attemptId);throw new OutboxError("SIGNER_RESULT_INVALID");}
      this.#currency(r,"AFTER_SIGN");
      const signed:SignedRecord={version:"irontrellis-anchor-outbox-signed/1",attemptId,transactionHash:verified.transactionHash,rawChunks:chunks(Buffer.from(verified.raw.slice(2),"hex"))};
      this.#write(signedPath,signed,"SIGNED");
    }
    const signed=await this.#signed(r);
    if (existsSync(sendPath)) return this.reconcileAttempt(attemptId);
    this.#currency(r,"BEFORE_SEND");
    try {this.#write(sendPath,{version:"irontrellis-anchor-outbox-submission-started/1",attemptId,transactionHash:signed.transactionHash},"SUBMISSION_STARTED");}
    catch(e) {if(code(e)==="EEXIST") return this.reconcileAttempt(attemptId);throw e;}
    // The last currency check follows fsync and immediately precedes the sole send.
    try {this.#currency(r,"BEFORE_SEND");} catch {return Object.freeze({...this.status(attemptId),status:"OUTCOME_UNKNOWN",reason:"POST_START_CURRENCY_FAILED"});}
    const submission=Object.freeze({attemptId,statementDigest:r.identity.statementDigest,transactionHash:signed.transactionHash,signedTransaction:signed.raw,publisher:r.identity.publisherAddress,nonce:r.identity.nonce});
    let observed:unknown;try {observed=await this.#connector.submitOnce(submission);} catch {observed={status:"UNKNOWN",transactionHash:signed.transactionHash,reason:"AMBIGUOUS_SEND"};}
    this.#observation(r,signed.transactionHash,observed);return this.status(attemptId);
  }
  #readObservations(r:AttemptRecord):Readonly<Record<string,unknown>>[] {
    const dir=join(this.directory,"jobs",r.identity.statementDigest,"attempt-"+r.attemptNumber+".observations");
    if(!existsSync(dir))return [];
    const names=readdirSync(privateDirectory(dir)).sort((a,b)=>Number(a.split(".")[0])-Number(b.split(".")[0]));
    need(names.length<=LIMITS.observations&&names.every((n,i)=>n===i+".json"),"OBSERVATION_RECORD_INVALID");
    if(names.length===0)return [];
    const signed=fields(readPrivate(this.#attemptPath(r,".signed")),["version","attemptId","transactionHash","rawChunks"]);
    need(signed.version==="irontrellis-anchor-outbox-signed/1"&&signed.attemptId===r.attemptId&&hash(signed.transactionHash),"SIGNED_RECORD_INVALID");
    return names.map(n=>{const value=fields(readPrivate(join(dir,n)),["version","attemptId","transactionHash","status","reason","evidence"]);
      need(value.version==="irontrellis-anchor-outbox-observation/1"&&value.attemptId===r.attemptId&&value.transactionHash===signed.transactionHash&&
        ["UNKNOWN","PENDING","INCLUDED_SUCCESS","INCLUDED_REVERTED","CONSUMED_BY_OTHER","CONFLICT"].includes(value.status as string)&&
        typeof value.reason==="string"&&value.reason.length<=512&&value.evidence==="RPC_OBSERVED","OBSERVATION_RECORD_INVALID");return value;});
  }
  #recoverObservedHalt(r:AttemptRecord):void {
    if(existsSync(this.#terminal(r)))return;
    for(const o of this.#readObservations(r))if(o.status==="CONSUMED_BY_OTHER"||o.status==="CONFLICT"){
      this.#halt(o.status==="CONFLICT"?"OUTBOX_CONFLICT":"CONSUMED_BY_OTHER",r.attemptId);return;
    }
  }
  #observation(r:AttemptRecord,txHash:Hex,input:unknown):void {
    need(this.#activeRecord(r.attemptId).accountGeneration===r.accountGeneration&&!existsSync(this.#terminal(r)),"ATTEMPT_FENCED");
    let o;
    try {o=exact(data(input),["status","transactionHash","reason"],["mode","dispatchAllowed"]);
      need(["UNKNOWN","PENDING","INCLUDED_SUCCESS","INCLUDED_REVERTED","CONSUMED_BY_OTHER","CONFLICT"].includes(o.status as string) && o.transactionHash===txHash && typeof o.reason==="string" && o.reason.length<=512,"OBSERVATION_INVALID");}
    catch {o={status:"UNKNOWN",transactionHash:txHash,reason:"MALFORMED_OBSERVATION"};}
    const dir=this.#directory(join(this.directory,"jobs",r.identity.statementDigest,`attempt-${r.attemptNumber}.observations`));
    let appended=false;
    for (let n=0;n<LIMITS.observations;n++) {
      const path=join(dir,`${n}.json`);if (existsSync(path)) {readPrivate(path);continue;}
      try {this.#write(path,{version:"irontrellis-anchor-outbox-observation/1",attemptId:r.attemptId,transactionHash:txHash,status:o.status,reason:o.reason,evidence:"RPC_OBSERVED"},"OBSERVATION");appended=true;break;}
      catch(e) {if(code(e)!=="EEXIST") throw e;}
    }
    need(appended,"OBSERVATION_LIMIT");
    if (o.status==="CONSUMED_BY_OTHER" || o.status==="CONFLICT") this.#halt(o.status==="CONFLICT"?"OUTBOX_CONFLICT":"CONSUMED_BY_OTHER",r.attemptId);
  }
  async reconcileAttempt(attemptId:ContentHash):Promise<unknown> {
    const r=this.#activeRecord(attemptId);if(existsSync(this.#terminal(r)))return this.status(attemptId);this.#recoverObservedHalt(r);
    if (!existsSync(this.#attemptPath(r,".signed"))) {if(existsSync(this.#attemptPath(r,".sign-started")))this.#halt("SIGNING_UNCERTAIN",attemptId);return this.status(attemptId);}
    const signed=await this.#signed(r);
    if (!existsSync(this.#attemptPath(r,".submission-started"))) return this.status(attemptId);
    const submission=Object.freeze({attemptId,statementDigest:r.identity.statementDigest,transactionHash:signed.transactionHash,signedTransaction:signed.raw,publisher:r.identity.publisherAddress,nonce:r.identity.nonce});
    let observed:unknown;try {observed=await this.#connector.reconcile(submission);} catch {observed={status:"UNKNOWN",transactionHash:signed.transactionHash,reason:"READ_OBSERVATION_UNAVAILABLE"};}
    this.#observation(r,signed.transactionHash,observed);
    let captured:Record<string,unknown>|null=null;
    try{captured=fields(observed,["status","transactionHash","reason"],["mode","dispatchAllowed"]);}catch{}
    if(captured!==null&&(captured.status==="INCLUDED_SUCCESS"||captured.status==="INCLUDED_REVERTED")&&this.#unresolved()===null&&this.#unresolved(r.namespaceId)===null){
      const own=await this.#observeNonce(r.identity.nonce,r,signed.transactionHash);
      need(this.#activeRecord(attemptId).accountGeneration===r.accountGeneration&&!existsSync(this.#terminal(r)),"ATTEMPT_FENCED");
      if(own.accountNonce>r.identity.nonce&&own.txAtNonce===signed.transactionHash&&own.bytesMatchOurs===true)
        this.#finish(r,captured.status as string,own.accountNonce,null);
    }
    return this.status(attemptId);
  }
  status(attemptId:ContentHash):Readonly<Record<string,unknown>> {
    need(hash(attemptId),"INVALID_INPUT");
    const generations=this.#numbered(this.#account(),"active"),found=generations.map(n=>this.#readAttempt(readPrivate(this.#active(n)))).filter(r=>r.attemptId===attemptId);
    need(found.length>0,"ATTEMPT_FENCED");const r=found[found.length-1]!,signed=existsSync(this.#attemptPath(r,".signed")),started=existsSync(this.#attemptPath(r,".submission-started")),signing=existsSync(this.#attemptPath(r,".sign-started"));
    const accountHalt=this.#unresolved()?.record??null,historyHalt=this.#unresolved(r.namespaceId)?.record??null;
    const terminal=this.#terminalRecord(r);
    const clearances=this.#clearanceRecords();
    const observations=this.#readObservations(r);
    return Object.freeze({attemptId,statementDigest:r.identity.statementDigest,namespaceId:r.namespaceId,nonce:r.identity.nonce,
      status:terminal!==null?terminal.status:accountHalt!==null||historyHalt!==null?"HALTED":started?"OUTCOME_UNKNOWN":signed?"SIGNED_READY_FIRST_SEND":signing?"SIGNING_UNCERTAIN":"RESERVED",
      signingStarted:signing,signed,submissionStarted:started,accountHalt,historyHalt,terminal,observations,clearances,publisherExposed:clearances.some(c=>c.keyExposure==="COMPROMISE_SUSPECTED"),feePolicy:this.selectedProfile.feePolicy,replacementAllowed:false,...publicState});
  }
  async #observeNonce(nonce:number,r:AttemptRecord|null,txHash:Hex|null):Promise<ClearanceObservation> {
    const signed=r!==null&&existsSync(this.#attemptPath(r,".signed"))?await this.#signed(r):null;
    const raw=await this.#connector.reconcileClearance(Object.freeze({namespaceId:this.selectedProfile.trustRoot.namespaceId,publisher:this.selectedProfile.publisher,
      nonce,attemptId:r?.attemptId??null,transactionHash:txHash,signedTransaction:signed?.raw??null,statementDigest:r?.identity.statementDigest??null,destination:this.selectedProfile.destination}));
    return observation(canonicalInput(raw,16384),nonce);
  }
  #finish(r:AttemptRecord,status:string,nextNonce:number,reclaimStatementDigest:ContentHash|null,clearanceDigest:ContentHash|null=null):void {
    this.#sameCreate(this.#terminal(r),{version:"irontrellis-anchor-outbox-terminal/1",attemptId:r.attemptId,accountGeneration:r.accountGeneration,status,nextNonce,reclaimStatementDigest,clearanceDigest},"TERMINAL");
  }
  /** Full A169 signed schema; a separately invoked read-only adapter must agree
   * before effects. All returned chain observations remain unqualified. */
  async clearHalt(input:Readonly<{clearanceBytes:Uint8Array}>):Promise<Readonly<Record<string,unknown>>> {
    const v=fields(input,["clearanceBytes"]),c=decodeClearance(v.clearanceBytes,this.selectedProfile),clearanceDigest=digest(c);
    validateRoleSeparation(replaySnapshot(this.#source()),this.selectedProfile);
    const latestGeneration=this.#generation();if(latestGeneration>0){const outstanding=this.#readAttempt(readPrivate(this.#active(latestGeneration)));
      if(!existsSync(this.#terminal(outstanding))){need(outstanding.namespaceId===c.namespaceId,"CLEARANCE_ATTEMPT_MISMATCH");this.#recoverObservedHalt(outstanding);}}
    const account=this.#unresolved(),history=this.#unresolved(c.namespaceId),halt=c.haltCode==="OUTBOX_CONFLICT"?(history??account):account;
    need(halt!==null&&halt.record.haltCode===c.haltCode,"CLEARANCE_HALT_MISMATCH");
    let r:AttemptRecord|null=null;
    const generation=this.#generation();
    if(generation>0){const latest=this.#readAttempt(readPrivate(this.#active(generation)));if(!existsSync(this.#terminal(latest)))r=latest;else {const t=this.#terminalRecord(latest)!;if(t.clearanceDigest===clearanceDigest)r=latest;}}
    need(c.attemptId===(r?.attemptId??null)&& (r===null?c.nonce===c.observed.accountNonce:c.nonce===r.identity.nonce),"CLEARANCE_ATTEMPT_MISMATCH");
    if(c.haltCode!=="OUTBOX_CONFLICT")need(r!==null&&halt.record.attemptId===r.attemptId,"CLEARANCE_ATTEMPT_MISMATCH");
    // Append signed evidence before querying. Compromise is monotone even when
    // the separately queried observation disagrees and the halt stays.
    const dir=this.#directory(join(this.directory,"clearances",this.selectedProfile.chainId,this.selectedProfile.publisher));
    let path:string|undefined;
    for(let n=0;n<LIMITS.observations;n++){const candidate=join(dir,c.nonce+"-"+n+".json");if(existsSync(candidate)){decodeClearance(Buffer.from(canonicalEncode(readPrivate(candidate))),this.selectedProfile);continue;}
      try{this.#write(candidate,c,"CLEARANCE");path=candidate;break;}catch(e){if(code(e)!=="EEXIST")throw e;}}
    need(path!==undefined,"CLEARANCE_LIMIT");
    if(c.keyExposure==="COMPROMISE_SUSPECTED")this.#sameCreate(join(this.#account(),"publisher-exposed.json"),
      {version:"irontrellis-publisher-exposed/1",namespaceId:c.namespaceId,publisher:c.publisher},"PUBLISHER_EXPOSED");
    let txHash:Hex|null=null;
    if(r!==null&&existsSync(this.#attemptPath(r,".signed")))txHash=(await this.#signed(r)).transactionHash;
    let own:ClearanceObservation;
    try{own=await this.#observeNonce(c.nonce,r,txHash);}catch{return Object.freeze({status:"CLEARANCE_OBSERVATION_MISMATCH",clearanceDigest,...publicState});}
    if(digest({...own,observedAt:c.observed.observedAt})!==digest(c.observed))return Object.freeze({status:"CLEARANCE_OBSERVATION_MISMATCH",clearanceDigest,...publicState});
    // Fresh fences after the asynchronous read; an intervening terminal or halt
    // resolution cannot authorize another effect.
    need(this.#unresolved(c.haltCode==="OUTBOX_CONFLICT"&&history!==null?c.namespaceId:undefined)?.path===halt.path,"CLEARANCE_FENCED");
    if(r!==null){need(this.#activeRecord(r.attemptId).accountGeneration===r.accountGeneration,"CLEARANCE_FENCED");if(existsSync(this.#terminal(r)))need(this.#terminalRecord(r)!.clearanceDigest===clearanceDigest,"CLEARANCE_FENCED");}
    if(c.disposition==="RECLAIM_SAME_NONCE_SAME_BYTES"){
      need(r!==null,"CLEARANCE_ATTEMPT_MISMATCH");
      const reclaim=join(this.#account(),"reclaim-"+c.nonce+".json");
      if(existsSync(reclaim))need(fields(readPrivate(reclaim),["version","statementDigest","originalAttemptId","clearanceDigest","unsignedTxDigest"]).clearanceDigest===clearanceDigest,"RECLAIM_ALREADY_USED");
      if(own.accountNonce>c.nonce){need(own.bytesMatchOurs===true,"CLEARANCE_OBSERVATION_MISMATCH");this.#finish(r!,"CONSUMED_BY_SELF",own.accountNonce,null,clearanceDigest);}
      else{this.#sameCreate(reclaim,{version:"irontrellis-outbox-reclaim/1",statementDigest:r!.identity.statementDigest,originalAttemptId:r!.attemptId,clearanceDigest,unsignedTxDigest:r!.identity.unsignedTxDigest},"RECLAIM");
        this.#finish(r!,"CLEARED_RECLAIM",c.nonce,r!.identity.statementDigest,clearanceDigest);}
    }else if(c.disposition==="NONCE_FOREIGN_CONSUMED"){
      need(r!==null,"CLEARANCE_ATTEMPT_MISMATCH");this.#finish(r!,"FAILED_NONCE_CONSUMED",own.accountNonce,null,clearanceDigest);
    }else{
      if(r!==null&&own.accountNonce<=r.identity.nonce)need(!existsSync(this.#attemptPath(r,".sign-started")),"CLEARANCE_OUTSTANDING_UNCERTAIN");
      const survivor=this.#readJob(c.canonicalStatementDigest!),state=replaySnapshot(this.#source());
      need(survivor.record.namespaceId===c.namespaceId&&validateReplayBindings(survivor.statement,survivor.record.attestation,state,this.selectedProfile)===c.namespaceId,"CLEARANCE_CANONICAL_INVALID");
      for(const name of readdirSync(privateDirectory(join(this.directory,"jobs")))){if(!hash(name))continue;const candidate=this.#readJob(name);
        if(candidate.record.namespaceId===c.namespaceId&&candidate.statement.sequence===survivor.statement.sequence&&candidate.record.statementDigest!==c.canonicalStatementDigest)
          this.#sameCreate(join(this.directory,"jobs",name,"superseded.json"),{version:"irontrellis-outbox-superseded/1",canonicalStatementDigest:c.canonicalStatementDigest,clearanceDigest},"SUPERSEDED");}
      this.#sameCreate(join(this.#historyPath(c.namespaceId),"survivor-"+survivor.statement.sequence+".json"),
        {version:"irontrellis-outbox-survivor/1",statementDigest:c.canonicalStatementDigest,clearanceDigest},"SURVIVOR");
      if(r!==null){
        if(own.accountNonce===r.identity.nonce){const original=this.#readAttempt(readPrivate(this.#reservation(r.identity.nonce)));
          this.#sameCreate(join(this.#account(),"conflict-reuse-"+c.nonce+".json"),{version:"irontrellis-outbox-conflict-reuse/1",statementDigest:c.canonicalStatementDigest,
            originalAttemptId:original.attemptId,clearanceDigest,unsignedTxDigest:null},"CONFLICT_REUSE");}
        this.#finish(r,r.identity.statementDigest===c.canonicalStatementDigest?"CLEARED_CONFLICT":"SUPERSEDED_LOCAL",own.accountNonce,
          own.accountNonce===r.identity.nonce?c.canonicalStatementDigest:null,clearanceDigest);}
    }
    this.#sameCreate(halt.path+".resolved.json",{version:"irontrellis-outbox-halt-resolution/1",haltDigest:digest(halt.record),clearanceDigest},"HALT_RESOLVED");
    return Object.freeze({status:"CLEARED",clearanceDigest,...publicState});
  }
}
const factoryToken=Symbol("outbox-factory");
/** Opens the outbox over a trust root whose `(chain.id, profile id)` is a pair of the A-183.1 class table (T6, A-195.2). */
export async function openAnchorOutbox(options:OutboxOptions):Promise<AnchorOutbox> { return open(options,false); }
/**
 * Test fixtures only; not public; no semver promise (CR-A195-01). As `openAnchorOutbox`, but T6 also admits the one synthetic
 * pair of the outbox's own fixtures, `eip155:31337` with `synthetic-local-anchor`; every other pair outside the table is
 * refused here too. Exported from `src/internal.ts`, never from the package's entry points.
 */
export async function openAnchorOutboxInternalForTests(options:OutboxOptions):Promise<AnchorOutbox> { return open(options,true); }
async function open(options:OutboxOptions,syntheticTestPair:boolean):Promise<AnchorOutbox> {
  const c=fields(options,["directory","trustRootBytes","adapterIdentity","feePolicy","historySource","observeImmutables","connector","signTransaction","assertCurrent"],["boundaryHook"]);
  need(typeof c.directory==="string"&&typeof c.historySource==="function"&&typeof c.observeImmutables==="function"&&typeof c.signTransaction==="function"&&
    typeof c.assertCurrent==="function"&&(c.boundaryHook===undefined||typeof c.boundaryHook==="function"),"INVALID_INPUT");
  const connector=fields(c.connector,["encodeStatementCall","submitOnce","reconcile","reconcileClearance"],["verifyAnchor"]);
  need(Object.values(connector).every(v=>typeof v==="function"),"CONNECTOR_INVALID");
  const snapshot=Object.freeze({...c,connector,trustRootBytes:bytes(c.trustRootBytes,32768)}) as unknown as OutboxOptions;
  const state=replaySnapshot(snapshot.historySource()),loaded=await loadProfile(snapshot.trustRootBytes,snapshot.adapterIdentity,snapshot.feePolicy,state,snapshot.observeImmutables,syntheticTestPair);
  return new AnchorOutbox(factoryToken,snapshot,loaded);
}
