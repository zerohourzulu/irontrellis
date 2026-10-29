/** Single-host cooperative destination store; checksums are not rollback authentication. */
import {
  constants, openSync, closeSync, writeFileSync, readSync, fsyncSync, fstatSync,
  lstatSync, realpathSync, readdirSync, renameSync, unlinkSync, existsSync,
} from 'node:fs';
import {join,resolve} from 'node:path';
import {hostname} from 'node:os';
import {randomUUID} from 'node:crypto';
import {types} from 'node:util';
import {encodeTransport,decodeTransport,canonicalDigest} from './wire.mjs';

const FILE_LIMIT=16*1024*1024, RECORD_LIMIT=1024;
const STATE_VERSION='irontrellis-cooperative-destination/1';
const SNAPSHOT_VERSION='continuity-destination-snapshot/1';
const IDENTITY_VERSION='continuity-destination-identity/1';
const LOCK_VERSION='continuity-destination-lock/1';
const STATE_KEYS=['version','domain','historyId','headAuthenticationPolicy','serviceId','coordinatorKey','serviceKey','sequence','lastTime','checkpoint','attempts','businessKeys','effects'];
const IDENTITY_KEYS=['version','domain','historyId','headAuthenticationPolicy','serviceId','coordinatorKey','serviceKey'];
const HASH=/^0x[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code})};
const check=(condition,code='DESTINATION_STATE_INVALID')=>{if(!condition)fail(code)};
const equal=(a,b)=>canonicalDigest(a)===canonicalDigest(b);
const exact=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&
  Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const integer=value=>Number.isSafeInteger(value)&&value>=0&&!Object.is(value,-0);
const identifier=value=>typeof value==='string'&&value.length>0&&value.length<=256&&!/[\u0000-\u001f\u007f]/u.test(value);
const capture=value=>decodeTransport(encodeTransport(value));
const identityOf=state=>capture(Object.fromEntries(IDENTITY_KEYS.map(key=>[key,state[key]])));

function checkedDirectory(value) {
  check(typeof value==='string'&&value.length>0,'DIRECTORY_INVALID');
  const path=resolve(value);
  check(realpathSync(path)===path&&lstatSync(path).isDirectory(),'DIRECTORY_INVALID');
  return path;
}
function syncDirectory(path) {
  const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  try {fsyncSync(fd)} finally {closeSync(fd)}
}
function readFile(path,maximum=FILE_LIMIT) {
  const before=lstatSync(path);
  check(before.isFile()&&!before.isSymbolicLink()&&before.nlink===1&&before.size<=maximum,'DESTINATION_FILE_INVALID');
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try {
    const opened=fstatSync(fd);
    check(opened.isFile()&&opened.nlink===1&&opened.dev===before.dev&&opened.ino===before.ino&&opened.size<=maximum,'DESTINATION_FILE_INVALID');
    const buffer=Buffer.alloc(opened.size+1);let offset=0;
    while(offset<buffer.length){const count=readSync(fd,buffer,offset,buffer.length-offset,null);if(!count)break;offset+=count}
    const after=fstatSync(fd),named=lstatSync(path);
    check(offset===opened.size&&after.size===opened.size&&after.mtimeMs===opened.mtimeMs&&after.ctimeMs===opened.ctimeMs&&
      after.nlink===1&&!named.isSymbolicLink()&&named.dev===opened.dev&&named.ino===opened.ino,'DESTINATION_FILE_CHANGED');
    const bytes=buffer.subarray(0,offset),value=decodeTransport(bytes);
    // Only the writer's exact serialization is a valid stored record.
    check(bytes.equals(encodeTransport(value)),'DESTINATION_ENCODING_INVALID');
    return value;
  } finally {closeSync(fd)}
}
function createFile(path,value,maximum=FILE_LIMIT) {
  const bytes=encodeTransport(value);check(bytes.length<=maximum,'DESTINATION_FILE_LIMIT');
  const fd=openSync(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try {writeFileSync(fd,bytes);fsyncSync(fd)} finally {closeSync(fd)}
}
function identityEnvelope(identity) {
  const body={version:IDENTITY_VERSION,identity};
  return {...body,checksum:canonicalDigest(body)};
}
function readIdentity(path) {
  const value=readFile(path,65536);
  check(exact(value,['version','identity','checksum'])&&value.version===IDENTITY_VERSION&&
    exact(value.identity,IDENTITY_KEYS)&&value.checksum===canonicalDigest({version:value.version,identity:value.identity}),'DESTINATION_IDENTITY_INVALID');
  return value.identity;
}
function validateState(input,identity,checkpointResolver) {
  const state=capture(input);
  check(exact(state,STATE_KEYS)&&state.version===STATE_VERSION&&integer(state.sequence)&&integer(state.lastTime));
  check(exact(state.domain,['protocol','version','deploymentId'])&&state.domain.protocol==='irontrellis'&&state.domain.version==='2'&&identifier(state.domain.deploymentId));
  check(typeof state.historyId==='string'&&HASH.test(state.historyId));
  check(['REQUIRE_OWNER','COORDINATOR_AUTHENTICATED'].includes(state.headAuthenticationPolicy));
  check(identifier(state.serviceId)&&typeof state.coordinatorKey==='string'&&HASH.test(state.coordinatorKey)&&
    typeof state.serviceKey==='string'&&HASH.test(state.serviceKey));
  if(identity)check(equal(identityOf(state),identity),'DESTINATION_IDENTITY_MISMATCH');
  for(const key of ['attempts','businessKeys','effects'])check(Array.isArray(state[key])&&state[key].length<=RECORD_LIMIT,'DESTINATION_RECORD_LIMIT');
  if(state.checkpoint!==null){
    check(exact(state.checkpoint,['head','reference']));
    const received=checkpointResolver?.(state.checkpoint.reference),events=received?.events;
    check(received?.historyId===state.historyId&&Array.isArray(events)&&events.length>0&&events.length<=262144);
    const head=state.checkpoint.head;
    check(exact(head,['hash','position','canonicalTime'])&&typeof head.hash==='string'&&HASH.test(head.hash)&&integer(head.position)&&integer(head.canonicalTime)&&
      head.position===events.length-1&&head.canonicalTime<=state.lastTime);
  }

  const attemptKeys=new Set(),businessKeys=new Set(),effectKeys=new Set();
  for(const attempt of state.attempts){
    check(exact(attempt,['key','fingerprint','intentId','operation','normalized','checkpointHead','preparedAt','report']));
    check(typeof attempt.key==='string'&&HASH.test(attempt.key)&&typeof attempt.fingerprint==='string'&&HASH.test(attempt.fingerprint)&&
      identifier(attempt.intentId)&&integer(attempt.preparedAt)&&attempt.preparedAt<=state.lastTime&&!attemptKeys.has(attempt.key));
    attemptKeys.add(attempt.key);
  }
  for(const record of state.businessKeys){
    check(exact(record,['businessKey','key','intentId'])&&identifier(record.businessKey)&&typeof record.key==='string'&&HASH.test(record.key)&&
      identifier(record.intentId)&&!businessKeys.has(record.businessKey)&&attemptKeys.has(record.key));
    businessKeys.add(record.businessKey);
  }
  for(const effect of state.effects){
    check(exact(effect,['effectId','key','fingerprint','tool','arguments','businessKey','contractId'])&&identifier(effect.effectId)&&
      typeof effect.key==='string'&&HASH.test(effect.key)&&typeof effect.fingerprint==='string'&&HASH.test(effect.fingerprint)&&
      identifier(effect.tool)&&identifier(effect.businessKey)&&identifier(effect.contractId)&&!effectKeys.has(effect.key)&&attemptKeys.has(effect.key));
    effectKeys.add(effect.key);
  }
  return state;
}
function monotonic(previous,next,checkpointResolver) {
  check(next.sequence===previous.sequence,'DESTINATION_SEQUENCE_OWNED_BY_STORE');
  check(next.lastTime>=previous.lastTime,'DESTINATION_TIME_ROLLBACK');
  for(const key of ['attempts','businessKeys','effects'])check(next[key].length>=previous[key].length,'DESTINATION_PRUNING_FORBIDDEN');
  for(let index=0;index<previous.attempts.length;index++){
    const {report:oldReport,...oldIdentity}=previous.attempts[index];
    const {report:newReport,...newIdentity}=next.attempts[index];
    check(equal(oldIdentity,newIdentity),'DESTINATION_ATTEMPT_IDENTITY_CHANGED');
    if(oldReport?.state==='APPLIED'||oldReport?.state==='CANCELLED')check(equal(oldReport,newReport),'DESTINATION_TERMINAL_CHANGED');
  }
  for(const key of ['businessKeys','effects'])for(let index=0;index<previous[key].length;index++)check(equal(previous[key][index],next[key][index]),'DESTINATION_RETAINED_RECORD_CHANGED');
  if(previous.checkpoint!==null){
    check(next.checkpoint!==null,'DESTINATION_CHECKPOINT_ROLLBACK');
    if(!equal(previous.checkpoint,next.checkpoint)){
      const prior=checkpointResolver(previous.checkpoint.reference),after=checkpointResolver(next.checkpoint.reference);
      check(after.historyId===prior.historyId&&after.head.position>=prior.head.position,'DESTINATION_CHECKPOINT_ROLLBACK');
      check(after.view.events[prior.head.position]?.recordHash===prior.head.hash,'DESTINATION_CHECKPOINT_FORK');
    }
  }
}
function snapshotEnvelope(state,identityHash) {
  const body={version:SNAPSHOT_VERSION,identityHash,state};
  return {...body,checksum:canonicalDigest(body)};
}
function loadSnapshot(path,identity,checkpointResolver) {
  const value=readFile(path);
  check(exact(value,['version','identityHash','state','checksum'])&&value.version===SNAPSHOT_VERSION&&
    value.identityHash===canonicalDigest(identity)&&value.checksum===canonicalDigest({version:value.version,identityHash:value.identityHash,state:value.state}),'DESTINATION_INTEGRITY_INVALID');
  return validateState(value.state,identity,checkpointResolver);
}
function lockRecord() {return {version:LOCK_VERSION,hostname:hostname(),pid:process.pid,instance:randomUUID()}}
function validateLock(value) {
  check(exact(value,['version','hostname','pid','instance'])&&value.version===LOCK_VERSION&&identifier(value.hostname)&&
    Number.isSafeInteger(value.pid)&&value.pid>0&&typeof value.instance==='string'&&/^[0-9a-f-]{36}$/.test(value.instance),'DESTINATION_LOCK_INVALID');
  return value;
}
function assertOwnLock(path,lock) {check(equal(validateLock(readFile(path,65536)),lock),'DESTINATION_LOCK_CHANGED')}

/** Read-only evidence for a separate, explicit operator recovery step. */
export function inspectDestinationLock({directory}) {
  return validateLock(readFile(join(checkedDirectory(directory),'destination.lock'),65536));
}

/** Exact lock token + same host + OS-confirmed absent PID. Never age-based. */
export function recoverDestinationLock({directory,expectedLock}) {
  const root=checkedDirectory(directory),expected=validateLock(capture(expectedLock));
  check(expected.hostname===hostname(),'DESTINATION_FOREIGN_LOCK');
  const lockPath=join(root,'destination.lock'),recoveryPath=join(root,'recovery.lock'),recovery=lockRecord();
  try{createFile(recoveryPath,recovery,65536);syncDirectory(root)}catch(error){if(error.code==='EEXIST')fail('DESTINATION_RECOVERY_LOCKED');throw error}
  try{
    assertOwnLock(lockPath,expected);
    let absent=false;
    try{process.kill(expected.pid,0)}catch(error){if(error.code==='ESRCH')absent=true;else fail('DESTINATION_LOCK_OWNER_UNVERIFIED')}
    check(absent,'DESTINATION_LOCK_OWNER_ALIVE');
    assertOwnLock(lockPath,expected);
    const retained=join(root,`recovered-${expected.instance}.lock`);
    check(!existsSync(retained),'DESTINATION_RECOVERY_EVIDENCE_EXISTS');
    renameSync(lockPath,retained);syncDirectory(root);
    return Object.freeze({recovered:true,retainedLock:retained,lock:expected});
  } finally {
    assertOwnLock(recoveryPath,recovery);unlinkSync(recoveryPath);syncDirectory(root);
  }
}

/** One lifetime lock, no pruning or implicit unlock/reinitialization. */
export function openDestinationStore({directory,initial,checkpointResolver}) {
  const root=checkedDirectory(directory),initialState=validateState(initial,undefined,checkpointResolver);
  check(initialState.sequence===0&&initialState.lastTime===0&&initialState.checkpoint===null&&
    initialState.attempts.length===0&&initialState.businessKeys.length===0&&initialState.effects.length===0,'DESTINATION_INITIAL_INVALID');
  const identity=identityOf(initialState),lock=lockRecord();
  const lockPath=join(root,'destination.lock'),identityPath=join(root,'identity.bin'),snapshotPath=join(root,'snapshot.bin');
  check(!existsSync(join(root,'recovery.lock')),'DESTINATION_RECOVERY_LOCKED');
  const before=readdirSync(root);
  try {createFile(lockPath,lock,65536);syncDirectory(root)}catch(error){if(error.code==='EEXIST')fail('DESTINATION_LOCKED');throw error}
  let closed=false,busy=false,poisoned=false,current;
  const release=()=>{assertOwnLock(lockPath,lock);unlinkSync(lockPath);syncDirectory(root)};
  const writeSnapshot=state=>{
    const temporary=join(root,`snapshot-${randomUUID()}.tmp`);
    createFile(temporary,snapshotEnvelope(state,canonicalDigest(identity)));
    renameSync(temporary,snapshotPath);syncDirectory(root);
  };
  try{
    check(!existsSync(join(root,'recovery.lock')),'DESTINATION_RECOVERY_LOCKED');
    const hasIdentity=existsSync(identityPath),hasSnapshot=existsSync(snapshotPath);
    if(!hasIdentity&&!hasSnapshot){
      check(before.length===0,'DESTINATION_INITIALIZATION_REFUSED');
      // Persist the identity first: interruption may block availability, never silently reset history.
      poisoned=true;createFile(identityPath,identityEnvelope(identity),65536);syncDirectory(root);
      writeSnapshot(initialState);poisoned=false;
    } else check(hasIdentity&&hasSnapshot,'DESTINATION_STATE_MISSING');
    check(equal(readIdentity(identityPath),identity),'DESTINATION_IDENTITY_MISMATCH');
    current=loadSnapshot(snapshotPath,identity,checkpointResolver);
  }catch(error){if(!poisoned)release();throw error}
  const active=()=>{check(!closed,'DESTINATION_STORE_CLOSED');check(!poisoned,'DESTINATION_STORE_UNCERTAIN');check(!busy,'DESTINATION_STORE_BUSY')};
  const verify=()=>{
    try{
      assertOwnLock(lockPath,lock);check(equal(readIdentity(identityPath),identity),'DESTINATION_IDENTITY_MISMATCH');
      const stored=loadSnapshot(snapshotPath,identity,checkpointResolver);
      check(equal(stored,current),'DESTINATION_EXTERNAL_STATE_CHANGE');return stored;
    }catch(error){poisoned=true;throw error}
  };
  return Object.freeze({
    read(){active();return verify()},
    transact(fn){
      active();check(typeof fn==='function','DESTINATION_TRANSACTION_INVALID');
      const previous=verify();busy=true;
      try{
        const answer=fn(structuredClone(previous));
        check(!types.isPromise(answer),'DESTINATION_ASYNC_TRANSACTION');
        const captured=capture(answer);
        check(exact(captured,['state','result']),'DESTINATION_TRANSACTION_INVALID');
        let next=validateState(captured.state,identity,checkpointResolver);monotonic(previous,next,checkpointResolver);
        if(equal(previous,next))return Object.freeze({state:previous,result:captured.result});
        check(previous.sequence<Number.MAX_SAFE_INTEGER,'DESTINATION_SEQUENCE_LIMIT');
        next=validateState({...next,sequence:previous.sequence+1},identity,checkpointResolver);
        try{writeSnapshot(next);current=next}catch(error){poisoned=true;throw Object.assign(new Error('DESTINATION_COMMIT_UNCERTAIN'),{code:'DESTINATION_COMMIT_UNCERTAIN',cause:error})}
        return Object.freeze({state:current,result:captured.result});
      }finally{busy=false}
    },
    close(){
      if(closed)return;
      check(!busy,'DESTINATION_STORE_BUSY');closed=true;
      // An uncertain write requires explicit recovery after the owning process is gone.
      if(!poisoned)release();
    },
  });
}

