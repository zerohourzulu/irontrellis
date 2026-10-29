import {test} from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import {join} from 'node:path';
import {tmpdir,hostname} from 'node:os';
import {randomUUID} from 'node:crypto';
import * as core from '../../packages/core-0.2/src/core/index.ts';
import * as h from '../../packages/core-0.3/src/history.ts';
import {PortableFileEventStore} from '../../packages/core-0.2/src/indexer/portable-file-event-store.ts';
import {DirectoryHistoryStore,historyCapacity,commitHistoryAdministration,prepareMigration,stageMigration,activateMigration,inspectMigration,recoverLock,lockRecord,openHistoryBinding} from '../../packages/core-0.3/src/history-store/index.ts';
import {readSnapshot,readManifest,initializeStore} from '../../packages/core-0.3/src/history-store/store.ts';
import {encodeEvent,decodeEvent,json,LIMITS} from '../../packages/core-0.3/src/history-store/codec.ts';
import {sha} from '../../packages/core-0.3/src/history-store/files.ts';
import {stateOf} from '../../packages/core-0.3/src/local-store.ts';
import {fixture,capture,padded,authArgs,signHash} from './fixtures/history-fixture.mjs';
// Synthetic fault-test seeding only. Public create refuses working histories;
// actual migration uses the supported source-fencing procedure below.
function seedStore(path,history,options={}){initializeStore(path,history,options);return new DirectoryHistoryStore(path);}
const code=c=>e=>e.code===c;
const event=id=>({id,type:'PRINCIPAL_CREATED',timestamp:100,data:{principalId:id}});
function area(t){const p=fs.mkdtempSync(join(tmpdir(),'continuity-h03-'));t.after(()=>fs.rmSync(p,{recursive:true,force:true}));return p;}
function reviewInput(f,id='review:new'){return{expectedDomain:f.config.domain,runtimeSessionId:'session',transition:{id,type:'ATTEMPT_DUTY_REVIEW_CLOSED',timestamp:100,data:{dutyId:'duty',actorId:'worker',observationEventIds:[],summaryDigest:'0x'+'a'.repeat(64)}}};}

test('repartitioning preserves every commitment, spent grant and old receipt',async t=>{
 const f=await fixture(t),root=area(t),events=padded(f.events,320),original=capture(events);
 const a=seedStore(join(root,'a'),original,{segmentEvents:64}),b=seedStore(join(root,'b'),original,{segmentEvents:1});
 const x=a.snapshot(),y=b.snapshot();assert.deepEqual(x.history.head,y.history.head);
 assert.equal(core.canonicalEncode(h.exportContinuationEvents(x.history)),core.canonicalEncode(events));assert.equal(core.canonicalEncode(h.exportContinuationEvents(y.history)),core.canonicalEncode(events));
 assert.deepEqual(stateOf(h.exportContinuationEvents(y.history)).eventHistoryHashes,stateOf(events).eventHistoryHashes);
 for(const position of [0,1,95,127,255,319])assert.equal(h.continuationPrefix(y.history,position).head.hash,core.hashEventHistory(events.slice(0,position+1)));
 for(const action of ['inspect','export'])assert.equal(h.authorizeContinuation(x.history,authArgs(events,action)).result.decision,'DENY');
 assert.equal(h.verifyContinuationReceipt(f.handle,x.history,{artifact:f.receipt.artifact,expectedDomain:f.config.domain,verifierTime:100}).result.historical,true);
 const after=a.append(event('extra:new'),x.revision);assert.equal(after.history.eventCount,321);assert.equal(after.revision.generation,1);
 assert.throws(()=>a.append(event('stale'),x.revision),code('HISTORY_CONFLICT'));
 assert.throws(()=>b.append(event('foreign'),x.revision),code('HISTORY_CONFLICT'));
});
test('tagged disk encoding preserves bigint and rejects aliases, bad tags and node/depth limits',()=>{
 const input={a:12345678901234567890n,b:['bigint','12'],c:{__proto__:null,x:'y'}};assert.deepEqual(decodeEvent(encodeEvent(input)),Object.assign(Object.create(null),{a:input.a,b:input.b,c:input.c}));
 for(const bytes of [Buffer.from('["bigint","01"]\n'),Buffer.from('["object",[["x",["null"]],["x",["null"]]]]\n'),Buffer.from('["number",-0]\n'),Buffer.from(' ["null"]\n')])assert.throws(()=>decodeEvent(bytes));
});
test('global reservations survive reopen and preserve room at the count boundary',async t=>{
 const f=await fixture(t,{policy:'E6'}),root=area(t);const reserve=historyCapacity(f.handle,1).reservedEvents;
 const full=capture(padded(f.events,1024-reserve)),store=seedStore(join(root,'store'),full);
 assert.equal(store.snapshot().capacity.projected.events,1024);
 const s=store.snapshot();assert.throws(()=>store.append(event('no-room'),s.revision),code('CAPACITY_RESERVED'));
 const result=await commitHistoryAdministration(store,reviewInput(f),{signHash,now:()=>100});
 assert.equal(result.history.eventCount,s.history.eventCount+1);assert.equal(result.capacity.reservedEvents,reserve-1);
 const again=new DirectoryHistoryStore(store.path).snapshot();assert.deepEqual(again.capacity,result.capacity);
 const before=again.history.head;let calls=0;await assert.rejects(commitHistoryAdministration(store,reviewInput(f,'review:repeat'),{signHash:async hash=>{calls++;return signHash(hash)},now:()=>100}),code('CAPACITY_RESERVED'));assert.equal(calls,0);
 assert.deepEqual(store.snapshot().history.head,before);
});
test('signing rechecks the actual store revision and trusted time without holding its lock',async t=>{
 const f=await fixture(t,{policy:'E6'}),root=area(t),store=seedStore(join(root,'store'),capture(padded(f.events,320)));
 await assert.rejects(commitHistoryAdministration(store,reviewInput(f),{signHash:async hash=>{assert.equal(fs.existsSync(join(store.path,'.writer-lock')),false);store.append(event('intervening'),store.snapshot().revision);return signHash(hash)},now:()=>100}),code('HISTORY_CONFLICT'));
 await assert.rejects(commitHistoryAdministration(store,reviewInput(f),{signHash,now:()=>10001}),e=>['SESSION_INVALID','POLICY_UNAVAILABLE'].includes(e.code));
 assert.equal(h.exportContinuationEvents(store.snapshot().history).some(e=>e.id==='review:new'),false);
});
test('no current snapshot can fall back around missing, altered or reordered required files',async t=>{
 const f=await fixture(t),root=area(t),store=seedStore(join(root,'store'),capture(padded(f.events,130))),snapshot=store.snapshot();
 const file=join(store.path,'segments',snapshot.manifest.segments[0].digest+'.jsonl'),bytes=fs.readFileSync(file);
 fs.unlinkSync(file);assert.throws(()=>store.snapshot());fs.writeFileSync(file,bytes,{mode:0o600});
 fs.appendFileSync(file,'x');assert.throws(()=>store.snapshot());fs.writeFileSync(file,bytes);
 const manifest=JSON.parse(fs.readFileSync(join(store.path,'manifest.json'),'utf8'));[manifest.segments[0],manifest.segments[1]]=[manifest.segments[1],manifest.segments[0]];
 fs.writeFileSync(join(store.path,'manifest.json'),json(manifest));assert.throws(()=>store.snapshot(),code('MANIFEST_INVALID'));
 assert.equal(h.exportContinuationEvents(snapshot.history).length,130); // Historical object, no live-store claim.
});
test('partial writes loop; write/sync/rename faults preserve evidence and freeze the failed instance',async t=>{
 const f=await fixture(t),root=area(t);
 for(const kind of ['short','zero','file-sync','rename','directory-after-replace']){
  const path=join(root,kind),base=seedStore(path,f.handle),before=base.snapshot();let replaced=false;
  const hooks=kind==='short'?{write:(fd,b,o,n)=>fs.writeSync(fd,b,o,Math.min(7,n))}:kind==='zero'?{write:()=>0}:kind==='file-sync'?{sync:()=>{throw Error('injected fsync')}}:kind==='rename'?{rename:()=>{throw Error('injected rename')}}:{point:name=>{if(name==='manifest-replaced')replaced=true},sync:(fd,label)=>{if(replaced&&label==='directory')throw Error('injected directory sync');fs.fsyncSync(fd)}};
  const store=new DirectoryHistoryStore(path,hooks);
  if(kind==='short'){assert.equal(store.append(event('ok'),before.revision).history.eventCount,before.history.eventCount+1);continue;}
  assert.throws(()=>store.append(event('fault'),before.revision),code('WRITE_UNCERTAIN'));
  assert.throws(()=>store.snapshot(),code('WRITE_UNCERTAIN'));
  const reopened=new DirectoryHistoryStore(path),after=reopened.snapshot();assert.equal(after.history.eventCount,before.history.eventCount+(kind==='directory-after-replace'?1:0));
  const orphans=reopened.inspectOrphans();if(kind!=='directory-after-replace')assert.ok(orphans.length>0);
  if(orphans.length){assert.throws(()=>reopened.cleanupOrphans(after.revision,[]),code('ORPHAN_INVENTORY_CHANGED'));assert.equal(reopened.cleanupOrphans(after.revision,orphans),orphans.length);}
 }
});
test('a pre-existing bad content-addressed file is refused, never overwritten or promoted',async t=>{
 const f=await fixture(t),root=area(t),store=seedStore(join(root,'store'),f.handle),e=event('collision'),bytes=encodeEvent(e),path=join(store.path,'segments',sha(bytes)+'.jsonl');
 fs.writeFileSync(path,'wrong',{mode:0o600});const revision=store.snapshot().revision;
 assert.throws(()=>store.append(e,revision),code('WRITE_UNCERTAIN'));assert.equal(fs.readFileSync(path,'utf8'),'wrong');
 assert.deepEqual(new DirectoryHistoryStore(store.path).snapshot().revision,revision);
});
test('writer capability expires and may not cross an asynchronous callback',async t=>{
 const f=await fixture(t),store=seedStore(join(area(t),'store'),f.handle);let escaped;
 store.withWriter(w=>{escaped=w;assert.throws(()=>store.append(event('nested'),w.snapshot().revision),code('STORE_BUSY'));});
 assert.throws(()=>escaped.snapshot(),code('WRITER_EXPIRED'));assert.throws(()=>store.withWriter(async()=>42),code('ASYNC_WRITER_FORBIDDEN'));
});
test('exact lock recovery refuses live, foreign, changed and malformed lock owners',async t=>{
 const f=await fixture(t),store=seedStore(join(area(t),'store'),f.handle),path=join(store.path,'.writer-lock');
 fs.writeFileSync(path,json({version:'continuity-writer-lock/1',host:hostname(),pid:process.pid,nonce:randomUUID()}),{mode:0o600});
 assert.throws(()=>recoverLock(store.path,lockRecord(path).sha256),code('LOCK_OWNER_LIVE'));
 assert.throws(()=>recoverLock(store.path,'0'.repeat(64)),code('LOCK_CHANGED'));
 fs.writeFileSync(path,json({version:'continuity-writer-lock/1',host:'another-host',pid:process.pid,nonce:randomUUID()}));assert.throws(()=>recoverLock(store.path,lockRecord(path).sha256),code('LOCK_OWNER_UNKNOWN'));
 fs.writeFileSync(path,'');assert.throws(()=>recoverLock(store.path,'0'.repeat(64)));fs.unlinkSync(path);
});
async function migrationFixture(t){const f=await fixture(t,{policy:'E6'}),root=area(t),artifact=join(root,'receipt.bin');fs.writeFileSync(artifact,Buffer.from('retained artifact bytes'),{mode:0o600});
 const input={sourceFile:f.config.historyFile,targetDirectory:join(root,'store'),planFile:join(root,'plan.json'),expectedHead:f.handle.head,configurationFiles:[join(root,'core-binding.json')],artifactFiles:[artifact],quiesced:true};return{f,root,input,plan:prepareMigration(input)};}
test('explicit migration preserves source/artifacts, fences old readers/writers and checks binding on every reopen',async t=>{
 const {f,input,plan}=await migrationFixture(t),original=fs.readFileSync(input.sourceFile);stageMigration(input.planFile,{quiesced:true});
 assert.throws(()=>new DirectoryHistoryStore(input.targetDirectory),code('STORE_INACTIVE'));
 assert.deepEqual(new PortableFileEventStore(input.sourceFile).readAll(),f.events);
 const active=activateMigration(input.planFile,{quiesced:true});assert.deepEqual(active.history.head,f.handle.head);
 assert.deepEqual(fs.readFileSync(join(input.targetDirectory,'source-original.bin')),original);
 assert.equal(fs.readFileSync(join(input.targetDirectory,'artifacts','artifact-00.bin'),'utf8'),'retained artifact bytes');
 assert.equal(inspectMigration(input.planFile).dispatchReady,true);
 assert.deepEqual(openHistoryBinding(input.configurationFiles[0]).snapshot().revision,active.revision);
 assert.throws(()=>new PortableFileEventStore(input.sourceFile).readAll());assert.throws(()=>new PortableFileEventStore(input.sourceFile).append(event('old-client')));
 assert.deepEqual(activateMigration(input.planFile,{quiesced:true}).revision,active.revision);
 fs.writeFileSync(input.configurationFiles[0],'{}\n');assert.throws(()=>new DirectoryHistoryStore(input.targetDirectory),code('CONFIGURATION_MISMATCH'));
 assert.equal(inspectMigration(input.planFile).dispatchReady,false);
});
test('incompatible migration or changed source cannot fence the original writer',async t=>{
 const {f,input}=await migrationFixture(t);stageMigration(input.planFile,{quiesced:true});f.owner.createAgent({id:'later'});
 assert.throws(()=>activateMigration(input.planFile,{quiesced:true}),code('SOURCE_CHANGED'));assert.equal(new PortableFileEventStore(input.sourceFile).readAll().at(-1).data.agentId,'later');
 assert.throws(()=>new DirectoryHistoryStore(input.targetDirectory),code('STORE_INACTIVE'));
});

async function child(mode,path,payloadFile='-',cut='-'){
 const {spawn}=await import('node:child_process');
 const p=spawn(process.execPath,['--experimental-strip-types',new URL('./fixtures/history-store-worker.mjs',import.meta.url).pathname,mode,path,payloadFile,cut],{stdio:['ignore','pipe','pipe','ipc']});
 let stdout='',stderr='',result;
 p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);p.on('message',m=>{if(m.status!=='READY')result=m;});
 const done=new Promise((resolve,reject)=>{p.on('error',reject);p.on('exit',(code,signal)=>resolve({code,signal,stdout,stderr,result,pid:p.pid}));});
 await new Promise((resolve,reject)=>{p.once('message',resolve);p.once('error',reject);p.once('exit',code=>{if(code!==null)reject(Error('Worker exited before READY: '+stderr));});});
 return {go:()=>p.send('GO'),done};
}

test('two real processes cannot both commit the same expected revision',async t=>{
 const f=await fixture(t),root=area(t),store=seedStore(join(root,'store'),f.handle),revision=store.snapshot().revision;
 const payloadA=join(root,'a.json'),payloadB=join(root,'b.json');fs.writeFileSync(payloadA,json({event:event('race:a'),revision}));fs.writeFileSync(payloadB,json({event:event('race:b'),revision}));
 const [a,b]=await Promise.all([child('append',store.path,payloadA),child('append',store.path,payloadB)]);a.go();b.go();
 const results=await Promise.all([a.done,b.done]);assert.equal(results.filter(r=>r.code===0).length,1,JSON.stringify(results));
 assert.ok(results.some(r=>['STORE_BUSY','HISTORY_CONFLICT'].includes(r.result?.code)),JSON.stringify(results));
 assert.equal(store.snapshot().history.eventCount,f.events.length+1);
});

test('actual process death at every commit cut uses only the committed manifest',async t=>{
 const f=await fixture(t),root=area(t),cuts=['before-segment-create','segment-synced','manifest-file-synced','before-manifest-replace','manifest-replaced','manifest-directory-synced','before-reply'];
 for(const cut of cuts){const store=seedStore(join(root,cut),f.handle),before=store.snapshot(),payload=join(root,cut+'.json');fs.writeFileSync(payload,json({event:event('crash:'+cut),revision:before.revision}));
  const worker=await child('append',store.path,payload,cut);worker.go();const result=await worker.done;assert.equal(result.signal,'SIGKILL');assert.ok(result.stdout.includes('CUT '+cut));
  const reopened=new DirectoryHistoryStore(store.path),snapshot=reopened.snapshot(),committed=['manifest-replaced','manifest-directory-synced','before-reply'].includes(cut);
  assert.equal(snapshot.history.eventCount,before.history.eventCount+(committed?1:0));
  assert.throws(()=>reopened.append(event('blocked'),snapshot.revision),code('STORE_BUSY'));
  recoverLock(store.path,lockRecord(join(store.path,'.writer-lock')).sha256);
  if(committed)assert.throws(()=>reopened.append(event('crash:'+cut),before.revision),code('HISTORY_CONFLICT'));
  assert.equal(h.authorizeContinuation(snapshot.history,authArgs(f.events)).result.decision,'DENY');
 }
});

test('migration process deaths resume the same plan without enabling two supported writers',async t=>{
 const cases=[['stage','migration-staged'],...['before-source-marker','source-marker-replaced','source-marker-synced','configurations-synced','manifest-replaced','migration-active'].map(c=>['activate',c])];
 for(const [mode,cut]of cases){const {f,input,plan}=await migrationFixture(t);if(mode==='activate')stageMigration(input.planFile,{quiesced:true});
  const worker=await child(mode,input.planFile,'-',cut);worker.go();const result=await worker.done;assert.equal(result.signal,'SIGKILL',result.stderr);assert.ok(result.stdout.includes('CUT '+cut));
  const beforeMark=['migration-staged','before-source-marker'].includes(cut);
  if(beforeMark){assert.deepEqual(new PortableFileEventStore(plan.source).readAll(),f.events);assert.throws(()=>new DirectoryHistoryStore(plan.target),code('STORE_INACTIVE'));}
  else{assert.throws(()=>new PortableFileEventStore(plan.source).readAll());if(!['manifest-replaced','migration-active'].includes(cut))assert.throws(()=>new DirectoryHistoryStore(plan.target),code('STORE_INACTIVE'));}
  const {dirname,basename}=await import('node:path');
  if(fs.existsSync(plan.source+'.writer-lock'))recoverLock(dirname(plan.source),lockRecord(plan.source+'.writer-lock').sha256,basename(plan.source)+'.writer-lock');
  if(fs.existsSync(join(plan.target,'.writer-lock')))recoverLock(plan.target,lockRecord(join(plan.target,'.writer-lock')).sha256);
  const active=activateMigration(input.planFile,{quiesced:true});assert.deepEqual(active.history.head,f.handle.head);assert.equal(active.manifest.instance,plan.instance);assert.equal(inspectMigration(input.planFile).dispatchReady,true);
 }
});

test('byte reservations can refuse a valid history before allocating a new store',async t=>{
 const f=await fixture(t),root=area(t),reserve=historyCapacity(f.handle,1).reservedEvents;
 const threshold=h.CONTINUATION_PROFILE.maxCanonicalHistoryBytes-reserve*h.CONTINUATION_PROFILE.maxEventBytes;
 const events=[...f.events],template=padded(f.events,f.events.length+1,{wide:true}).at(-1);
 let bytes=events.reduce((n,e)=>n+Buffer.byteLength(core.canonicalEncode(e)),0);
 while(bytes<=threshold){const n=events.length,e={...template,id:'wide-budget:'+n,data:{grant:{...template.data.grant,authorityId:'wide-budget:'+n,rootAuthorityId:'wide-budget:'+n,constraints:{...template.data.grant.constraints,resources:Array.from({length:28},(_,i)=>('r'+n+':'+i).padEnd(230,'x'))}}}};events.push(e);bytes+=Buffer.byteLength(core.canonicalEncode(e));}
 assert.ok(events.length+reserve<1024);assert.ok(bytes<h.CONTINUATION_PROFILE.maxCanonicalHistoryBytes);
 const history=capture(events);assert.equal(historyCapacity(history,Math.ceil(events.length/64)).compatible,false);
 assert.throws(()=>seedStore(join(root,'rejected'),history),code('CAPACITY_INCOMPATIBLE'));assert.equal(fs.existsSync(join(root,'rejected')),false);
});
test('symlinks, hard links, traversal descriptors and oversized manifests cannot become store input',async t=>{
 const f=await fixture(t),root=area(t),store=seedStore(join(root,'store'),f.handle),snapshot=store.snapshot(),path=join(store.path,'segments',snapshot.manifest.segments[0].digest+'.jsonl');
 const bytes=fs.readFileSync(path),backup=join(root,'segment-copy');fs.writeFileSync(backup,bytes,{mode:0o600});fs.unlinkSync(path);fs.symlinkSync(backup,path);assert.throws(()=>store.snapshot());fs.unlinkSync(path);fs.linkSync(backup,path);assert.throws(()=>store.snapshot());fs.unlinkSync(path);fs.writeFileSync(path,bytes,{mode:0o600});
 fs.symlinkSync(store.path,join(root,'alias'));assert.throws(()=>new DirectoryHistoryStore(join(root,'alias')),code('PATH_INVALID'));
 const manifest=JSON.parse(fs.readFileSync(join(store.path,'manifest.json'),'utf8'));manifest.segments[0].digest='../escape';fs.writeFileSync(join(store.path,'manifest.json'),json(manifest));assert.throws(()=>store.snapshot(),code('MANIFEST_INVALID'));
 fs.writeFileSync(join(store.path,'manifest.json'),Buffer.alloc(LIMITS.manifestBytes+1));assert.throws(()=>store.snapshot(),code('FILE_INVALID'));
});
test('orphan allocation is bounded and cleanup requires the exact current classification',async t=>{
 const f=await fixture(t),store=seedStore(join(area(t),'store'),f.handle);
 for(let i=0;i<31;i++)fs.writeFileSync(join(store.path,'segments',sha(Buffer.from('orphan:'+i))+'.jsonl'),Buffer.from('orphan:'+i),{mode:0o600});
 const before=store.snapshot();assert.throws(()=>store.append(event('no-allocation'),before.revision),code('ORPHAN_LIMIT'));
 assert.equal(store.inspectOrphans().length,31);assert.equal(store.cleanupOrphans(before.revision,store.inspectOrphans()),31);
 assert.equal(store.append(event('after-cleanup'),before.revision).history.eventCount,before.history.eventCount+1);
});
test('lost migration durability acknowledgments never restore the old writable file',async t=>{
 for(const at of ['source-marker-replaced','configurations-synced','manifest-replaced']){
  const {input,plan}=await migrationFixture(t);stageMigration(input.planFile,{quiesced:true});
  assert.throws(()=>activateMigration(input.planFile,{quiesced:true},{point:name=>{if(name===at)throw Error('injected migration interruption')}}));
  assert.throws(()=>new PortableFileEventStore(plan.source).readAll());
  if(at!=='manifest-replaced')assert.throws(()=>new DirectoryHistoryStore(plan.target),code('STORE_INACTIVE'));
  assert.equal(activateMigration(input.planFile,{quiesced:true}).manifest.phase,'ACTIVE');
 }
});

test('migration carries a real receipt artifact, current denials and the original duty state',async t=>{
 const f=await fixture(t),root=area(t),artifactFile=join(root,'receipt.bin');fs.writeFileSync(artifactFile,encodeEvent(f.receipt.artifact),{mode:0o600});
 const input={sourceFile:f.config.historyFile,targetDirectory:join(root,'store'),planFile:join(root,'plan.json'),expectedHead:f.handle.head,configurationFiles:[join(root,'binding.json')],artifactFiles:[artifactFile],quiesced:true};
 prepareMigration(input);stageMigration(input.planFile,{quiesced:true});activateMigration(input.planFile,{quiesced:true});
 const store=openHistoryBinding(input.configurationFiles[0]),snapshot=store.snapshot();
 const artifact=decodeEvent(fs.readFileSync(join(store.path,'artifacts','artifact-00.bin')));
 assert.equal(h.verifyContinuationReceipt(snapshot.history,snapshot.history,{artifact,expectedDomain:f.config.domain,verifierTime:100}).result.current,true);
 for(const action of ['inspect','export'])assert.equal(h.authorizeContinuation(snapshot.history,authArgs(f.events,action)).result.decision,'DENY');
 const unknown=await migrationFixture(t);stageMigration(unknown.input.planFile,{quiesced:true});const migrated=activateMigration(unknown.input.planFile,{quiesced:true});
 const survives=h.queryContinuation('SURVIVES',migrated.history,migrated.history,{targetAgentId:'worker',evaluationTime:100,disclosure:core.portablePublicQueryDisclosure('SURVIVES')}).result;
 assert.equal(survives.answer.attemptDuties[0].status,'OPEN');assert.equal(survives.answer.attemptDuties[0].dutyId,'duty');
});


test('ordinary creation accepts a fresh bootstrap and refuses copied working history before writing',async t=>{
 const f=await fixture(t),root=area(t);
 assert.throws(()=>DirectoryHistoryStore.create(join(root,'copy'),f.handle),code('MIGRATION_REQUIRED'));
 assert.equal(fs.existsSync(join(root,'copy')),false);
 const fresh=h.continuationPrefix(f.handle,1);
 assert.equal(DirectoryHistoryStore.create(join(root,'bootstrap'),fresh).snapshot().history.eventCount,2);
});
