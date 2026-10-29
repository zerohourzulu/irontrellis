import test from 'node:test';
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalEncode, eventHash, historyIdOfGenesis, openHistoryStore, hashCanonical, PRODUCTION_ANCHORING_PROFILE, TEST_ANCHORING_PROFILE, TEST_PROFILE_LABEL, TEST_TRUSTED_NODE_BARRIER_LABEL } from '@ramex-labs/irontrellis';
import { setup } from './fixtures.mjs';
import { createGateway, operationIdentity } from '../dist/gateway.js';
import { deriveNamespace, encodeTrustRoot, encodeAnchorVerifyReport } from '../dist/anchor-profile/index.js';
import { dispatchPaths, appendBarrier, readBarrierChain } from '../dist/dispatch-files.js';
import { openAnchorBarrier } from '../dist/anchor-barrier.js';

// Synthetic privileged producer fixtures exercise the gateway contract only. They are not chain evidence or connector qualification.
const title = {title:'Synthetic barrier ticket'};
const h = (v) => '0x'+v.repeat(64);
const block = 'BKiHLREqU3JkXfzEDYAkmmfX48gBDtYhMrpA98s7Aq4SzbUAB6M';
const operation = 'oneev3QMfQJd2fEM3zQPdFwwPY1aohkxffttrK8Qrswemnh2nML';
async function fixture(t, extra={}) {
  const dir=realpathSync(mkdtempSync(join(tmpdir(),'irontrellis-barrier-'))), f=await setup(join(dir,'case')), reportDirectory=join(dir,'reports');
  mkdirSync(reportDirectory,{mode:0o700});
  const state=()=>openHistoryStore(f.local.historyFile).state(), initial=state(), gateways=[];
  // A-183.1 / A-195.2 (T6): the pair must be in the class table, so the synthetic fixture uses the production literals.
  const manifest={version:'irontrellis-profile-manifest/1',id:PRODUCTION_ANCHORING_PROFILE.profileId,domain:initial.genesis.domain,
    historyId:historyIdOfGenesis(initial.events[0]),genesisEventHash:eventHash(initial.events[0]),chain:{id:'eip155:42793'},publisher:'0x'+'44'.repeat(20),
    operatorKeys:[{keyId:'public-test-base-point',scheme:'ed25519',credential:'0x58'+'66'.repeat(31)}],
    nodes:{evm:{chainId:'eip155:42793',operator:'synthetic-evm'},l1:{chainId:'synthetic-tezos',operator:'synthetic-l1'},ownRollup:null},bodyStore:null,maxL1HeadLag:null,supersedes:null};
  const namespace=deriveNamespace(canonicalEncode(manifest));
  const root={version:'irontrellis-profile-trust-root/1',manifest,manifestHash:namespace.manifestHash,namespaceId:namespace.namespaceId,destination:'0x'+'55'.repeat(20)};
  const trustRootBytes=encodeTrustRoot(canonicalEncode(root)).canonicalText;
  let reads=0;
  const anchoring={trustRootBytes,reportDirectory,stopFile:join(dir,'stop.json'),waitMs:0,pollMs:5,
    async readInstanceImmutables(){reads++;return {destination:root.destination,namespaceId:root.namespaceId,publisher:manifest.publisher,chainId:manifest.chain.id,mode:'CONSENSUS_VERIFIED'};},...extra};
  const operationId=operationIdentity(f.local.domain,f.config.operations[1].businessKey), paths=dispatchPaths(f.config.storage,operationId);
  t.after(async()=>{for(const g of gateways)await g.close();rmSync(dir,{recursive:true,force:true,maxRetries:5});});
  const open=async (overrides={})=>{const g=await createGateway({...f.config,local:f.local,anchoring,...overrides});gateways.push(g);return g;};
  const context=()=>{const admission=state().intentAdmissions.get(operationId);return {operationId,intentId:operationId,admissionEventId:admission.admissionEventId,admissionHead:admission.admissionHead,submissionIdentity:admission.adapterIdentity,resumed:true};};
  function report(patch={}) {
    const current=state();
    const value={version:'irontrellis-anchor-verify-report/1',profileId:manifest.id,chainId:manifest.chain.id,
      statement:{digest:h('1'),historyId:manifest.historyId,head:{hash:current.head.hash,position:current.head.position}},
      tx:{hash:h('2'),l2Block:0,l2BlockHash:'SYNTHETIC'},nodes:{evm:{...manifest.nodes.evm,protocol:'synthetic',softwareCommit:'fixture',headLevel:0},l1:{...manifest.nodes.l1,protocol:'synthetic',softwareCommit:'fixture',headLevel:102},ownRollup:null},
      finality:{label:'L1_FINAL',mode:'CONSENSUS_VERIFIED',l1Level:100,l1BlockHash:block,l1BlockTime:1_760_000_000_000,operationHash:operation,refutationResidual:'OPEN',cementedAt:null},
      sentence:'Synthetic offline fixture; not a statement of actual chain finality.',observedAt:0,continuity:{previousReportDigest:null,contradiction:false}};
    return {...value,...patch};
  }
  function persist(value=report()){const encoded=encodeAnchorVerifyReport(canonicalEncode(value));writeFileSync(join(reportDirectory,encoded.reportDigest.slice(2)+'.json'),encoded.canonicalText,{mode:0o600,flag:'wx'});return encoded;}
  return {...f,dir,state,manifest,root,anchoring,operationId,paths,context,open,report,persist,reads:()=>reads,
    count:()=>existsSync(join(f.directory,'tickets.calls.jsonl'))?readFileSync(join(f.directory,'tickets.calls.jsonl'),'utf8').trim().split('\n').length:0,
    stop:()=>writeFileSync(anchoring.stopFile,'{}',{mode:0o600,flag:'wx'})};
}
async function waitFor(p){for(let i=0;i<500;i++){if(p())return;await new Promise(r=>setTimeout(r,5));}throw Error('deadline');}

test('durable admission waits without refusal, then a fresh run dispatches once using retained request',async t=>{
  const f=await fixture(t),g=await f.open();
  const first=await g.run('create_incident_ticket',title);
  assert.equal(first.status,'DELAYED');assert.equal(first.dispatchPerformed,false);assert.equal(f.count(),0);
  assert.equal(f.state().intentAdmissions.size,1);assert.equal(f.state().refusals.size,0);assert.equal(existsSync(f.paths.attempt),false);
  assert.equal(g.status('create_incident_ticket').status,'NOT_DISPATCHED');
  f.persist();await g.close();const resumed=await f.open();
  const delivered=await resumed.run('create_incident_ticket',title);assert.equal(delivered.status,'RESPONSE_RETAINED');assert.equal(delivered.resumed,true);
  assert.equal(f.count(),1);assert.equal(f.reads(),2);
  const barrier=JSON.parse(readFileSync(f.paths.barrier));assert.equal(barrier.resumed,true);assert.equal(barrier.barrierSeq,0);
  assert.equal((await resumed.run('create_incident_ticket',title)).status,'RECONCILIATION_ONLY');assert.equal(f.count(),1);
});

test('STOPPED during the unlocked wait writes no attempt, effect, refusal or spool',async t=>{
  const f=await fixture(t,{waitMs:2000}),g=await f.open(),pending=g.run('create_incident_ticket',title);
  await waitFor(()=>f.state().intentAdmissions.size===1);
  await waitFor(()=>g.status('create_incident_ticket').status==='DELAYED');f.stop();
  const answer=await pending;assert.equal(answer.status,'STOPPED');assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);
  assert.equal(f.state().refusals.size,0);assert.equal(f.state().effects.size,0);
});

test('A-181.3: finality.l1BlockTime is a U53 under CONSENSUS_VERIFIED and null in any other mode; the closed codec refuses a missing key or the wrong kind',async t=>{
  const f=await fixture(t),r=f.report(),codec=v=>encodeAnchorVerifyReport(canonicalEncode(v));
  assert.equal(codec(r).claimedReport.finality.l1BlockTime,1_760_000_000_000);
  assert.equal(codec({...r,finality:{...r.finality,mode:'TRUSTED_NODE',l1BlockTime:null}}).claimedReport.finality.l1BlockTime,null);
  const {l1BlockTime:_,...missing}=r.finality;
  for(const [finality,why] of [[missing,/finality/],[{...r.finality,l1BlockTime:null},/l1BlockTime/],[{...r.finality,l1BlockTime:-1},/l1BlockTime/],[{...r.finality,mode:'TRUSTED_NODE'},/NULL_UNLESS_CONSENSUS_VERIFIED/],[{...r.finality,mode:'UNVERIFIED'},/NULL_UNLESS_CONSENSUS_VERIFIED/]])
    assert.throws(()=>codec({...r,finality}),e=>e.code==='REPORT_CODEC_INVALID'&&why.test(e.message),JSON.stringify(finality));
});

test('report eligibility never falls back to trusted-node mode',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);
  const r=f.report();f.persist({...r,finality:{...r.finality,mode:'TRUSTED_NODE',l1BlockTime:null}}); // A-181.3: null unless CONSENSUS_VERIFIED
  const before=readFileSync(f.local.historyFile);assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');
  assert.deepEqual(readFileSync(f.local.historyFile),before);assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);
});

test('changed original arguments on an undispatched admission are ADMISSION_MISMATCH, no writes',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);f.persist();const before=readFileSync(f.local.historyFile);
  const answer=await g.run('create_incident_ticket',{title:'changed'});assert.equal(answer.status,'NOT_DISPATCHED');assert.equal(answer.reason,'ADMISSION_MISMATCH');assert.equal(f.count(),0);assert.deepEqual(readFileSync(f.local.historyFile),before);
});

for(const priorCount of [1,2])test(`barrier-only crash resumes with sequence ${priorCount} and preserves every earlier byte`,async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);const r=f.persist();
  const context=f.context();const evidence={statementDigest:r.claimedReport.statement.digest,statementHead:r.claimedReport.statement.head,profileId:r.claimedReport.profileId,chainId:r.claimedReport.chainId,label:r.claimedReport.finality.label,mode:r.claimedReport.finality.mode,reportDigest:r.reportDigest};
  // Synthetic crash snapshot has the durable barrier and no durable start. Actual append helper is used under the real writer lock.
  const store=openHistoryStore(f.local.historyFile);for(let n=0;n<priorCount;n++)store.withExclusiveWriter(()=>appendBarrier(f.config.storage,{...context,resumed:n>0},evidence));
  const old=Array.from({length:priorCount},(_,n)=>readFileSync(n===0?f.paths.barrier:f.paths.barrier.replace(/\.barrier\.json$/,`.barrier-${n}.json`)));await g.close();const second=await f.open();await second.run('create_incident_ticket',title);
  assert.equal(f.count(),1);for(let n=0;n<priorCount;n++)assert.deepEqual(readFileSync(n===0?f.paths.barrier:f.paths.barrier.replace(/\.barrier\.json$/,`.barrier-${n}.json`)),old[n]);
  const records=readBarrierChain(f.config.storage,context);assert.equal(records.length,priorCount+1);assert.equal(records[priorCount].resumed,true);assert.equal(records[priorCount].previousBarrierDigest,hashCanonical(records[priorCount-1],'sha256'));
  await second.run('create_incident_ticket',title);assert.equal(readBarrierChain(f.config.storage,context).length,priorCount+1);assert.equal(f.count(),1);
});

test('broken barrier chain is ADMISSION_MISMATCH and never becomes a start record',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);f.persist();writeFileSync(f.paths.barrier,'{"broken":true}',{mode:0o600});
  const before=readFileSync(f.local.historyFile),answer=await g.run('create_incident_ticket',title);
  assert.equal(answer.status,'NOT_DISPATCHED');assert.equal(answer.reason,'ADMISSION_MISMATCH');assert.equal(f.count(),0);assert.deepEqual(readFileSync(f.local.historyFile),before);
});

test('profile rejects Shadownet before any instance-read callback',async t=>{
  const f=await fixture(t),manifest={...f.manifest,chain:{id:'eip155:127823'},nodes:{...f.manifest.nodes,evm:{...f.manifest.nodes.evm,chainId:'eip155:127823'}}};
  const n=deriveNamespace(canonicalEncode(manifest)),root={...f.root,manifest,manifestHash:n.manifestHash,namespaceId:n.namespaceId};
  await assert.rejects(f.open({anchoring:{...f.anchoring,trustRootBytes:canonicalEncode(root)}}),e=>e.code==='TRUST_ROOT_INVALID'&&/^T6/.test(e.detail));assert.equal(f.reads(),0);assert.equal(f.count(),0);
});

// ---------------------------------------------------------------- A-183.1 / A-183.2 / A-195: classes, the TEST opt-in, the trusted-node barrier
/** The fixture moved onto another (chain, profile id) pair; its instance read answers for the new root. */
async function onPair(t,{chainId,profileId,observed='CONSENSUS_VERIFIED',l1Operator}={},extra={}) {
  const f=await fixture(t);
  const manifest={...f.manifest,id:profileId,chain:{id:chainId},nodes:{...f.manifest.nodes,evm:{...f.manifest.nodes.evm,chainId},l1:{...f.manifest.nodes.l1,operator:l1Operator??f.manifest.nodes.l1.operator}}};
  const n=deriveNamespace(canonicalEncode(manifest)),root={...f.root,manifest,manifestHash:n.manifestHash,namespaceId:n.namespaceId};
  let reads=0;
  const anchoring={...f.anchoring,trustRootBytes:canonicalEncode(root),...extra,
    async readInstanceImmutables(){reads++;return {destination:root.destination,namespaceId:root.namespaceId,publisher:manifest.publisher,chainId,mode:observed};}};
  const report=(finality={})=>{const r=f.report();return {...r,profileId,chainId,nodes:{...r.nodes,evm:{...r.nodes.evm,chainId},l1:{...r.nodes.l1,operator:manifest.nodes.l1.operator}},finality:{...r.finality,...finality}};};
  const warnings=[],write=process.stderr.write;
  process.stderr.write=(chunk,...rest)=>{if(/allowTestProfile/.test(String(chunk)))warnings.push(String(chunk));return write.call(process.stderr,chunk,...rest);};
  t.after(()=>{process.stderr.write=write;});
  return {...f,anchoring,report,warnings,reads:()=>reads,open:(overrides={})=>f.open({anchoring,...overrides})};
}
const TEST_PAIR={chainId:TEST_ANCHORING_PROFILE.chainId,profileId:TEST_ANCHORING_PROFILE.profileId};

test('A-195.2 T6: a pair outside the class table is TRUST_ROOT_INVALID before the instance read, the production id on another chain and a synthetic id on mainnet alike',async t=>{
  for(const pair of [{chainId:'eip155:42793',profileId:'synthetic-offline-gateway'},{chainId:TEST_ANCHORING_PROFILE.chainId,profileId:PRODUCTION_ANCHORING_PROFILE.profileId},{chainId:PRODUCTION_ANCHORING_PROFILE.chainId,profileId:TEST_ANCHORING_PROFILE.profileId}]) {
    const f=await onPair(t,pair,{allowTestProfile:true});
    await assert.rejects(f.open(),e=>e.code==='TRUST_ROOT_INVALID'&&/^T6/.test(e.detail),JSON.stringify(pair));assert.equal(f.reads(),0);
  }
});

test('A-183.2 (i): the TEST pair is TRUST_ROOT_INVALID {TEST_PROFILE_NOT_ALLOWED} without anchoring.allowTestProfile; with it the gateway opens, warns on every open and labels status()',async t=>{
  const refused=await onPair(t,TEST_PAIR);
  await assert.rejects(refused.open(),e=>e.code==='TRUST_ROOT_INVALID'&&/^TEST_PROFILE_NOT_ALLOWED/.test(e.detail));assert.equal(refused.reads(),0);
  await assert.rejects(refused.open({anchoring:{...refused.anchoring,allowTestProfile:false}}),e=>/^TEST_PROFILE_NOT_ALLOWED/.test(e.detail));
  await assert.rejects(refused.open({anchoring:{...refused.anchoring,allowTestProfile:'yes'}}),e=>e.code==='INVALID_INPUT');
  const f=await onPair(t,TEST_PAIR,{allowTestProfile:true});
  const g=await f.open();await g.close();const again=await f.open();
  assert.equal(f.warnings.length,2,'logged on every open');assert.match(f.warnings[0],/barrier mode CONSENSUS_VERIFIED/);
  const status=again.status('create_incident_ticket');
  assert.deepEqual([status.profileClass,status.barrierMode,status.classLabel],['TEST','CONSENSUS_VERIFIED',TEST_PROFILE_LABEL]);
  // Default barrier: a TEST profile is measured in CONSENSUS_VERIFIED, so a trusted-node report never satisfies it.
  await again.run('create_incident_ticket',title);f.persist(f.report({mode:'TRUSTED_NODE',l1BlockTime:null}));
  assert.equal((await again.run('create_incident_ticket',title)).status,'DELAYED');assert.equal(f.count(),0);
  f.persist(f.report());
  assert.equal((await again.run('create_incident_ticket',title)).status,'RESPONSE_RETAINED');assert.equal(f.count(),1);
});

test('A-195.1: testBarrierMode TRUSTED_NODE is refused on the production profile {TRUSTED_NODE_BARRIER_NOT_ALLOWED}, with the opt-in set or not',async t=>{
  for(const extra of [{testBarrierMode:'TRUSTED_NODE'},{testBarrierMode:'TRUSTED_NODE',allowTestProfile:true}]) {
    const f=await onPair(t,{chainId:PRODUCTION_ANCHORING_PROFILE.chainId,profileId:PRODUCTION_ANCHORING_PROFILE.profileId},extra);
    await assert.rejects(f.open(),e=>e.code==='TRUST_ROOT_INVALID'&&/^TRUSTED_NODE_BARRIER_NOT_ALLOWED/.test(e.detail),JSON.stringify(extra));assert.equal(f.reads(),0);
  }
  const f=await onPair(t,TEST_PAIR,{testBarrierMode:'trusted-node',allowTestProfile:true});
  await assert.rejects(f.open(),e=>e.code==='INVALID_INPUT');
  const production=await onPair(t,{chainId:PRODUCTION_ANCHORING_PROFILE.chainId,profileId:PRODUCTION_ANCHORING_PROFILE.profileId});
  const g=await production.open(),status=g.status('create_incident_ticket');
  assert.deepEqual([status.profileClass,status.barrierMode,status.classLabel],['PRODUCTION','CONSENSUS_VERIFIED',null]);
});

test('A-168.4: status() lists the whole barrier chain; before the attempt no record is relied on, after it the last one is',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);const r=f.persist();
  const context=f.context(),store=openHistoryStore(f.local.historyFile);
  const evidence={statementDigest:r.claimedReport.statement.digest,statementHead:r.claimedReport.statement.head,profileId:r.claimedReport.profileId,chainId:r.claimedReport.chainId,label:r.claimedReport.finality.label,mode:r.claimedReport.finality.mode,reportDigest:r.reportDigest};
  store.withExclusiveWriter(()=>appendBarrier(f.config.storage,{...context,resumed:false},evidence)); // a barrier-only crash
  const before=g.status('create_incident_ticket');
  assert.equal(before.status,'NOT_DISPATCHED');assert.equal(before.barrierChain.length,1);assert.equal(before.barrierChain[0].reliedOn,false);assert.equal(before.reliedOnBarrierDigest,null);
  await g.close();const resumed=await f.open();assert.equal((await resumed.run('create_incident_ticket',title)).status,'RESPONSE_RETAINED');
  const after=resumed.status('create_incident_ticket'),chain=readBarrierChain(f.config.storage,context);
  assert.equal(after.status,'RESPONSE_RETAINED');
  assert.deepEqual(after.barrierChain.map(b=>[b.barrierSeq,b.resumed,b.reliedOn,b.digest]),chain.map((b,i)=>[i,i>0,i===chain.length-1,hashCanonical(b,'sha256')]));
  assert.equal(after.barrierChain.length,2);assert.equal(after.reliedOnBarrierDigest,hashCanonical(chain[1],'sha256'));
  assert.equal(after.barrierChain[1].reportDigest,r.reportDigest);
  writeFileSync(f.paths.barrier,'{"broken":true}',{mode:0o600,flag:'w'});
  assert.deepEqual([resumed.status('create_incident_ticket').barrierChain,resumed.status('create_incident_ticket').barrierChainStatus],[null,'ADMISSION_MISMATCH']);
});

test('A-195.1: a TRUSTED_NODE barrier record is refused for the production pair and accepted for the TEST pair',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);const r=f.persist();
  const context=f.context(),store=openHistoryStore(f.local.historyFile);
  const evidence={statementDigest:r.claimedReport.statement.digest,statementHead:r.claimedReport.statement.head,profileId:r.claimedReport.profileId,chainId:r.claimedReport.chainId,label:'L1_FINAL',mode:'TRUSTED_NODE',reportDigest:r.reportDigest};
  assert.throws(()=>store.withExclusiveWriter(()=>appendBarrier(f.config.storage,context,evidence)),e=>e.code==='ADMISSION_MISMATCH');
  assert.equal(existsSync(f.paths.barrier),false);
  store.withExclusiveWriter(()=>appendBarrier(f.config.storage,context,{...evidence,...TEST_PAIR}));
  assert.equal(readBarrierChain(f.config.storage,context)[0].mode,'TRUSTED_NODE');
});

test('J77-10: a barrier record must name the open trust root\'s pair; a TEST-pair record in a production gateway\'s storage is listed as ADMISSION_MISMATCH and never relied on',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);const r=f.persist();
  const context=f.context(),store=openHistoryStore(f.local.historyFile),production={profileId:r.claimedReport.profileId,chainId:r.claimedReport.chainId,mode:'CONSENSUS_VERIFIED'};
  const evidence={statementDigest:r.claimedReport.statement.digest,statementHead:r.claimedReport.statement.head,label:'L1_FINAL',mode:'TRUSTED_NODE',reportDigest:r.reportDigest,...TEST_PAIR};
  assert.throws(()=>store.withExclusiveWriter(()=>appendBarrier(f.config.storage,context,evidence,production)),e=>e.code==='ADMISSION_MISMATCH');
  assert.equal(existsSync(f.paths.barrier),false);
  store.withExclusiveWriter(()=>appendBarrier(f.config.storage,context,evidence)); // valid on its own pair: a record planted for the TEST profile
  assert.equal(readBarrierChain(f.config.storage,context).length,1);
  assert.throws(()=>readBarrierChain(f.config.storage,context,production),e=>e.code==='ADMISSION_MISMATCH');
  assert.deepEqual([g.status('create_incident_ticket').barrierChain,g.status('create_incident_ticket').barrierChainStatus],[null,'ADMISSION_MISMATCH']);
  const result=await g.run('create_incident_ticket',title);
  assert.equal(result.status,'NOT_DISPATCHED',JSON.stringify(result));assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);
});

test('step 5b review (defence in depth): a barrier record must also carry the open barrier mode; a CONSENSUS_VERIFIED record planted under the trusted-node barrier is listed as ADMISSION_MISMATCH and never relied on',async t=>{
  const f=await onPair(t,{...TEST_PAIR,observed:'TRUSTED_NODE',l1Operator:'synthetic-evm'},{allowTestProfile:true,testBarrierMode:'TRUSTED_NODE'});
  const g=await f.open();assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');
  const r=f.persist(f.report({mode:'TRUSTED_NODE',l1BlockTime:null})),context=f.context(),store=openHistoryStore(f.local.historyFile);
  const evidence={statementDigest:r.claimedReport.statement.digest,statementHead:r.claimedReport.statement.head,profileId:r.claimedReport.profileId,chainId:r.claimedReport.chainId,label:'L1_FINAL',mode:'CONSENSUS_VERIFIED',reportDigest:r.reportDigest};
  assert.throws(()=>store.withExclusiveWriter(()=>appendBarrier(f.config.storage,context,evidence,{profileId:evidence.profileId,chainId:evidence.chainId,mode:'TRUSTED_NODE'})),e=>e.code==='ADMISSION_MISMATCH');
  store.withExclusiveWriter(()=>appendBarrier(f.config.storage,context,evidence)); // valid on its own: a CONSENSUS_VERIFIED record for the TEST pair
  assert.deepEqual([g.status('create_incident_ticket').barrierChain,g.status('create_incident_ticket').barrierChainStatus],[null,'ADMISSION_MISMATCH']);
  const result=await g.run('create_incident_ticket',title);
  assert.equal(result.status,'NOT_DISPATCHED',JSON.stringify(result));assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);
});

test('A-195.1: under a TEST profile with testBarrierMode TRUSTED_NODE, an L1_FINAL trusted-node report is ELIGIBLE (no independent L1 node needed); the barrier record says TRUSTED_NODE',async t=>{
  const f=await onPair(t,{...TEST_PAIR,observed:'TRUSTED_NODE',l1Operator:'synthetic-evm'},{allowTestProfile:true,testBarrierMode:'TRUSTED_NODE'});
  const g=await f.open();assert.match(f.warnings[0],/barrier mode TRUSTED_NODE/);
  assert.equal(g.status('create_incident_ticket').classLabel,TEST_TRUSTED_NODE_BARRIER_LABEL);
  assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');
  f.persist(f.report({label:'L1_POSTED',mode:'TRUSTED_NODE',l1BlockTime:null}));
  assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED','below L1_FINAL stays delayed');
  f.persist(f.report({mode:'TRUSTED_NODE',l1BlockTime:null}));
  const delivered=await g.run('create_incident_ticket',title);assert.equal(delivered.status,'RESPONSE_RETAINED',JSON.stringify(delivered));assert.equal(f.count(),1);
  assert.match(readFileSync(f.paths.barrier,'utf8'),/"mode":"TRUSTED_NODE"/);
});


test('stop after attempt fsync leaves UNKNOWN and zero calls, including after restart',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);f.persist();
  const result=await g.run('create_incident_ticket',title,{assertCurrent(){if(existsSync(f.paths.attempt)&&!existsSync(f.anchoring.stopFile))f.stop();}});
  assert.equal(result.status,'OUTCOME_UNKNOWN');assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),true);
  await g.close();const next=await f.open();assert.equal(next.status('create_incident_ticket').status,'OUTCOME_UNKNOWN');
  const before=readdirSync(f.config.storage).filter(n=>n.includes('.barrier'));
  await next.run('create_incident_ticket',title);assert.equal(f.count(),0);assert.deepEqual(readdirSync(f.config.storage).filter(n=>n.includes('.barrier')),before);
});

test('explicit resume horizon is disclosed and refuses an old undispatched admission',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);f.persist();await f.owner.createRole({id:'horizon-probe'});await g.close();
  const next=await f.open({anchoring:{...f.anchoring,resumeHorizon:{kind:'HEAD_POSITIONS',limit:0}}});
  const before=readFileSync(f.local.historyFile),result=await next.run('create_incident_ticket',title);
  assert.equal(result.status,'NOT_DISPATCHED');assert.equal(result.reason,'RESUME_HORIZON');assert.equal(f.count(),0);
  assert.deepEqual(next.status('create_incident_ticket').resumeHorizon,{kind:'HEAD_POSITIONS',limit:0});assert.deepEqual(readFileSync(f.local.historyFile),before);
});

test('expiry during the wait is ACCESS_NOT_CURRENT with no attempted call',async t=>{
  const f=await fixture(t,{waitMs:2000}),g=await f.open(),pending=g.run('create_incident_ticket',title);
  await waitFor(()=>f.state().intentAdmissions.size===1);await f.owner.advanceEpoch({agent:'worker',from:1,to:2});
  const result=await pending;assert.equal(result.status,'NOT_DISPATCHED');assert.equal(result.reason,'ACCESS_NOT_CURRENT');assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);assert.equal(f.state().refusals.size,0);
});

test('two gateway handles serialize on the durable attempt and issue only one call',async t=>{
  const f=await fixture(t),first=await f.open();await first.run('create_incident_ticket',title);f.persist();const second=await f.open();
  const results=await Promise.all([first.run('create_incident_ticket',title),second.run('create_incident_ticket',title)]);
  assert.equal(f.count(),1);assert.equal(results.filter(r=>r.status==='RESPONSE_RETAINED').length,1);
  assert.equal(readBarrierChain(f.config.storage,f.context()).length,1);assert.equal(f.state().refusals.size,0);
});

test('declared contradiction and stale node administration never release dispatch',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);const r=f.report();
  f.persist({...r,continuity:{previousReportDigest:null,contradiction:true}});
  assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');assert.equal(f.count(),0);
  const other=f.report({statement:{...r.statement,digest:h('6')},nodes:{...r.nodes,l1:{...r.nodes.l1,operator:'changed-administration'}}});f.persist(other);
  assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');assert.equal(f.count(),0);
});


test('J77-08 / A-181.3: two reports for one statement with the same l1BlockHash and different l1BlockTime are a contradiction; dispatch stays delayed',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);const r=f.report();
  f.persist(r);f.persist({...r,finality:{...r.finality,l1BlockTime:r.finality.l1BlockTime+1},observedAt:1});
  assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');assert.equal(f.count(),0);
});

test('A-150.0: a CEMENTED report with an OPEN refutation residual or a null cementedAt is listed CEMENTED_REQUIRES_CLOSED_AND_LEVEL and never releases dispatch; a closed CEMENTED report does',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);const base=f.report();
  for(const finality of [{refutationResidual:'OPEN',cementedAt:101},{refutationResidual:'CLOSED',cementedAt:null}]){
    const r=f.persist({...base,finality:{...base.finality,label:'CEMENTED',...finality}});
    assert.deepEqual([r.claimConsistency.status,[...r.claimConsistency.codes]],['LISTED_CLAIM_CONTRADICTION',['CEMENTED_REQUIRES_CLOSED_AND_LEVEL']]);
  }
  assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');assert.equal(f.count(),0);
  const closed=f.persist({...base,finality:{...base.finality,label:'CEMENTED',refutationResidual:'CLOSED',cementedAt:101}});assert.equal(closed.claimConsistency.status,'NO_LISTED_CLAIM_CONTRADICTION');
  assert.equal((await g.run('create_incident_ticket',title)).status,'RESPONSE_RETAINED');assert.equal(f.count(),1);
  assert.match(readFileSync(f.paths.barrier,'utf8'),/"label":"CEMENTED"/);
});

test('later changed administration voids earlier matching reports, not just the later candidate',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);const first=f.persist();
  const changed=f.report({nodes:{...first.claimedReport.nodes,l1:{...first.claimedReport.nodes.l1,operator:'changed-admin'}},
    observedAt:1,continuity:{previousReportDigest:first.reportDigest,contradiction:false}});f.persist(changed);
  assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);
});

test('report custody refuses a different profile trust root in the same directory',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);f.persist();await g.close();
  const root={...f.root,destination:'0x'+'77'.repeat(20)};
  await assert.rejects(f.open({anchoring:{...f.anchoring,trustRootBytes:canonicalEncode(root),async readInstanceImmutables(){return {destination:root.destination,namespaceId:root.namespaceId,publisher:root.manifest.publisher,chainId:root.manifest.chain.id,mode:'CONSENSUS_VERIFIED'};}}}),e=>e.code==='TRUST_ROOT_INVALID');assert.equal(f.count(),0);
});


for(const kind of ['stop','retire'])test(`pre-existing ${kind} refuses resume as NOT_DISPATCHED without Core refusal`,async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);f.persist();
  if(kind==='stop')f.stop();else await f.owner.advanceEpoch({agent:'worker',from:1,to:2});
  const before=readFileSync(f.local.historyFile),result=await g.run('create_incident_ticket',title);
  assert.equal(result.status,'NOT_DISPATCHED');assert.equal(result.reason,kind==='stop'?'STOPPED':'ACCESS_NOT_CURRENT');
  assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);assert.deepEqual(readFileSync(f.local.historyFile),before);
});


// Inject process-local filesystem failures at the actual shared durableCreate boundaries. This does not weaken production I/O.
function injectDurableFault(target, phase) {
  const original={open:fs.openSync,write:fs.writeFileSync,sync:fs.fsyncSync,close:fs.closeSync},files=new Map();let fired=false,created=false;
  const fail=()=>{fired=true;throw Object.assign(new Error('synthetic crash boundary'),{code:'STORAGE_UNAVAILABLE'});};
  fs.openSync=function(path,flags,...rest){
    const selected=String(path)===target && typeof flags==='number' && (flags&fs.constants.O_EXCL)!==0;
    if(selected&&phase==='before-create'&&!fired)fail();
    const fd=original.open(path,flags,...rest);files.set(fd,String(path));
    if(selected){created=true;if(phase==='after-create'&&!fired){original.close(fd);files.delete(fd);fail();}}
    return fd;
  };
  fs.writeFileSync=function(fd,...args){const selected=files.get(fd)===target;
    if(selected&&phase==='before-write'&&!fired)fail();const result=original.write(fd,...args);if(selected&&phase==='after-write'&&!fired)fail();return result;};
  fs.fsyncSync=function(fd){const selected=files.get(fd)===target, directory=created&&files.get(fd)===target.slice(0,target.lastIndexOf('/'));
    if(!fired&&((selected&&phase==='before-file-sync')||(directory&&phase==='before-directory-sync')))fail();
    const result=original.sync(fd);if(!fired&&((selected&&phase==='after-file-sync')||(directory&&phase==='after-directory-sync')))fail();return result;};
  fs.closeSync=function(fd){files.delete(fd);return original.close(fd);};syncBuiltinESMExports();
  return ()=>{fs.openSync=original.open;fs.writeFileSync=original.write;fs.fsyncSync=original.sync;fs.closeSync=original.close;syncBuiltinESMExports();return fired;};
}
for(const kind of ['barrier','attempt','report'])for(const phase of ['before-create','after-create','before-write','after-write','before-file-sync','after-file-sync','before-directory-sync','after-directory-sync']){
  test(`durable fault ${kind} ${phase}: callback count and retry disposition`,async t=>{
    const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);f.persist();const before=readFileSync(f.local.historyFile);
    const undo=injectDurableFault(f.paths[kind],phase);let result,fired;
    try{result=await g.run('create_incident_ticket',title);}finally{fired=undo();}
    assert.equal(fired,true,'actual production boundary was intercepted');
    assert.equal(f.count(),kind==='report'?1:0);
    if(kind!=='report')assert.deepEqual(readFileSync(f.local.historyFile),before,'failure never writes a Core refusal or outcome');
    await g.close();const next=await f.open();const again=await next.run('create_incident_ticket',title);
    if(kind==='report'){assert.equal(f.count(),1,'report failure cannot repeat an effect');assert.equal(existsSync(f.paths.attempt),true);}
    else if(kind==='attempt'&&phase!=='before-create'){
      assert.equal(result.status,'OUTCOME_UNKNOWN');assert.equal(again.status,'OUTCOME_UNKNOWN');assert.equal(f.count(),0,'durable start is reconcile-only even when empty');
    }else if(kind==='barrier'&&['after-create','before-write'].includes(phase)){
      assert.equal(again.status,'NOT_DISPATCHED');assert.equal(again.reason,'ADMISSION_MISMATCH');assert.equal(f.count(),0,'broken chain cannot be skipped');
    }else{
      assert.equal(again.status,'RESPONSE_RETAINED');assert.equal(f.count(),1,'absence of durable start permits exactly one resumption');
    }
  });
}


test('malformed protected report is a storage failure, never an authority failure or call',async t=>{
  const f=await fixture(t),g=await f.open();await g.run('create_incident_ticket',title);
  writeFileSync(join(f.anchoring.reportDirectory,'f'.repeat(64)+'.json'),'{',{mode:0o600});
  const before=readFileSync(f.local.historyFile),answer=await g.run('create_incident_ticket',title);
  assert.equal(answer.status,'NOT_DISPATCHED');assert.equal(answer.reason,'STORAGE_UNAVAILABLE');assert.equal(f.count(),0);assert.deepEqual(readFileSync(f.local.historyFile),before);
});

test('unverified instance observations cannot release a consensus barrier',async t=>{
  const f=await fixture(t),g=await f.open({anchoring:{...f.anchoring,async readInstanceImmutables(){return {destination:f.root.destination,namespaceId:f.root.namespaceId,publisher:f.manifest.publisher,chainId:f.manifest.chain.id,mode:'UNVERIFIED'};}}});
  await g.run('create_incident_ticket',title);f.persist();assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');assert.equal(f.count(),0);
});

test('physical rollback before resume is HISTORY_DIVERGED, without any external call',async t=>{
  const f=await fixture(t),g=await f.open(),prefix=readFileSync(f.local.historyFile);
  await g.run('create_incident_ticket',title);f.persist();writeFileSync(f.local.historyFile,prefix,{mode:0o600});
  const answer=await g.run('create_incident_ticket',title);assert.equal(answer.status,'NOT_DISPATCHED');assert.equal(answer.reason,'HISTORY_DIVERGED');assert.equal(f.count(),0);assert.deepEqual(readFileSync(f.local.historyFile),prefix);assert.equal(existsSync(f.paths.attempt),false);
});

test('J77-01 / A-195.1 / A-207.1: under the trusted-node barrier a report claiming CONSENSUS_VERIFIED is not eligible (no independent L1 node qualified it), nor is a CONSENSUS_VERIFIED instance observation',async t=>{
  const claim=await onPair(t,{...TEST_PAIR,observed:'TRUSTED_NODE',l1Operator:'synthetic-evm'},{allowTestProfile:true,testBarrierMode:'TRUSTED_NODE'});
  const g=await claim.open();assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED');
  claim.persist(claim.report());// L1_FINAL, CONSENSUS_VERIFIED, with an l1BlockTime
  assert.equal((await g.run('create_incident_ticket',title)).status,'DELAYED','a consensus claim is not eligible under the trusted-node barrier');
  assert.equal(claim.count(),0);assert.equal(existsSync(claim.paths.attempt),false);
  const observed=await onPair(t,{...TEST_PAIR,observed:'CONSENSUS_VERIFIED',l1Operator:'synthetic-evm'},{allowTestProfile:true,testBarrierMode:'TRUSTED_NODE'});
  const h=await observed.open();assert.equal((await h.run('create_incident_ticket',title)).status,'DELAYED');
  observed.persist(observed.report({mode:'TRUSTED_NODE',l1BlockTime:null}));
  assert.equal((await h.run('create_incident_ticket',title)).status,'DELAYED','the observation mode must be TRUSTED_NODE too');
  assert.equal(observed.count(),0);
});

test('J77-04 / A-207.1: a TEST profile under the default CONSENSUS_VERIFIED barrier still needs independent node administration',async t=>{
  const f=await onPair(t,{...TEST_PAIR,l1Operator:'synthetic-evm'},{allowTestProfile:true});
  await assert.rejects(f.open(),e=>e.code==='TRUST_ROOT_INVALID'&&/Independent node administration/.test(e.detail));assert.equal(f.reads(),0);
});
