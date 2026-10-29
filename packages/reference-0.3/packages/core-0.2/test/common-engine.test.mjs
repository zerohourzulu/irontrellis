import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, cpSync, writeFileSync, realpathSync, rmSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { derivePortableAdapterIdempotencyKey, derivePortableAdapterNoEffectReference } from '../src/core/portable-adapter-engine.ts';
import { createPortableQueryProjectionWriter } from '../src/core/portable-query-output.ts';
import { createPacketExecutor } from '../../../integrations/core-0.2-reference/src/packet-executor.mjs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import * as core from '../src/core/index.ts';
import { DurableAdmissionCoordinator } from '../src/sdk/durable-admission.ts';
import { PortableFileEventStore } from '../src/indexer/portable-file-event-store.ts';
import { DeterministicSimulatedAdapter } from '../src/adapters/simulated-adapter.ts';

const clone = value => structuredClone(value);
const read = path => JSON.parse(readFileSync(new URL(path, import.meta.url),'utf8'));
function fixture(mode) {
  const base=`../../../tests/fixtures/original-core/cases/core02-${mode}-r1/`;
  const history=read(base+'export/history.json'), config=read(base+'case.json'), input=read(base+'admission.json').input;
  const index=history.findIndex(e=>e.type==='TRANSACTION_INTENT_ADMITTED'), admissionEvent=history[index];
  const submission={operationVersion:'continuity-adapter-submission/0.2',domain:config.domain,intentId:admissionEvent.data.intentId,admissionEvent,admittedHistory:history.slice(0,index+1)};
  return {history,config,input,submission,identity:core.derivePortableAdapterIdentity(submission),receipt:read(base+'export/receipt.json'),summary:read(base+'export/summary.json')};
}
const replay=events=>core.replayPortable({operationVersion:core.PORTABLE_REPLAY_VERSION,events});
const rejected=events=>assert.notEqual(replay(events).status,'ACCEPTED');
const consumptionIndex=events=>events.findIndex(e=>e.type==='TRANSACTION_INTENT_CONSUMED');
async function storeFor(events, run) {
  const dir=mkdtempSync(join(tmpdir(),'continuity-core02-check-'));
  console.log(`Common-engine store directory: ${dir}`);
  try { const store=new PortableFileEventStore(join(dir,'history.jsonl'));store.appendAll(events);return await run(store); }
  finally { console.log(`Retained common-engine store: ${dir}`); }
}
const coordinator=(store,adapter)=>new DurableAdmissionCoordinator(store,adapter,{authoritativeNow:()=>replay(store.readAll()).head.canonicalTime+1});
const typedResult=(identity,ack)=>({status:'SUBMITTED',idempotencyKey:identity.idempotencyKey,submissionFingerprint:identity.submissionFingerprint,acknowledgment:ack,evidence:core.portableAdapterAcknowledgmentEvidence(identity,ack)});

test('one engine reconstructs both actual profiles and preserves distinct receipt/effect claims',()=>{
  for(const mode of ['packet','simulated']) {
    const f=fixture(mode),r=replay(f.history);assert.equal(r.status,'ACCEPTED');
    const consumed=f.history[consumptionIndex(f.history)].data;
    assert.deepEqual(f.receipt.payload.result.acknowledgment,consumed.acknowledgment);
    assert.equal(consumed.acknowledgment.result.kind,mode==='packet'?'LOCAL_PACKET_CREATED':'SIMULATED_SUBMISSION');
    assert.equal(f.receipt.payload.assurance.externalOutcome,mode==='packet'?'NOT_PROVEN':'SIMULATED');
    const recorded=f.history.findIndex(e=>e.type==='RECEIPT_RECORDED');
    const verified=core.verifyPortableReceipt({operationVersion:core.PORTABLE_RECEIPT_VERIFICATION_VERSION,artifact:f.receipt,issuanceEvents:f.history.slice(0,recorded+1),observedEvents:f.history,expectedDomain:f.config.domain,verifierTime:r.head.canonicalTime});
    assert.equal(verified.status,'EVALUATED');assert.equal(verified.valid,true);assert.equal(verified.current,false);
    assert.equal(f.summary.duty.status,'OUTCOME_UNKNOWN');
  }
});
test('genesis policy and declared profile cannot be substituted beneath an existing signed admission',()=>{
  const f=fixture('packet'),declared=f.history.findIndex(e=>e.type==='TRANSACTION_INTENT_DECLARED');
  let changed=clone(f.submission.admittedHistory);changed[0].data.adapterPolicyHash='0x'+'1'.repeat(64);rejected(changed);
  changed=clone(f.submission.admittedHistory);changed[declared].data.adapterProfile=core.approvedPortableAdapterProfile(core.SIMULATED_ADAPTER_ID);rejected(changed);
  changed=clone(f.submission.admittedHistory);delete changed[declared].data.adapterProfile;rejected(changed);
  changed=clone(f.submission.admittedHistory);changed[declared].data.adapterProfile.descriptorHash='0x'+'2'.repeat(64);rejected(changed);
  assert.throws(()=>core.approvedPortableAdapterProfile('adapter:unapproved'));
});
test('typed ACK enforces profile, result kind, digest, closed fields and original identity',()=>{
  const f=fixture('packet'),ack=f.receipt.payload.result.acknowledgment;
  assert.equal(core.validatePortableAdapterAcknowledgment(ack,f.identity),true);
  const changes=[a=>a.result.kind='SIMULATED_SUBMISSION',a=>a.result.manifestDigest.algorithm='keccak256',a=>a.result.manifestDigest.value='0xBAD',a=>a.extra=true,a=>a.adapterProfile=core.approvedPortableAdapterProfile(core.SIMULATED_ADAPTER_ID),a=>a.domain.deploymentId+='-other',a=>a.intentId+='-other',a=>a.admissionHead.position++,a=>a.idempotencyKey='0x'+'3'.repeat(64),a=>a.submissionFingerprint='0x'+'4'.repeat(64)];
  for(const change of changes){const a=clone(ack);change(a);assert.equal(core.validatePortableAdapterAcknowledgment(a,f.identity),false);}
});
test('new typed data refuses getters and proxies without running their traps',()=>{
  const f=fixture('packet');let touched=0;
  const value=clone(f.receipt.payload.result.acknowledgment);Object.defineProperty(value,'result',{enumerable:true,get(){touched++;return {};}});
  assert.equal(core.validatePortableAdapterAcknowledgment(value,f.identity),false);
  const proxy=new Proxy({}, {getPrototypeOf(){touched++;return Object.prototype;},ownKeys(){touched++;return [];},get(){touched++;return undefined;}});
  assert.equal(core.validatePortableAdapterAcknowledgment(proxy,f.identity),false);
  const events=clone(f.submission.admittedHistory), declaration=events.find(e=>e.type==='TRANSACTION_INTENT_DECLARED');
  Object.defineProperty(declaration.data.adapterProfile,'profileId',{enumerable:true,get(){touched++;return core.LOCAL_EVIDENCE_PACKET_ADAPTER_ID;}});
  rejected(events);assert.equal(touched,0);
});
test('canonical consumption refuses ACK substitutions even when the generic evidence hash is recomputed',()=>{
  for(const mode of ['packet','simulated']) {
    const f=fixture(mode),index=consumptionIndex(f.history);
    for(const change of [a=>a.domain.chainId='1',a=>a.admissionHead.hash='0x'+'5'.repeat(64),a=>a.submissionFingerprint='0x'+'6'.repeat(64)]) {
      const events=clone(f.history.slice(0,index+1)),data=events[index].data;change(data.acknowledgment);
      data.evidenceReference.reference=core.hashCanonical(data.acknowledgment);rejected(events);
    }
    const events=clone(f.history.slice(0,index+1));events[index].data.transactionReference='0x'+'7'.repeat(64);rejected(events);
  }
});
test('receipt creation rejects the other profile assurance before requesting a signature',async()=>{
  let signs=0;
  for(const mode of ['packet','simulated']){
    const f=fixture(mode),events=f.history.slice(0,consumptionIndex(f.history)+1);
    await assert.rejects(()=>core.createPortableReceipt({events,intentId:f.submission.intentId,issuedAt:replay(events).head.canonicalTime+1,externalOutcome:mode==='packet'?'SIMULATED':'NOT_PROVEN'},{keyId:`key:${f.config.caseId}:a`,signHash:()=>{signs++;throw new Error('must not sign');}}));
  }
  assert.equal(signs,0);
});
test('simulator no-effect is typed, retained and terminal; local FAILED remains unsupported',async()=>{
  const f=fixture('simulated'),sim=new DeterministicSimulatedAdapter({failIntentIds:[f.submission.intentId]});
  assert.equal(sim.reconcile(f.submission).status,'OUTCOME_UNKNOWN');
  const result=await sim.submit(f.submission);assert.equal(result.status,'FAILED');assert.equal(core.validatePortableAdapterNoEffect(result.noEffect,f.identity),true);
  assert.equal((await sim.submit(f.submission)).status,'RETRY');assert.equal(sim.reconcile(f.submission).status,'RETRY');assert.equal(sim.attempts.length,1);
  const events=clone(f.submission.admittedHistory);events.push({id:'test:sim-no-effect',type:'TRANSACTION_OUTCOME_RECORDED',timestamp:replay(events).head.canonicalTime+1,data:{intentId:f.submission.intentId,status:'FAILED',attesterId:core.SIMULATED_ADAPTER_ID,evidenceReference:result.evidence,noEffect:result.noEffect}});
  assert.equal(replay(events).status,'ACCEPTED');
  const query=core.survivesPortable({operationVersion:core.PORTABLE_QUERY_VERSION,observedEvents:events,targetAgentId:`a:${f.config.caseId}`,evaluationTime:replay(events).head.canonicalTime,disclosure:core.portablePublicQueryDisclosure('SURVIVES')});
  assert.deepEqual(query.answer.adapterOutcomes[0].latestOutcome.noEffect,result.noEffect);
  assert.equal(query.answer.unresolvedIntents.some(row=>row.intentId===f.submission.intentId),false);
  const p=fixture('packet');assert.throws(()=>core.createPortableAdapterNoEffect(p.identity));
  const local=clone(p.submission.admittedHistory);local.push({...events.at(-1),data:{...events.at(-1).data,intentId:p.submission.intentId}});rejected(local);
  const bad=clone(events);bad.at(-1).data.status='OUTCOME_UNKNOWN';rejected(bad);
});
test('SDK refuses mismatched configured profiles before persisting admission or invoking an executor',async()=>{
  const f=fixture('packet');let calls=0;
  await storeFor(f.input.events,async store=>{
    const adapter={adapterProfile:core.approvedPortableAdapterProfile(core.SIMULATED_ADAPTER_ID),submit(){calls++;throw Error('must not invoke');},reconcile(){calls++;throw Error('must not reconcile');}};
    const sdk=coordinator(store,adapter),before=core.canonicalEncode(store.readAll()),admitted=sdk.admit(sdk.prepare(f.input));
    assert.notEqual(admitted.status,'ADMITTED');assert.equal(core.canonicalEncode(store.readAll()),before);assert.equal(calls,0);
  });
});
test('SDK records cached simulator failure through read-only reconciliation without another submit',async()=>{
  const f=fixture('simulated'),sim=new DeterministicSimulatedAdapter({failIntentIds:[f.submission.intentId]});await sim.submit(f.submission);
  await storeFor(f.submission.admittedHistory,async store=>{
    const sdk=coordinator(store,sim),result=await sdk.reconcile(f.submission.intentId);assert.equal(result.status,'RETRY');assert.equal(result.recorded,true);
    assert.equal(store.readAll().at(-1).type,'TRANSACTION_OUTCOME_RECORDED');assert.equal(store.readAll().at(-1).data.status,'FAILED');
    const before=core.canonicalEncode(store.readAll());assert.equal((await sdk.reconcile(f.submission.intentId)).status,'RETRY');assert.equal(core.canonicalEncode(store.readAll()),before);assert.equal(sim.attempts.length,1);
  });
});
test('SDK captures valid cached RETRY from its sole invoke, and uncertainty does not cause a resend',async()=>{
  const f=fixture('simulated');
  await storeFor(f.input.events,async store=>{
    const sim=new DeterministicSimulatedAdapter();let calls=0;
    const adapter={adapterProfile:sim.adapterProfile,async submit(input){calls++;await sim.submit(input);return sim.reconcile(input);},reconcile:input=>sim.reconcile(input)};
    const sdk=coordinator(store,adapter),admitted=sdk.admit(sdk.prepare(f.input));assert.equal(admitted.status,'ADMITTED');
    const result=await sdk.invoke(admitted.capability);assert.equal(result.status,'RETRY');assert.equal(result.recorded,true);assert.equal(calls,1);assert.equal(sim.attempts.length,1);
    assert.equal((await sdk.invoke(admitted.capability)).status,'NOT_INVOKED');assert.equal(calls,1);
  });
  await storeFor(f.input.events,async store=>{
    let calls=0;const adapter={adapterProfile:core.approvedPortableAdapterProfile(core.SIMULATED_ADAPTER_ID),submit(input){calls++;const identity=core.derivePortableAdapterIdentity(input);return Promise.resolve({status:'OUTCOME_UNKNOWN',idempotencyKey:identity.idempotencyKey,submissionFingerprint:identity.submissionFingerprint});},reconcile(input){const identity=core.derivePortableAdapterIdentity(input);return {status:'OUTCOME_UNKNOWN',idempotencyKey:identity.idempotencyKey,submissionFingerprint:identity.submissionFingerprint};}};
    const sdk=coordinator(store,adapter),admitted=sdk.admit(sdk.prepare(f.input));assert.equal(admitted.status,'ADMITTED');assert.equal((await sdk.invoke(admitted.capability)).status,'OUTCOME_UNKNOWN');assert.equal((await sdk.reconcile(f.submission.intentId)).status,'OUTCOME_UNKNOWN');assert.equal(calls,1);assert.equal(store.readAll().some(e=>e.type==='TRANSACTION_INTENT_CONSUMED'),false);
  });
});
test('post-yield control loss refuses consumption of an otherwise matching acknowledgment',async()=>{
  const f=fixture('simulated');await storeFor(f.input.events,async store=>{
    let calls=0;const adapter={adapterProfile:core.approvedPortableAdapterProfile(core.SIMULATED_ADAPTER_ID),async submit(input){calls++;const identity=core.derivePortableAdapterIdentity(input),ack=core.createPortableAdapterAcknowledgment(identity);await Promise.resolve();const h=replay(store.readAll()).head;store.appendAtExpectedHead({id:'test:epoch-after-entry',type:'CONTROL_EPOCH_ADVANCED',timestamp:h.canonicalTime+1,data:{agentId:`a:${f.config.caseId}`,controllerId:`controller:${f.config.caseId}`,fromEpoch:1,toEpoch:2}},h);return typedResult(identity,ack);},reconcile(){throw Error('must not reconcile');}};
    const sdk=coordinator(store,adapter),admitted=sdk.admit(sdk.prepare(f.input));assert.equal(admitted.status,'ADMITTED');assert.equal((await sdk.invoke(admitted.capability)).status,'OUTCOME_UNKNOWN');assert.equal(calls,1);assert.equal(store.readAll().some(e=>e.type==='TRANSACTION_INTENT_CONSUMED'),false);assert.equal(store.readAll().at(-1).type,'CONTROL_EPOCH_ADVANCED');assert.equal(replay(store.readAll()).status,'ACCEPTED');
  });
});
test('historical versions retain separate interpretation and are rejected by the new engine',()=>{
  for(const path of ['../../../tests/fixtures/original-core/legacy-intake-history.json','../../../tests/fixtures/original-core/legacy-handover-history.json']) {
    rejected(read(path));
  }
});

test('query output counts nested evidence occurrences, aliases and merges at the retained bound',()=>{
  const ref={kind:'EXTERNAL',evidenceType:'test',reference:'one',attesterId:'test'};
  const make=()=>{const w=createPortableQueryProjectionWriter({rows:[]});w.row('rows','one',{nested:Array(4095).fill(ref)},[ref]);w.row('rows','one',{nested:Array(4095).fill(ref)},[ref]);return w;};
  const fits=make().finish(()=>{});assert.equal(fits.outputLimitExceeded,false);assert.equal(fits.answer.rows[0].nested.length,4095);
  const over=make();over.row('rows','two',{nested:ref},[]);assert.equal(over.finish(()=>{}).outputLimitExceeded,true);
});
test('SDK rejects proxy results and accessor profile configuration without running their traps',async()=>{
  const f=fixture('simulated');let touched=0;
  await storeFor(f.input.events,async store=>{
    const adapter={adapterProfile:core.approvedPortableAdapterProfile(core.SIMULATED_ADAPTER_ID),async submit(input){const identity=core.derivePortableAdapterIdentity(input),ack=core.createPortableAdapterAcknowledgment(identity),result=typedResult(identity,ack);result.acknowledgment=new Proxy(ack,{getPrototypeOf(){touched++;return Object.prototype;},ownKeys(){touched++;return [];},get(){touched++;return undefined;}});return result;},reconcile(){throw Error('must not reconcile');}};
    const sdk=coordinator(store,adapter),admitted=sdk.admit(sdk.prepare(f.input));assert.equal(admitted.status,'ADMITTED');assert.equal((await sdk.invoke(admitted.capability)).status,'OUTCOME_UNKNOWN');assert.equal(store.readAll().some(e=>e.type==='TRANSACTION_INTENT_CONSUMED'),false);
    const bad={submit(){},reconcile(){}};Object.defineProperty(bad,'adapterProfile',{get(){touched++;return adapter.adapterProfile;}});assert.throws(()=>coordinator(store,bad));
  });
  assert.equal(touched,0);
});
test('reference reader binds configured profile to the signed declaration',async()=>{
  const repo=fileURLToPath(new URL('../../../',import.meta.url));
  const dir=mkdtempSync(join(repo,'integrations/.core02-reader-check-'));
  console.log(`Common-engine reader directory: ${dir}`);
  try {
    cpSync(join(repo,'integrations/core-0.2-reference/src'),join(dir,'src'),{recursive:true});
    cpSync(join(repo,'tests/fixtures/original-core/cases/core02-packet-r1'),join(dir,'cases/core02-packet-r1'),{recursive:true});
    const config=fixture('packet').config;config.adapterProfile=core.approvedPortableAdapterProfile(core.SIMULATED_ADAPTER_ID);
    writeFileSync(join(dir,'cases/core02-packet-r1/case.json'),core.canonicalEncode(config)+'\n');
    const app=await import(pathToFileURL(join(dir,'src/application.mjs')).href);
    await assert.rejects(()=>app.inspectCase('core02-packet-r1'),/CASE_ADAPTER_PROFILE_CHANGED/);
    rmSync(dir,{recursive:true});
  } finally {console.log(`Retained common-engine reader: ${dir}`);}
});
test('packet inspector refuses internally consistent evidence for another intent',()=>{
  const f=fixture('packet'),dir=mkdtempSync(join(realpathSync(tmpdir()),'continuity-core02-packet-check-'));
  console.log(`Common-engine packet directory: ${dir}`);
  const source=fileURLToPath(new URL('../../../tests/fixtures/original-core/cases/core02-packet-r1/execution',import.meta.url));
  try {
    cpSync(source,dir,{recursive:true});
    const readLocal=p=>JSON.parse(readFileSync(join(dir,p),'utf8'));
    const write=(p,v)=>writeFileSync(join(dir,p),core.canonicalEncode(v)+'\n');
    const executor=createPacketExecutor({inputDirectory:f.config.inputDirectory,outputDirectory:dir,selection:f.config.selection,termsCommitment:f.config.termsCommitment,resource:readLocal('attempt.json').resource,domain:f.config.domain,intentId:f.submission.intentId});
    assert.equal(executor.inspect().status,'PACKET_VERIFIED');
    const attempt=readLocal('attempt.json'),manifest=readLocal('packet/manifest.json');
    attempt.adapterIdentity.intentId+=':other';attempt.adapterIdentity.idempotencyKey=derivePortableAdapterIdempotencyKey(f.config.domain,attempt.adapterIdentity.intentId);attempt.adapterIdentity.adapterNoEffectReference=derivePortableAdapterNoEffectReference(attempt.adapterIdentity.idempotencyKey,attempt.adapterIdentity.submissionFingerprint);attempt.idempotencyKey=attempt.adapterIdentity.idempotencyKey;manifest.idempotencyKey=attempt.idempotencyKey;manifest.adapterIdentity=attempt.adapterIdentity;write('attempt.json',attempt);write('packet/manifest.json',manifest);
    const digest=createHash('sha256').update(readFileSync(join(dir,'packet/manifest.json'))).digest('hex'),ack=core.createPortableAdapterAcknowledgment(attempt.adapterIdentity,'0x'+digest),record=readLocal('ack.json');
    record.idempotencyKey=attempt.idempotencyKey;record.manifestSha256=digest;record.acknowledgment=ack;record.evidence=core.portableAdapterAcknowledgmentEvidence(attempt.adapterIdentity,ack);write('ack.json',record);
    assert.equal(executor.inspect().status,'OUTCOME_UNKNOWN');
  }finally{console.log(`Retained common-engine packet: ${dir}`);}
});
