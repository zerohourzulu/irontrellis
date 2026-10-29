// Original accepted policy-edition regression tests; paths curated for this public candidate.
// All adapters below emit TEST DATA ONLY. They perform NO endpoint/state transition.
// Their typed ACKs test plumbing; they are deliberately not executor evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { inspect } from 'node:util';
import { createHash } from 'node:crypto';
import * as core from '../../../packages/core-0.2/src/core/index.ts';
import { DurableAdmissionCoordinator } from '../../../packages/core-0.2/src/sdk/durable-admission.ts';
import { PortableFileEventStore } from '../../../packages/core-0.2/src/indexer/portable-file-event-store.ts';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const VECTOR_PATH = join(ROOT, 'tests/fixtures/original-core/VECTORS.json');
const LEGACY_PATH = join(ROOT, 'tests/fixtures/original-core/cases/core02-simulated-r1/admission.json');
const vectorBytes = readFileSync(VECTOR_PATH);
assert.equal(createHash('sha256').update(vectorBytes).digest('hex'), 'feda44b0742571c44ea8354da69ac46187a2915c8ce661900c627c41f4adb894');
const vectors = JSON.parse(vectorBytes);
assert.equal(vectors.schemaVersion, 'continuity-prospective-adapter-policy-vectors/1');
const legacyBytes = readFileSync(LEGACY_PATH);
assert.equal(createHash('sha256').update(legacyBytes).digest('hex'), '25ff21a2e29f16803f4e23311b94d9b28a1504c961c0c41cb690882c9ff221a5');
const legacy = JSON.parse(legacyBytes);
const clone = value => structuredClone(value);
const ids = ['adapter:local-evidence-packet', 'adapter:local-synthetic-endpoint-state', 'adapter:simulated'];
const THIRD = ids[1], SIM = ids[2], PACKET = ids[0];
const TEST_DIGEST = '0x' + '2'.repeat(64); // Arbitrary test syntax, NOT a retained transition commitment.
const WRONG_HASH = '0x' + 'f'.repeat(64);
const RUN = mkdtempSync(join(tmpdir(), 'continuity-editions-NO-STATE-EFFECT-'));
console.log(`Retained prospective-test fixtures: ${RUN}`);
writeFileSync(join(RUN, 'SCOPE.txt'), 'TEST DATA ONLY. No actual endpoint or state transition. Every fixture is retained; no cleanup.\n');
writeFileSync(join(RUN, 'vectors.json'), readFileSync(VECTOR_PATH));
writeFileSync(join(RUN, 'legacy-admission.json'), readFileSync(LEGACY_PATH));
let sequence = 0;
const retain = (name, value) => writeFileSync(join(RUN, `${++sequence}-${name}.txt`), inspect(value, { depth: null, maxArrayLength: null, maxStringLength: null, getters: false, customInspect: false }) + '\n');
const replay = events => core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events });
const head = events => { const r = replay(events); assert.equal(r.status, 'ACCEPTED'); return r.head; };
const reject = (events, name, code) => { retain(name, events); const r = replay(events); retain(`${name}-result`, r); assert.equal(r.status, 'REJECTED'); if (code !== undefined) assert.equal(r.code, code); };
const profile = (edition, id) => clone(vectors[edition].profiles.find(p => p.profileId === id));
const remap = (value, from, to) => {
  if (typeof value === 'string') return value.replaceAll(from, to);
  if (Array.isArray(value)) return value.map(v => remap(v, from, to));
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, remap(v, from, to)]));
  return value;
};
let signerPromise;
const signer = () => signerPromise ??= (async () => {
  // Public development scalar1001, explicitly used by application.mjs:56-62. Never operational custody.
  const requireCore = createRequire(join(ROOT, 'packages/core-0.2/package.json'));
  const { privateKeyToAccount } = await import(pathToFileURL(requireCore.resolve('viem/accounts')).href);
  return privateKeyToAccount(`0x${(1001).toString(16).padStart(64, '0')}`);
})();
async function fixture(edition = 'E2', id = THIRD) {
  const oldCase = 'core02-simulated-r1';
  const name = `edition-test-${RUN.split('/').at(-1)}-${++sequence}`;
  // Fresh deployment/lineage, all event/entity/session/nonce IDs remapped BEFORE fresh signing.
  // Reuse only the old fixture's unsigned setup shapes; never relabel its old signed admission.
  const input = remap(clone(legacy.input), oldCase, name);
  delete input.binding.runtimeSignature;
  input.events[0].data.adapterPolicyHash = vectors[edition].policyHash;
  input.events.at(-1).data.adapterProfile = profile(edition, id);
  for (const e of input.events) if (e.type === 'AUTHORITY_GRANTED') delete e.data.grant.constraints.expiresAt;
  const account = await signer();
  assert.equal(input.events.find(e => e.type === 'RUNTIME_SESSION_ADMITTED').data.credentialAddress.toLowerCase(), account.address.toLowerCase());
  input.expectedHistoryHead = head(input.events);
  input.evaluationTime = input.expectedHistoryHead.canonicalTime + 1;
  const challenge = core.createPortableRuntimeAuthorizationChallenge({ domain: input.domain, request: input.request,
    evaluationTime: input.evaluationTime, policyVersion: input.policyVersion, historyHead: input.expectedHistoryHead, binding: input.binding });
  retain(`${name}-unsigned-input-and-challenge`, { input, challenge, fixtureSigner: 'PUBLIC_SCALAR_1001', effect: 'NONE' });
  input.binding.runtimeSignature = await account.signMessage({ message: { raw: core.hashCanonical(challenge) } });
  retain(`${name}-signed-input`, input);
  return { name, input, profile: profile(edition,id), account };
}
async function admittedFixture(edition = 'E2', id = THIRD) {
  const f = await fixture(edition,id), proposal = core.proposePortableIntentAdmission(f.input);
  retain(`${f.name}-proposal`, proposal); assert.equal(proposal.status, 'PROPOSED');
  const events = [...f.input.events, proposal.admissionEvent]; head(events);
  const submission = { operationVersion: 'continuity-adapter-submission/0.2', domain: f.input.domain,
    intentId: f.input.binding.intentId, admissionEvent: proposal.admissionEvent, admittedHistory: events };
  const identity = core.derivePortableAdapterIdentity(submission);
  retain(`${f.name}-admitted-identity`, { events, submission, identity });
  return { ...f, events, submission, identity };
}
const ackFor = identity => identity.adapterProfile.profileId === THIRD
  ? core.createLocalSyntheticEndpointStateAcknowledgment(identity, TEST_DIGEST)
  : core.createPortableAdapterAcknowledgment(identity, identity.adapterProfile.profileId === PACKET ? TEST_DIGEST : undefined);
const typed = (identity, ack = ackFor(identity)) => ({ status: 'SUBMITTED', idempotencyKey: identity.idempotencyKey,
  submissionFingerprint: identity.submissionFingerprint, acknowledgment: ack, evidence: core.portableAdapterAcknowledgmentEvidence(identity,ack) });
const consumption = (f, ack = ackFor(f.identity)) => ({ id: `${f.name}:test-consumption`, type: 'TRANSACTION_INTENT_CONSUMED', timestamp: head(f.events).canonicalTime + 1,
  data: { intentId: f.identity.intentId, adapterId: f.profile.profileId, idempotencyKey: f.identity.idempotencyKey,
    submissionFingerprint: f.identity.submissionFingerprint, status: 'SUBMITTED', acknowledgment: ack,
    transactionReference: core.portableAdapterAcknowledgmentTransactionReference(ack,f.identity), evidenceReference: core.portableAdapterAcknowledgmentEvidence(f.identity,ack) } });
async function withStore(f, run) {
  const dir = join(RUN, `${++sequence}-store`); mkdirSync(dir);
  const store = new PortableFileEventStore(join(dir,'history.jsonl')); store.appendAll(f.input.events);
  try { return await run(store); }
  finally { retain(`${f.name}-retained-store-path`, { dir, effect: 'NO_ENDPOINT_OR_STATE_EFFECT' }); }
}
const sdkFor = (store,adapter) => new DurableAdmissionCoordinator(store,adapter,{authoritativeNow:()=>head(store.readAll()).canonicalTime+1});
const admit = (sdk,f) => { const r=sdk.admit(sdk.prepare(f.input)); retain(`${f.name}-sdk-admission`,r); assert.equal(r.status,'ADMITTED'); return r; };
const mock = (f,submit,reconcile) => ({ adapterProfile: clone(f.profile), scope: 'DATA_ONLY_NO_STATE_EFFECT', submit, reconcile });

// G1: Expected hashes/schema names come only from the separately frozen root vector file.
test('E1/E2 fixed hash vectors, exact membership, closed tuples and unknown selectors',()=>{
  assert.equal(core.PORTABLE_ADAPTER_POLICY_HASH,vectors.E1.policyHash);
  assert.equal(core.PORTABLE_ADAPTER_POLICY_E2_HASH,vectors.E2.policyHash);
  assert.notEqual(vectors.E1.policyHash,vectors.E2.policyHash);
  assert.deepEqual(vectors.E1.profiles.map(p=>p.profileId),[PACKET,SIM]);
  assert.deepEqual(vectors.E2.profiles.map(p=>p.profileId),ids);
  for(const edition of ['E1','E2']) {
    const v=vectors[edition],policy=core.resolvePortableAdapterPolicy(v.policyHash);
    assert.equal(policy.edition,edition); assert.equal(policy.hash,v.policyHash); assert.deepEqual(policy.profiles,v.profiles);
    assert.equal(Object.isFrozen(policy),true); assert.equal(Object.isFrozen(policy.profiles),true);
    for(const p of v.profiles) {
      assert.deepEqual(core.approvedPortableAdapterProfileForPolicy(v.policyHash,p.profileId),p);
      assert.equal(core.validatePortableAdapterProfileForPolicy(v.policyHash,p),true);
      for(const bad of [{...p,profileVersion:'2'},{...p,descriptorHash:WRONG_HASH},{...p,extra:undefined}]) assert.equal(core.validatePortableAdapterProfileForPolicy(v.policyHash,bad),false);
    }
  }
  for(const hash of [undefined,null,'',WRONG_HASH]) {
    assert.equal(core.resolvePortableAdapterPolicy(hash),undefined);
    assert.throws(()=>core.approvedPortableAdapterProfileForPolicy(hash,SIM));
    assert.equal(core.validatePortableAdapterProfileForPolicy(hash,profile('E1',SIM)),false);
  }
  assert.throws(()=>core.approvedPortableAdapterProfileForPolicy(vectors.E2.policyHash,'adapter:unknown'));
  assert.equal(core.validatePortableAdapterProfileForPolicy(vectors.E2.policyHash,{...profile('E2',THIRD),profileId:'adapter:unknown'}),false);
  assert.throws(()=>core.approvedPortableAdapterProfile(THIRD));
  assert.equal(core.validatePortableAdapterProfile(profile('E2',THIRD)),false);
  assert.equal(core.validatePortableAdapterProfileForPolicy(vectors.E1.policyHash,profile('E2',THIRD)),false);
  for(const p of vectors.E1.profiles) assert.deepEqual(core.approvedPortableAdapterProfile(p.profileId),p);
});

test('fresh E2 signed history selects third identity; E1 membership and old signed heads remain binding',async()=>{
  for(const id of [PACKET,SIM]) { const f=await admittedFixture('E1',id); assert.deepEqual(f.identity.adapterProfile,profile('E1',id)); }
  const f=await admittedFixture(); assert.deepEqual(f.identity.adapterProfile,profile('E2',THIRD));
  const mismatch=clone(f.input.events); mismatch[0].data.adapterPolicyHash=vectors.E1.policyHash;
  reject(mismatch,'E1-third-membership','TRANSITION_INVALID');
  const unknown=clone(f.input.events); unknown[0].data.adapterPolicyHash=WRONG_HASH; reject(unknown,'unknown-genesis','EVENT_DATA_INVALID');
  const old=[...clone(legacy.input.events),clone(legacy.admission.result.admissionEvent)]; head(old);
  old[0].data.adapterPolicyHash=vectors.E2.policyHash; reject(old,'old-signed-E1-head-substitution');
  const changed=clone(f.submission); changed.admittedHistory.at(-2).data.adapterProfile=profile('E2',SIM);
  assert.throws(()=>core.derivePortableAdapterIdentity(changed));
});

test('all three paired ACK variants reject cross-profile, schema, result and closed-field substitutions',async()=>{
  const fixtures=await Promise.all(ids.map(id=>admittedFixture('E2',id))),acks=fixtures.map(f=>ackFor(f.identity));
  for(let i=0;i<fixtures.length;i++) {
    const f=fixtures[i],ack=acks[i];
    assert.equal(ack.schemaVersion,vectors.expectedAckSchemas[f.profile.profileId]);
    assert.equal(core.validatePortableAdapterAcknowledgment(ack,f.identity),true);
    assert.equal(core.portableAdapterAcknowledgmentEvidence(f.identity,ack).evidenceType,ack.schemaVersion);
    assert.equal(core.portableAdapterAcknowledgmentTransactionReference(ack,f.identity),f.profile.profileId===SIM?f.identity.submissionFingerprint:TEST_DIGEST);
    for(let j=0;j<fixtures.length;j++) if(i!==j) for(const field of ['adapterProfile','result']) {
      const bad=clone(ack); bad[field]=clone(acks[j][field]); retain('paired-substitution',bad);
      assert.equal(core.validatePortableAdapterAcknowledgment(bad,f.identity),false);
      assert.throws(()=>core.portableAdapterAcknowledgmentTransactionReference(bad,f.identity));
    }
    for(const bad of [{...clone(ack),schemaVersion:'continuity-unknown-ack/1'},{...clone(ack),extra:undefined}]) assert.equal(core.validatePortableAdapterAcknowledgment(bad,f.identity),false);
  }
  const third=fixtures[1]; assert.throws(()=>core.createPortableAdapterAcknowledgment(third.identity,TEST_DIGEST));
  const bad=clone(acks[1]); bad.result.transitionDigest.algorithm='sha256'; assert.equal(core.validatePortableAdapterAcknowledgment(bad,third.identity),false);
  bad.result.transitionDigest.algorithm='keccak256'; bad.schemaVersion='continuity-adapter-acknowledgment/0.2'; assert.equal(core.validatePortableAdapterAcknowledgment(bad,third.identity),false);
});

test('third consumption validates typed ACK fields and rejects canonical overflow before evidence hashing',async()=>{
  const f=await admittedFixture(),event=consumption(f); head([...f.events,event]);
  const mutations=[a=>a.domain.deploymentId+=':wrong',a=>a.schemaVersion='continuity-adapter-acknowledgment/0.2',a=>a.result.transitionDigest.algorithm='sha256',a=>a.result.transitionDigest.extra=undefined];
  for(const mutate of mutations) {
    const e=clone(event); mutate(e.data.acknowledgment); e.data.evidenceReference.reference=core.hashCanonical(e.data.acknowledgment);
    reject([...f.events,e],'third-invalid-consumption');
  }
  const oversized=clone(event); oversized.data.acknowledgment.result.transitionDigest.value='0x'+'a'.repeat(4096);
  retain('third-oversized-ack-before-hash',oversized);
  assert.throws(()=>core.hashCanonical(oversized.data.acknowledgment),/4096-byte ProtocolString bound/);
  reject([...f.events,oversized],'third-oversized-consumption');
  const wrong=clone(event); wrong.data.transactionReference=WRONG_HASH; reject([...f.events,wrong],'wrong-transaction-reference');
});

test('SDK configuration cannot override history and uncertain evidence schema must match third profile',async()=>{
  const f=await fixture(); let calls=0;
  await withStore(f,async store=>{
    const bad=mock(f,()=>{calls++;throw Error('must not submit');},()=>{throw Error('must not reconcile');}); bad.adapterProfile=profile('E1',SIM);
    const sdk=sdkFor(store,bad),before=core.canonicalEncode(store.readAll());
    assert.notEqual(sdk.admit(sdk.prepare(f.input)).status,'ADMITTED'); assert.equal(core.canonicalEncode(store.readAll()),before); assert.equal(calls,0);
  });
  await withStore(f,async store=>{
    const adapter=mock(f,async()=>{calls++;throw Error('must not submit after profile substitution');},()=>{throw Error('must not reconcile');});
    const sdk=sdkFor(store,adapter),a=admit(sdk,f); adapter.adapterProfile=profile('E1',SIM);
    assert.equal((await sdk.invoke(a.capability)).status,'NOT_INVOKED'); assert.equal(calls,0);
    assert.equal(store.readAll().some(e=>e.type==='TRANSACTION_INTENT_CONSUMED'),false);
  });
  for(const validSchema of [true,false]) {
    const f2=await fixture(); await withStore(f2,async store=>{
      const adapter=mock(f2,async input=>{
        const identity=core.derivePortableAdapterIdentity(input),ack=ackFor(identity),evidence=core.portableAdapterAcknowledgmentEvidence(identity,ack);
        assert.deepEqual(identity.adapterProfile,f2.profile);
        return {status:'OUTCOME_UNKNOWN',idempotencyKey:identity.idempotencyKey,submissionFingerprint:identity.submissionFingerprint,
          latestEvidence:{...evidence,evidenceType:validSchema?evidence.evidenceType:'continuity-adapter-acknowledgment/0.2'}};
      },()=>{throw Error('must not reconcile');});
      const sdk=sdkFor(store,adapter),a=admit(sdk,f2),result=await sdk.invoke(a.capability); retain('schema-specific-uncertainty',result);
      assert.equal(result.status,'OUTCOME_UNKNOWN');
      assert.equal(result.reason,validSchema?'The adapter cannot establish a definitive outcome.':'The adapter response is missing, invalid or exceptional.');
      assert.equal(store.readAll().some(e=>e.type==='TRANSACTION_INTENT_CONSUMED'),false);
    });
  }
});

test('third receipt remains NOT_PROVEN and complete query includes every transition digest field',async()=>{
  const f=await admittedFixture(),ack=ackFor(f.identity),events=[...f.events,consumption(f,ack)],issuedAt=head(events).canonicalTime+1;
  let signs=0;
  await assert.rejects(()=>core.createPortableReceipt({events,intentId:f.identity.intentId,issuedAt,externalOutcome:'SIMULATED'},
    {keyId:f.input.binding.credentialKeyId,signHash:()=>{signs++;throw Error('must not sign');}})); assert.equal(signs,0);
  const receipt=await core.createPortableReceipt({events,intentId:f.identity.intentId,issuedAt,externalOutcome:'NOT_PROVEN'},
    {keyId:f.input.binding.credentialKeyId,signHash:hash=>f.account.signMessage({message:{raw:hash}})});
  assert.deepEqual(receipt.payload.result.acknowledgment,ack); assert.equal(receipt.payload.result.status,'SUBMITTED');
  const verified=core.verifyPortableReceipt({operationVersion:core.PORTABLE_RECEIPT_VERIFICATION_VERSION,artifact:receipt,issuanceEvents:events,observedEvents:events,expectedDomain:f.input.domain,verifierTime:issuedAt});
  assert.equal(verified.status,'EVALUATED'); assert.equal(verified.historical,true); assert.equal(verified.current,false);
  assert.equal(verified.externalOutcome.status,'UNVERIFIED'); assert.equal(verified.externalOutcome.primaryCode,'NOT_PROVEN');
  const query=core.survivesPortable({operationVersion:core.PORTABLE_QUERY_VERSION,observedEvents:events,targetAgentId:f.input.request.actorId,evaluationTime:head(events).canonicalTime,disclosure:core.portablePublicQueryDisclosure('SURVIVES')});
  assert.equal(query.epistemicStatus,'ESTABLISHED'); assert.deepEqual(query.answer.adapterOutcomes[0].acknowledgment,ack);
  for(const suffix of ['', '.algorithm','.value']) assert.equal(query.scope.disclosure.includedFields.includes(`adapterOutcomes.acknowledgment.result.transitionDigest${suffix}`),true);
  retain('third-receipt-query', {events,receipt,verified,query,effect:'NO_ACTUAL_STATE_EFFECT'});
});

test('third no-effect and FAILED remain forbidden while E2 simulator retains its old typed no-effect',async()=>{
  const third=await admittedFixture(),sim=await admittedFixture('E2',SIM);
  assert.throws(()=>core.createPortableAdapterNoEffect(third.identity));
  const noEffect=core.createPortableAdapterNoEffect(sim.identity); assert.equal(core.validatePortableAdapterNoEffect(noEffect,sim.identity),true);
  assert.equal(core.validatePortableAdapterNoEffect(noEffect,third.identity),false);
  const forged={...clone(noEffect),adapterProfile:clone(third.profile),domain:clone(third.identity.domain),intentId:third.identity.intentId,
    admissionHead:clone(third.identity.admissionHead),idempotencyKey:third.identity.idempotencyKey,submissionFingerprint:third.identity.submissionFingerprint,
    result:{kind:'SIMULATED_NO_EFFECT',reference:third.identity.adapterNoEffectReference}};
  assert.equal(core.validatePortableAdapterNoEffect(forged,third.identity),false);
  assert.throws(()=>core.portableAdapterNoEffectEvidence(third.identity,forged));
  const forgedEvidence={kind:'EXTERNAL',evidenceType:'continuity-adapter-no-effect/0.2',reference:core.hashCanonical(forged),attesterId:SIM};
  const e={id:`${third.name}:bad-failed`,type:'TRANSACTION_OUTCOME_RECORDED',timestamp:head(third.events).canonicalTime+1,
    data:{intentId:third.identity.intentId,status:'FAILED',attesterId:SIM,evidenceReference:forgedEvidence,noEffect:forged}};
  reject([...third.events,e],'third-failed-refusal');
  await withStore(third,async store=>{
    const adapter=mock(third,async input=>{const i=core.derivePortableAdapterIdentity(input);return {status:'FAILED',idempotencyKey:i.idempotencyKey,submissionFingerprint:i.submissionFingerprint,evidence:e.data.evidenceReference,noEffect:forged};},()=>{throw Error('must not reconcile');});
    const sdk=sdkFor(store,adapter),a=admit(sdk,third); assert.equal((await sdk.invoke(a.capability)).status,'OUTCOME_UNKNOWN');
    assert.equal(store.readAll().some(e=>e.type==='TRANSACTION_OUTCOME_RECORDED'),false);
  });
});

test('post-yield control loss stays unknown; withheld mock ACK recovers read-only without resubmission',async()=>{
  for(const loseControl of [true,false]) {
    const f=await fixture(); await withStore(f,async store=>{
      let submits=0,reconciles=0,retained;
      const adapter=mock(f,async input=>{
        submits++; const identity=core.derivePortableAdapterIdentity(input); retained=typed(identity); retain('retained-data-only-ack',retained);
        await Promise.resolve();
        if(loseControl) {
          const h=head(store.readAll()); store.appendAtExpectedHead({id:`${f.name}:epoch-after-yield`,type:'CONTROL_EPOCH_ADVANCED',timestamp:h.canonicalTime+1,
            data:{agentId:f.input.request.actorId,controllerId:f.input.events.find(e=>e.type==='AGENT_CREATED').data.controllerId,fromEpoch:1,toEpoch:2}},h);
          return retained;
        }
        throw Error('Intentional withholding of DATA-ONLY mock ACK; no state effect occurred.');
      },()=>{reconciles++;return {status:'RETRY',idempotencyKey:retained.idempotencyKey,submissionFingerprint:retained.submissionFingerprint,retainedEvidence:retained.evidence,acknowledgment:retained.acknowledgment};});
      const sdk=sdkFor(store,adapter),a=admit(sdk,f); assert.equal((await sdk.invoke(a.capability)).status,'OUTCOME_UNKNOWN');
      assert.equal((await sdk.invoke(a.capability)).status,'NOT_INVOKED');
      assert.equal(store.readAll().some(e=>e.type==='TRANSACTION_INTENT_CONSUMED'),false);
      const recovered=await sdk.reconcile(f.input.binding.intentId); retain('read-only-mock-reconciliation',recovered);
      assert.equal(recovered.status,loseControl?'OUTCOME_UNKNOWN':'RETRY');
      assert.equal(store.readAll().filter(e=>e.type==='TRANSACTION_INTENT_CONSUMED').length,loseControl?0:1);
      if(!loseControl) assert.equal(recovered.recorded,true);
      assert.equal(submits,1); assert.equal(reconciles,1); head(store.readAll());
    });
  }
});
