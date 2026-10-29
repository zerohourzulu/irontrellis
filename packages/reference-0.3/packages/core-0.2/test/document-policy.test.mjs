// E3 common-engine development checks: DATA ONLY, no document publication.
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
const THIRD = 'adapter:local-document-release', SIM = ids[2], PACKET = ids[0];
const docDescriptor = { profileId: THIRD, profileVersion: '1', acknowledgmentSchemaVersion: 'continuity-local-document-release-ack/1', replayRuleId: 'continuity-adapter-replay/local-document-release/1' };
const oldDescriptors = JSON.parse(vectors.canonicalPreimages.E2).profiles;
vectors.E3 = { policyHash: core.hashCanonical({schemaVersion:'continuity-adapter-policy/0.2',profiles:[docDescriptor,...oldDescriptors]}), profiles:[{profileId:THIRD,profileVersion:'1',descriptorHash:core.hashCanonical(docDescriptor)},...vectors.E2.profiles] };
vectors.expectedAckSchemas[THIRD] = docDescriptor.acknowledgmentSchemaVersion;
const TEST_DIGEST = '0x' + '2'.repeat(64); // Arbitrary test syntax, NOT a retained transition commitment.
const WRONG_HASH = '0x' + 'f'.repeat(64);
const RUN = mkdtempSync(join(tmpdir(), 'continuity-document-policy-NO-DOCUMENT-EFFECT-'));
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
async function fixture(edition = 'E3', id = THIRD) {
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
async function admittedFixture(edition = 'E3', id = THIRD) {
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
  ? core.createLocalDocumentReleaseAcknowledgment(identity, TEST_DIGEST)
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

test('E3 prospective descriptor order preserves exact E1/E2 policy identities and membership',()=>{
  assert.equal(core.PORTABLE_ADAPTER_POLICY_HASH,vectors.E1.policyHash);
  assert.equal(core.PORTABLE_ADAPTER_POLICY_E2_HASH,vectors.E2.policyHash);
  assert.equal(core.PORTABLE_ADAPTER_POLICY_E3_HASH,vectors.E3.policyHash);
  assert.equal(core.LOCAL_DOCUMENT_RELEASE_ADAPTER_ID,THIRD);
  assert.equal(core.LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION,docDescriptor.acknowledgmentSchemaVersion);
  for(const edition of ['E1','E2','E3']) {
    const policy=core.resolvePortableAdapterPolicy(vectors[edition].policyHash);
    assert.equal(policy.edition,edition); assert.deepEqual(policy.profiles,vectors[edition].profiles);
    assert.ok(Object.isFrozen(policy)); assert.ok(Object.isFrozen(policy.profiles));
    for(const p of policy.profiles) assert.ok(Object.isFrozen(p));
  }
  assert.deepEqual(core.resolvePortableAdapterPolicy(vectors.E3.policyHash).profiles.map(p=>p.profileId),[THIRD,...ids]);
  for(const edition of ['E1','E2']) {
    assert.throws(()=>core.approvedPortableAdapterProfileForPolicy(vectors[edition].policyHash,THIRD));
    assert.equal(core.validatePortableAdapterProfileForPolicy(vectors[edition].policyHash,profile('E3',THIRD)),false);
  }
  assert.throws(()=>core.approvedPortableAdapterProfile(THIRD));
  assert.equal(core.validatePortableAdapterProfile(profile('E3',THIRD)),false);
  for(const bad of [undefined,null,'',WRONG_HASH]) assert.equal(core.resolvePortableAdapterPolicy(bad),undefined);
});

test('fresh E3 admission binds document profile; earlier editions and signed-head substitution reject',async()=>{
  const f=await admittedFixture(); assert.deepEqual(f.identity.adapterProfile,profile('E3',THIRD));
  for(const edition of ['E1','E2']) {
    const mismatch=clone(f.input.events); mismatch[0].data.adapterPolicyHash=vectors[edition].policyHash;
    reject(mismatch,edition+'-document-profile-forbidden');
  }
  const old=[...clone(legacy.input.events),clone(legacy.admission.result.admissionEvent)]; head(old);
  old[0].data.adapterPolicyHash=vectors.E3.policyHash; reject(old,'old-signed-head-substitution');
});

test('document ACK rejects cross-profile, identity, closed-field and malformed digest substitutions',async()=>{
  const f=await admittedFixture(),ack=ackFor(f.identity);
  assert.equal(core.validatePortableAdapterAcknowledgment(ack,f.identity),true);
  assert.equal(core.portableAdapterAcknowledgmentTransactionReference(ack,f.identity),TEST_DIGEST);
  assert.deepEqual(core.portableAdapterAcknowledgmentEvidence(f.identity,ack),{kind:'EXTERNAL',evidenceType:'continuity-local-document-release-ack/1',reference:core.hashCanonical(ack),attesterId:THIRD});
  assert.throws(()=>core.createPortableAdapterAcknowledgment(f.identity,TEST_DIGEST));
  for(const p of vectors.E2.profiles) {
    const bad=clone(ack);bad.adapterProfile=p;
    assert.equal(core.validatePortableAdapterAcknowledgment(bad,f.identity),false);
    assert.throws(()=>core.createLocalDocumentReleaseAcknowledgment({...f.identity,adapterProfile:p},TEST_DIGEST));
  }
  for(const mutate of [a=>a.extra=undefined,a=>a.result.extra=undefined,a=>a.result.publicationManifestDigest.extra=undefined,
    a=>a.adapterProfile.extra=undefined,a=>a.domain.extra=undefined,a=>a.admissionHead.extra=undefined,
    a=>a.schemaVersion='continuity-adapter-acknowledgment/0.2',a=>a.result.kind='LOCAL_PACKET_CREATED',
    a=>a.result.publicationManifestDigest.algorithm='keccak256',a=>a.idempotencyKey=WRONG_HASH,
    a=>a.submissionFingerprint=WRONG_HASH,a=>a.intentId+=':wrong',a=>a.admissionHead.position++]) {
    const bad=clone(ack);mutate(bad);assert.equal(core.validatePortableAdapterAcknowledgment(bad,f.identity),false);
    assert.throws(()=>core.portableAdapterAcknowledgmentTransactionReference(bad,f.identity));
  }
  for(const value of [undefined,'f'.repeat(64),'0x'+'F'.repeat(64),'0x'+'f'.repeat(63),'0x'+'f'.repeat(65)]) assert.throws(()=>core.createLocalDocumentReleaseAcknowledgment(f.identity,value));
});

test('document consumption validates typed ACK fields and rejects canonical overflow before evidence hashing',async()=>{
  const f=await admittedFixture(),event=consumption(f); head([...f.events,event]);
  const mutations=[a=>a.domain.deploymentId+=':wrong',a=>a.schemaVersion='continuity-adapter-acknowledgment/0.2',a=>a.result.publicationManifestDigest.algorithm='keccak256',a=>a.result.publicationManifestDigest.extra=undefined];
  for(const mutate of mutations) {
    const e=clone(event); mutate(e.data.acknowledgment); e.data.evidenceReference.reference=core.hashCanonical(e.data.acknowledgment);
    reject([...f.events,e],'document-invalid-consumption');
  }
  const oversized=clone(event); oversized.data.acknowledgment.result.publicationManifestDigest.value='0x'+'a'.repeat(4096);
  retain('document-oversized-ack-before-hash',oversized);
  assert.throws(()=>core.hashCanonical(oversized.data.acknowledgment),/4096-byte ProtocolString bound/);
  reject([...f.events,oversized],'document-oversized-consumption');
  const wrong=clone(event); wrong.data.transactionReference=WRONG_HASH; reject([...f.events,wrong],'wrong-transaction-reference');
});

test('SDK configuration cannot override history and uncertain evidence schema must match document profile',async()=>{
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

test('document receipt remains NOT_PROVEN and complete query includes every publication manifest digest field',async()=>{
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
  for(const suffix of ['', '.algorithm','.value']) assert.equal(query.scope.disclosure.includedFields.includes(`adapterOutcomes.acknowledgment.result.publicationManifestDigest${suffix}`),true);
  retain('document-receipt-query', {events,receipt,verified,query,effect:'NO_ACTUAL_STATE_EFFECT'});
});

test('document no-effect and FAILED remain forbidden while E2 simulator retains its old typed no-effect',async()=>{
  const document=await admittedFixture(),sim=await admittedFixture('E2',SIM);
  assert.throws(()=>core.createPortableAdapterNoEffect(document.identity));
  const noEffect=core.createPortableAdapterNoEffect(sim.identity); assert.equal(core.validatePortableAdapterNoEffect(noEffect,sim.identity),true);
  assert.equal(core.validatePortableAdapterNoEffect(noEffect,document.identity),false);
  const forged={...clone(noEffect),adapterProfile:clone(document.profile),domain:clone(document.identity.domain),intentId:document.identity.intentId,
    admissionHead:clone(document.identity.admissionHead),idempotencyKey:document.identity.idempotencyKey,submissionFingerprint:document.identity.submissionFingerprint,
    result:{kind:'SIMULATED_NO_EFFECT',reference:document.identity.adapterNoEffectReference}};
  assert.equal(core.validatePortableAdapterNoEffect(forged,document.identity),false);
  assert.throws(()=>core.portableAdapterNoEffectEvidence(document.identity,forged));
  const forgedEvidence={kind:'EXTERNAL',evidenceType:'continuity-adapter-no-effect/0.2',reference:core.hashCanonical(forged),attesterId:SIM};
  const e={id:`${document.name}:bad-failed`,type:'TRANSACTION_OUTCOME_RECORDED',timestamp:head(document.events).canonicalTime+1,
    data:{intentId:document.identity.intentId,status:'FAILED',attesterId:SIM,evidenceReference:forgedEvidence,noEffect:forged}};
  reject([...document.events,e],'document-failed-refusal');
  await withStore(document,async store=>{
    const adapter=mock(document,async input=>{const i=core.derivePortableAdapterIdentity(input);return {status:'FAILED',idempotencyKey:i.idempotencyKey,submissionFingerprint:i.submissionFingerprint,evidence:e.data.evidenceReference,noEffect:forged};},()=>{throw Error('must not reconcile');});
    const sdk=sdkFor(store,adapter),a=admit(sdk,document); assert.equal((await sdk.invoke(a.capability)).status,'OUTCOME_UNKNOWN');
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

test('document SHA-256 reference forbids terminal line breaks without changing legacy helper meanings',async()=>{
  const f=await admittedFixture(),ack=ackFor(f.identity);
  for(const suffix of ['\n','\r','\r\n']) {
    assert.throws(()=>core.createLocalDocumentReleaseAcknowledgment(f.identity,TEST_DIGEST+suffix));
    const bad=clone(ack);bad.result.publicationManifestDigest.value=TEST_DIGEST+suffix;
    assert.equal(core.validatePortableAdapterAcknowledgment(bad,f.identity),false);
    assert.equal(core.validatePortableAdapterAcknowledgmentShape(bad),false);
    assert.throws(()=>core.portableAdapterAcknowledgmentTransactionReference(bad,f.identity));
  }
  assert.equal(core.validatePortableAdapterAcknowledgment(ack,f.identity),true);
});
