import { mkdirSync, existsSync, openSync, closeSync, unlinkSync, readFileSync, readdirSync, lstatSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import * as core from '../../../packages/core-0.2/src/core/index.ts';
import { captureBoundedCanonicalReplayBodyIncrementally } from '../../../packages/core-0.2/src/core/canonical.ts';
import { createPortableReplayKernel } from '../../../packages/core-0.2/src/core/portable-replay.ts';
import { DurableAdmissionCoordinator } from '../../../packages/core-0.2/src/sdk/durable-admission.ts';
import { DurableReceiptCoordinator } from '../../../packages/core-0.2/src/sdk/durable-receipt.ts';
import { PortableFileEventStore } from '../../../packages/core-0.2/src/indexer/portable-file-event-store.ts';
import { produceAdministrativeEvent } from '../../../packages/core-0.2/src/administration/index.ts';
import { selectInput, createPacketExecutor } from './packet-executor.mjs';
import { writeNew, directory, readJson } from './io.mjs';
import { recoverPortableContentHashSigner } from '../../../packages/core-0.2/src/core/portable-authority-engine.ts';
import { validateProgressEntry, summarizeProgress } from './review-progress.mjs';
import { handoverProgress } from './handover-plan.mjs';
import { reviewedCaseVersion, validateExpectedCaseVersion } from './reviewed-case-version.mjs';
import { validateReviewSnapshotId, reviewSnapshotDirectory } from './review-snapshot-location.mjs';
import { parseSupplementRequest, SUPPLEMENT_SUMMARY_SCHEMA, SUPPLEMENT_EXPORT_SCHEMA, SUPPLEMENT_SOURCE_SCOPE, SIGNED_CONTEXT_SUMMARY_SCHEMA, SIGNED_CONTEXT_EXPORT_SCHEMA } from './review-supplement-format.mjs';
import { captureSupplementInput, readReviewSupplement, writeReviewSupplement } from './review-supplement-storage.mjs';
import { captureContextBoundInput, verifyContextBinding } from './signed-reviewed-context.mjs';
import { loadReviewSnapshotBundle } from '../../agent-gateway/src/evidence.mjs';
import { DeterministicSimulatedAdapter } from '../../../packages/core-0.2/src/adapters/simulated-adapter.ts';

export const VERSION = '0.2';
export const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const CASES = join(ROOT, 'cases');
const MAX_EVENTS = 80;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const bytes = value => Buffer.from(core.canonicalEncode(value) + '\n');
const equal = (a, b) => core.canonicalEncode(a) === core.canonicalEncode(b);
const assert = (ok, code) => { if (!ok) throw new Error(code); };
function slug(value) { assert(typeof value === 'string' && /^[a-z][a-z0-9-]{0,31}$/.test(value), 'CASE_ID_MUST_BE_LOWERCASE_SLUG'); return value; }
function ids(caseId) {
  return Object.freeze(Object.fromEntries(['principal','controller','a','b','role','tenure-a','tenure-b','succession','collect-authority','obligate-authority','review-authority','progress-a-authority','progress-b-authority','obligation','resource','intent','nonce','stale-intent','stale-nonce'].map(name => [name, `${name}:${caseId}`])));
}
const domainFor = caseId => ({ protocol: 'continuity', version: VERSION, deploymentId: `core-0.2-reference:${caseId}`, chainId: '31337', verifyingContract: '0x0000000000000000000000000000000000003002' });
const policyFor = caseId => `local-evidence-intake-policy:${caseId}/${VERSION}`;
const session = (caseId, who) => ({ runtimeSessionId: `session:${caseId}:${who}`, credentialKeyId: `key:${caseId}:${who}`, controlEpoch: 1 });
const termsFor = (caseId, selection) => ({ caseId, subject: 'Collect the selected synthetic log packet; investigate and account for unresolved review.', syntheticOnly: true, selection, reviewDeadline: 1000 });
function replay(events) {
  const kernel = createPortableReplayKernel();
  const captured = captureBoundedCanonicalReplayBodyIncrementally(events, Object.freeze({ operationVersion: core.PORTABLE_REPLAY_VERSION, events }), kernel.visit);
  assert(captured.status === 'CAPTURED', 'HISTORY_CAPTURE_FAILED');
  const result = kernel.finish(); assert(result.status === 'ACCEPTED', `HISTORY_REJECTED:${result.code ?? ''}`); return result.state;
}
function event(caseId, suffix, type, timestamp, data) { return core.immutableProtocolValue({ id: `${caseId}:${suffix}`, type, timestamp, data }); }
function graph(value) {
  if (value instanceof Map) return { '$localIntake.map': [...value.entries()].sort(([a], [b]) => core.compareProtocolStrings(a,b)).map(([key, member]) => [key, graph(member)]) };
  if (Array.isArray(value)) return value.map(graph);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key,member]) => [key,graph(member)]));
  return value;
}
async function credentials() {
  // Public development scalars, never operational keys. Reuse already installed signing library.
  const requireCore = createRequire(new URL('../../../packages/core/package.json', import.meta.url));
  const { privateKeyToAccount } = await import(pathToFileURL(requireCore.resolve('viem/accounts')).href);
  return Object.freeze(Object.fromEntries([['a',1001],['b',1003]].map(([name,scalar]) => {
    const account = privateKeyToAccount(`0x${scalar.toString(16).padStart(64,'0')}`);
    return [name, { address: account.address, signHash: hash => account.signMessage({ message: { raw: hash } }) }];
  })));
}
function load(caseId) {
  slug(caseId); const path = directory(join(CASES,caseId));
  const config = readJson(join(path,'case.json'),32768);
  assert(equal(Object.keys(config).sort(), ['adapterProfile','caseId','domain','inputDirectory','schemaVersion','selection','terms','termsCommitment'].sort()), 'CASE_CONFIG_FIELDS');
  assert(config.schemaVersion === `continuity-local-intake-case/${VERSION}` && config.caseId === caseId && equal(config.domain,domainFor(caseId)), 'CASE_CONFIG_DOMAIN');
  assert(equal(config.adapterProfile,core.approvedPortableAdapterProfile(config.adapterProfile.profileId)), 'CASE_ADAPTER_PROFILE');
  assert(equal(config.terms,termsFor(caseId,config.selection)) && core.hashCanonical(config.terms) === config.termsCommitment, 'CASE_CONFIG_TERMS');
  const store = new PortableFileEventStore(join(path,'history.jsonl'));
  const history = store.readAll(); assert(history.length > 0 && history.length <= MAX_EVENTS, 'CASE_HISTORY_LIMIT');
  assert(equal(history[0].data.domain,config.domain), 'CASE_HISTORY_DOMAIN');
  const i = ids(caseId), state = replay(history);
  const declared = state.intentDeclarations.get(i.intent);
  if (declared) {
    assert(declared.data.termsCommitment === config.termsCommitment, 'CASE_TERMS_CHANGED');
    assert(equal(declared.data.adapterProfile, config.adapterProfile), 'CASE_ADAPTER_PROFILE_CHANGED');
  }
  let time = state.head.canonicalTime;
  const executor = config.adapterProfile.profileId===core.SIMULATED_ADAPTER_ID ? new DeterministicSimulatedAdapter() : createPacketExecutor({ inputDirectory: config.inputDirectory, outputDirectory: directory(join(path,'execution')), selection: config.selection, termsCommitment: config.termsCommitment, resource: i.resource, domain:config.domain, intentId:i.intent });
  const context = { path, config, i, store, executor, now: () => time, advance: () => ++time, state: () => replay(store.readAll()) };
  // Present-but-incomplete evidence must be refused before any command mutates history or notes.
  context.reviewSupplement = readReviewSupplement(path);
  if (context.reviewSupplement !== null) bindLoadedSupplement(context, state, history);
  return context;
}
async function locked(caseId, operation) {
  const path = directory(join(CASES,slug(caseId))), lock = join(path,'.command.lock');
  const fd = openSync(lock,'wx',0o600);
  try { return await operation(load(caseId)); }
  finally { closeSync(fd); unlinkSync(lock); }
}
function append(context, suffix, type, data) {
  const history = context.store.readAll(); assert(history.length < MAX_EVENTS, 'CASE_EVENT_LIMIT');
  const before = replay(history).head, next = event(context.config.caseId,suffix,type,context.advance(),data);
  const head = context.store.appendAtExpectedHead(next,before);
  assert(equal(head,replay(context.store.readAll()).head), 'APPEND_READBACK_MISMATCH'); return next;
}
async function administrative(c, suffix, type, data, who, handles) {
  const history = c.store.readAll(), expectedHistoryHead = replay(history).head;
  const transition = event(c.config.caseId,suffix,type,c.advance(),data);
  const result = await produceAdministrativeEvent({ events: history, expectedDomain: c.config.domain, expectedHistoryHead, transition, runtimeSessionId: session(c.config.caseId,who).runtimeSessionId }, { signHash: handles[who].signHash });
  const head = c.store.appendAtExpectedHead(result.event,expectedHistoryHead);
  assert(equal(head,result.replayHead), 'ADMINISTRATIVE_READBACK_MISMATCH'); return result.event;
}
function inspectBoundPacket(c, state=c.state()) {
  const consumed=state.intentConsumptions.get(c.i.intent);
  if(c.config.adapterProfile.profileId===core.SIMULATED_ADAPTER_ID) return {status:consumed?'SIMULATED_ACKNOWLEDGMENT_RECORDED':'NOT_STARTED',acknowledgment:consumed?.acknowledgment??null,files:[],externalEffect:'NONE_SIMULATED'};
  const packet=c.executor.inspect();
  if(packet.status==='PACKET_VERIFIED' && consumed &&
    (consumed.transactionReference!==`0x${packet.manifestSha256}` || consumed.idempotencyKey!==packet.manifest.idempotencyKey || consumed.submissionFingerprint!==packet.manifest.submissionFingerprint || packet.manifest.intentId!==c.i.intent || !equal(consumed.acknowledgment,packet.acknowledgment))) {
    return {status:'OUTCOME_UNKNOWN',reason:'PACKET_DOES_NOT_MATCH_CANONICAL_ACKNOWLEDGMENT'};
  }
  return packet;
}
function bindLoadedSupplement(c, state, history) {
  const record = c.reviewSupplement.reference.record, packet = inspectBoundPacket(c, state);
  assert(packet.status === 'PACKET_VERIFIED' && record.caseId === c.config.caseId &&
    record.basePacketManifestSha256 === packet.manifestSha256 && state.intentConsumptions.has(c.i.intent), 'REVIEW_SUPPLEMENT_INCOMPLETE');
  const head = record.observedHistoryHead;
  assert(head.position <= state.head.position && head.canonicalTime <= state.head.canonicalTime &&
    equal(replay(history.slice(0, head.position + 1)).head, head), 'REVIEW_SUPPLEMENT_INCOMPLETE');
}

/** Explicit trusted operator input. Not an agent tool or another collection/executor request. */
export async function attachReviewSupplement(caseId, request, inputPath) {
  const selectedCase = validateReviewSnapshotId(caseId), selected = parseSupplementRequest(request);
  const sourceBytes = captureSupplementInput(inputPath, selected.expectedSha256);
  return locked(selectedCase, c => {
    assert(c.reviewSupplement === null, 'REVIEW_SUPPLEMENT_EXISTS');
    const history = c.store.readAll(), state = replay(history), packet = inspectBoundPacket(c, state);
    const duty = state.obligations.get(c.i.obligation);
    assert(packet.status === 'PACKET_VERIFIED' && state.intentConsumptions.has(c.i.intent) && duty?.status === 'OPEN', 'REVIEW_SUPPLEMENT_REVIEW_REQUIRED');
    const record = { schemaVersion: 'continuity-review-supplement/1', caseId: selectedCase,
      supplementId: selected.supplementId, fileName: selected.fileName, bytes: sourceBytes.length,
      sha256: selected.expectedSha256, sourceLabel: selected.sourceLabel, sourceScope: SUPPLEMENT_SOURCE_SCOPE,
      importedAt: new Date().toISOString(), observedHistoryHead: state.head, basePacketManifestSha256: packet.manifestSha256 };
    c.reviewSupplement = writeReviewSupplement(c.path, record, sourceBytes);
    bindLoadedSupplement(c, state, history);
    const summary = inspectLoadedCase(c);
    return { caseId: selectedCase, status: 'REVIEW_SUPPLEMENT_ATTACHED', reference: c.reviewSupplement.reference,
      reviewedCaseVersion: reviewedCaseVersion(summary), case: summary };
  });
}
function grant(c, name, grantee, actions, resources, timestamp) {
  return event(c,name,'AUTHORITY_GRANTED',timestamp,{ grant: { kind:'PERMISSION', authorityId:ids(c)[name],grantorId:ids(c).principal,granteeId:grantee,rootAuthorityId:ids(c)[name],independent:true,constraints:{actions,resources,quantitative:false,expiresAt:1000,maxDelegationDepth:0,requiredIntersectionIds:[]} } });
}
export async function createCase(caseId,inputDirectory,profileName='packet') {
  assert(profileName==='packet'||profileName==='simulated','PROFILE_MUST_BE_PACKET_OR_SIMULATED');
  const adapterProfile=core.approvedPortableAdapterProfile(profileName==='packet'?core.LOCAL_EVIDENCE_PACKET_ADAPTER_ID:core.SIMULATED_ADAPTER_ID);
  slug(caseId); const input = directory(resolve(inputDirectory)), selection = selectInput(input), terms = termsFor(caseId,selection), i = ids(caseId);
  const handles = await credentials();
  const config = { adapterProfile, schemaVersion:`continuity-local-intake-case/${VERSION}`,caseId,inputDirectory:input,selection,terms,termsCommitment:core.hashCanonical(terms),domain:domainFor(caseId) };
  const e=(suffix,type,time,data)=>event(caseId,suffix,type,time,data);
  const initial=[
    e('genesis','DEPLOYMENT_INITIALIZED',0,{domain:config.domain,adapterPolicyHash:core.PORTABLE_ADAPTER_POLICY_HASH,canonicalLineageId:`lineage:${caseId}`,versions:{eventSchemaVersion:`continuity-event/${VERSION}`,receiptSchemaVersion:`continuity-receipt/${VERSION}`,queryEnvelopeVersion:`continuity-query-envelope/${VERSION}`,authorizationProofVersion:`continuity-authorization-proof/${VERSION}`,runtimeAuthorizationVersion:`continuity-runtime-authorization/${VERSION}`,administrativeAuthorizationVersion:`continuity-administrative-authorization/${VERSION}`,signatureScheme:'eip191-personal-sign-keccak256'},policyVersion:policyFor(caseId),rootRecognitionPolicy:`declared-principal-root/${VERSION}`,globalPolicySourceId:`policy-source:${caseId}`,timeSource:'EVENT_TIMESTAMP',finality:'LOCAL_ONLY'}),
    e('principal','PRINCIPAL_CREATED',1,{principalId:i.principal}),
    e('a','AGENT_CREATED',2,{agentId:i.a,principalId:i.principal,controllerId:i.controller,initialControlEpoch:1}),
    e('b','AGENT_CREATED',3,{agentId:i.b,principalId:i.principal,controllerId:i.controller,initialControlEpoch:1}),
    e('role','ROLE_CREATED',4,{roleId:i.role,principalId:i.principal,exclusive:true}),
    e('succession','SUCCESSION_RULE_DECLARED',5,{ruleId:i.succession,principalId:i.principal,predecessorAgentId:i.a,successorAgentId:i.b,roleId:i.role,trigger:'AGENT_TERMINATED',permittedEventTypes:['AGENT_TERMINATED','ROLE_TRANSFERRED','OBLIGATION_PERFORMANCE_ASSIGNED']}),
    e('appointment','AGENT_APPOINTED',6,{agentId:i.a,roleId:i.role,roleTenureId:i['tenure-a'],tenureNumber:1,principalId:i.principal,successionRuleId:i.succession}),
    e('session-a','RUNTIME_SESSION_ADMITTED',7,{sessionId:session(caseId,'a').runtimeSessionId,agentId:i.a,controllerId:i.controller,controlEpoch:1,credentialKeyId:session(caseId,'a').credentialKeyId,credentialAddress:handles.a.address,expiresAt:10000}),
    grant(caseId,'collect-authority',i.a,['collect-evidence-packet'],[i.resource],8),
    grant(caseId,'obligate-authority',i.a,['OBLIGATE'],[i.resource],9),
    grant(caseId,'review-authority',i.b,['ASSIGN_PERFORMANCE','record-collection-disposition'],[i.obligation],10),
    grant(caseId,'progress-a-authority',i.a,['record-review-progress'],[i.obligation],11),
    grant(caseId,'progress-b-authority',i.b,['record-review-progress'],[i.obligation],12),
  ];
  replay(initial); // Validate the prepared setup before creating any case directory.
  mkdirSync(CASES,{recursive:true}); directory(CASES);
  const target=join(CASES,caseId); mkdirSync(target); mkdirSync(join(target,'execution'));
  writeNew(join(target,'case.json'),bytes(config));
  new PortableFileEventStore(join(target,'history.jsonl')).appendAll(initial);
  return inspectCase(caseId);
}
async function prepareRequest(c, handles, stale=false) {
  const intentId=stale?c.i['stale-intent']:c.i.intent, nonce=stale?c.i['stale-nonce']:c.i.nonce;
  assert(!c.state().intentDeclarations.has(intentId),'INTENT_ALREADY_DECLARED_RECONCILE_FIRST');
  const request={actorId:c.i.a,action:'collect-evidence-packet',resource:c.i.resource,claimedAt:c.now()+1,termsCommitment:c.config.termsCommitment};
  append(c,stale?'stale-declared':'declared','TRANSACTION_INTENT_DECLARED',{intentId,nonce,adapterProfile:c.config.adapterProfile,actorId:c.i.a,action:request.action,resource:request.resource,roleId:c.i.role,roleTenureId:c.i['tenure-a'],termsCommitment:request.termsCommitment});
  const events=c.store.readAll(), evaluationTime=c.advance(), binding={...session(c.config.caseId,'a'),roleId:c.i.role,roleTenureId:c.i['tenure-a'],intentId,nonce};
  const challenge=core.createPortableRuntimeAuthorizationChallenge({domain:c.config.domain,request,evaluationTime,policyVersion:policyFor(c.config.caseId),historyHead:replay(events).head,binding});
  const runtimeSignature=await handles.a.signHash(core.hashCanonical(challenge));
  return {operationVersion:core.PORTABLE_INTENT_ADMISSION_VERSION,events,expectedHistoryHead:replay(events).head,admissionEventId:`${c.config.caseId}:${stale?'stale-admission':'admission'}`,domain:c.config.domain,policyVersion:policyFor(c.config.caseId),request,evaluationTime,binding:{...binding,runtimeSignature}};
}
export async function collectCase(caseId) {
  return locked(caseId,async c=>{
    assert(c.state().agents.get(c.i.a).currentControlEpoch===1 && c.state().agents.get(c.i.a).status!=='TERMINATED','OLD_WORKER_NO_LONGER_CURRENT');
    const handles=await credentials();
    const observedExecutor={
      adapterProfile:c.executor.adapterProfile,
      submit(submission) {
        const history=c.store.readAll(), head=replay(history).head;
        assert(history.at(-1)?.id===submission.admissionEvent.id,'ADMISSION_NOT_DURABLE_AT_EXECUTOR_ENTRY');
        writeNew(join(c.path,'before-effect.json'),bytes({phase:'BEFORE_EXECUTOR_ENTRY',history,head,admissionEventId:submission.admissionEvent.id,observedAt:new Date().toISOString()}));
        return c.executor.submit(submission);
      },
      reconcile:submission=>c.executor.reconcile(submission),
    };
    const coordinator=new DurableAdmissionCoordinator(c.store,observedExecutor,{authoritativeNow:c.now});
    if(c.state().intentAdmissions.has(c.i.intent)) {
      // A repeated command only reconciles the original attempt. It cannot issue a new effect.
      const result=await coordinator.reconcile(c.i.intent);
      return {caseId,status:'RECONCILIATION_ONLY',result,case:inspectLoadedCase(c)};
    }
    const input=await prepareRequest(c,handles), prepared=coordinator.prepare(input), admitted=coordinator.admit(prepared);
    writeNew(join(c.path,'admission.json'),bytes({input,proposal:prepared.proposal,admission:admitted.status==='ADMITTED'?{status:admitted.status,result:admitted.result}:admitted}));
    assert(admitted.status==='ADMITTED',`ADMISSION_${admitted.status}`);
    c.advance();
    const invocation=await coordinator.invoke(admitted.capability);
    writeNew(join(c.path,'invocation.json'),bytes(invocation));
    if(invocation.status!=='SUBMITTED' || invocation.recorded!==true) return {caseId,status:'RECONCILIATION_REQUIRED',invocation,case:inspectLoadedCase(c)};
    const packet=inspectBoundPacket(c); assert(['PACKET_VERIFIED','SIMULATED_ACKNOWLEDGMENT_RECORDED'].includes(packet.status),'ACKNOWLEDGMENT_NOT_VERIFIED');
    const issuanceEvents=c.store.readAll();
    const receipt=await core.createPortableReceipt({events:issuanceEvents,intentId:c.i.intent,issuedAt:c.advance(),externalOutcome:c.config.adapterProfile.profileId===core.SIMULATED_ADAPTER_ID?'SIMULATED':'NOT_PROVEN'},{keyId:session(caseId,'a').credentialKeyId,signHash:handles.a.signHash});
    writeNew(join(c.path,'receipt.json'),bytes(receipt));
    const record=new DurableReceiptCoordinator(c.store).record({operationVersion:core.PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION,artifact:receipt,events:issuanceEvents,expectedHistoryHead:replay(issuanceEvents).head,expectedDomain:c.config.domain,recordEventId:`case:${caseId}:receipt`});
    assert(record.status==='ADMITTED',`RECEIPT_${record.status}`);
    append(c,'outcome-unknown','TRANSACTION_OUTCOME_RECORDED',{intentId:c.i.intent,status:'OUTCOME_UNKNOWN',attesterId:c.config.adapterProfile.profileId,evidenceReference:{kind:'EXTERNAL',evidenceType:`continuity-local-review-pending/${VERSION}`,reference:`case:${caseId}:review-pending`,attesterId:c.config.adapterProfile.profileId}});
    const consumption=c.state().intentConsumptions.get(c.i.intent);
    const obligation={obligationId:c.i.obligation,sourceIntentId:c.i.intent,causalReceiptContentHash:receipt.contentHash,durableRoleId:c.i.role,creationRoleTenureId:c.i['tenure-a'],description:'Review the collected synthetic packet; account for the unresolved investigation.',trigger:consumption.eventId,deadline:1000,status:'OPEN',beneficiaryId:c.i.principal,termsCommitment:c.config.termsCommitment,performanceAssigneeId:c.i.a,successionRuleId:c.i.succession,transitionPolicies:[{fromStatus:'OPEN',toStatus:'OUTCOME_UNKNOWN',action:'record-collection-disposition',acceptedAttesterIds:[c.config.adapterProfile.profileId],requiredAuthorityIds:[c.i['review-authority']]}]};
    await administrative(c,'obligation','OBLIGATION_CREATED',{record:obligation,actorId:c.i.a},'a',handles);
    return inspectLoadedCase(c);
  });
}
function handoverSteps(c, successorAddress) {
  return [
    {suffix:'epoch',type:'CONTROL_EPOCH_ADVANCED',data:{agentId:c.i.a,controllerId:c.i.controller,fromEpoch:1,toEpoch:2}},
    {suffix:'terminated',type:'AGENT_TERMINATED',data:{agentId:c.i.a,principalId:c.i.principal,successionRuleId:c.i.succession,roleId:c.i.role,roleTenureId:c.i['tenure-a']}},
    {suffix:'transfer',type:'ROLE_TRANSFERRED',data:{roleId:c.i.role,fromAgentId:c.i.a,fromRoleTenureId:c.i['tenure-a'],toAgentId:c.i.b,toRoleTenureId:c.i['tenure-b'],toTenureNumber:2,principalId:c.i.principal,transferKind:'SUCCESSION',successionRuleId:c.i.succession}},
    {suffix:'session-b',type:'RUNTIME_SESSION_ADMITTED',data:{sessionId:session(c.config.caseId,'b').runtimeSessionId,agentId:c.i.b,controllerId:c.i.controller,controlEpoch:1,credentialKeyId:session(c.config.caseId,'b').credentialKeyId,credentialAddress:successorAddress,expiresAt:10000}},
    {suffix:'assignment',type:'OBLIGATION_PERFORMANCE_ASSIGNED',data:{obligationId:c.i.obligation,fromAgentId:c.i.a,toAgentId:c.i.b,successionRuleId:c.i.succession,actorId:c.i.b}},
  ];
}
export async function handoverCase(caseId, options={}) {
  assert(options && typeof options==='object' && Object.keys(options).every(key=>key==='stopAfter'), 'HANDOVER_OPTIONS');
  assert(options.stopAfter===undefined || ['epoch','terminated','transfer','session-b'].includes(options.stopAfter), 'HANDOVER_STOP_STEP');
  return locked(caseId,async c=>{
    const state=c.state(); assert(state.obligations.has(c.i.obligation),'NO_CORE_DUTY_RECONCILE_INTAKE_FIRST');
    const handles=await credentials(), steps=handoverSteps(c,handles.b.address);
    let progress=handoverProgress(c.store.readAll(),caseId,steps);
    if(progress.status==='COMPLETE') return {caseId,status:'HANDOVER_ALREADY_COMPLETE',progress,case:inspectLoadedCase(c)};
    if(progress.completedSteps===0) {
      assert(state.agents.get(c.i.a).currentControlEpoch===1 && !state.agents.get(c.i.a).terminated,'HANDOVER_PREDECESSOR_STATE');
      assert(c.store.readAll().at(-1)?.id===`${caseId}:obligation`,'HANDOVER_UNEXPECTED_START');
    }
    // Only exact committed steps are skipped. Replay still validates each next transition.
    for(let index=progress.completedSteps;index<steps.length;index++) {
      const step=steps[index];
      if(step.suffix==='assignment') await administrative(c,step.suffix,step.type,step.data,'b',handles);
      else append(c,step.suffix,step.type,step.data);
      progress=handoverProgress(c.store.readAll(),caseId,steps);
      if(step.suffix===options.stopAfter) return {caseId,status:'HANDOVER_PAUSED',stopAfter:step.suffix,progress,case:inspectLoadedCase(c)};
    }
    return {caseId,status:'HANDOVER_COMPLETE',progress,case:inspectLoadedCase(c)};
  });
}
export async function attemptOldWorker(caseId) {
  return locked(caseId,async c=>{
    assert(c.state().agents.get(c.i.a).currentControlEpoch===2,'HANDOVER_REQUIRED');
    const before=inspectBoundPacket(c), handles=await credentials(), input=await prepareRequest(c,handles,true);
    const coordinator=new DurableAdmissionCoordinator(c.store,c.executor,{authoritativeNow:c.now}), prepared=coordinator.prepare(input), admission=coordinator.admit(prepared);
    assert(admission.status==='NOT_ADMITTED' && admission.result.status==='DENIED','STALE_WORKER_NOT_DENIED');
    assert(equal(before,inspectBoundPacket(c)),'STALE_REQUEST_CHANGED_PACKET');
    const observation={status:'DENIED',input,proposal:prepared.proposal,admission,executorInvoked:false,packetUnchanged:true};
    writeNew(join(c.path,'stale-request.json'),bytes(observation)); return {caseId,status:'DENIED',executorInvoked:false};
  });
}
export async function reviewCase(caseId) {
  return locked(caseId,async c=>{
    const duty=c.state().obligations.get(c.i.obligation);
    assert(duty?.performanceAssigneeId===c.i.b && duty.status==='OPEN','SUCCESSOR_OPEN_DUTY_REQUIRED');
    const packet=inspectBoundPacket(c); assert(['PACKET_VERIFIED','SIMULATED_ACKNOWLEDGMENT_RECORDED'].includes(packet.status),'ACKNOWLEDGMENT_UNAVAILABLE_REVIEW_UNRESOLVED');
    const handles=await credentials();
    await administrative(c,'review-unknown','OBLIGATION_STATUS_RECORDED',{obligationId:c.i.obligation,fromStatus:'OPEN',toStatus:'OUTCOME_UNKNOWN',actorId:c.i.b,action:'record-collection-disposition',attesterId:c.config.adapterProfile.profileId,evidenceReference:{kind:'EXTERNAL',evidenceType:`continuity-reference-review-disposition/${VERSION}`,reference:c.state().intentConsumptions.get(c.i.intent).transactionReference,attesterId:c.config.adapterProfile.profileId}},'b',handles);
    return inspectLoadedCase(c);
  });
}
// Notes are signed application records. They do not create a Core intent,
// consume authority, discharge a duty or serve as permission for an executor.
export function progressAuthorization(caseId, config, history, actorId) {
  const state=replay(history), i=ids(caseId), who=actorId===i.a?'a':actorId===i.b?'b':undefined;
  assert(who,'REVIEW_ACTOR_UNKNOWN');
  const agent=state.agents.get(actorId), runtime=state.runtimeSessions.get(session(caseId,who).runtimeSessionId);
  assert(agent && !agent.terminated,'REVIEW_AGENT_INACTIVE');
  assert(runtime && runtime.agentId===actorId && runtime.controlEpoch===agent.currentControlEpoch && runtime.controlEpoch===1,'REVIEW_SESSION_FENCED');
  assert(runtime.expiresAt===undefined || state.head.canonicalTime<runtime.expiresAt,'REVIEW_SESSION_EXPIRED');
  const tenureId=i[`tenure-${who}`], tenure=state.tenures.get(tenureId), duty=state.obligations.get(i.obligation);
  assert(tenure && !tenure.closed && state.roles.get(i.role)?.currentTenureId===tenureId,'REVIEW_ROLE_NOT_CURRENT');
  assert(duty && duty.performanceAssigneeId===actorId && ['OPEN','OUTCOME_UNKNOWN'].includes(duty.status),'REVIEW_ASSIGNMENT_REQUIRED');
  const authorization=core.authorizePortable({operationVersion:core.PORTABLE_AUTHORIZATION_VERSION,events:history,expectedHistoryHead:state.head,domain:config.domain,policyVersion:policyFor(caseId),rootRecognitionPolicy:core.PORTABLE_ROOT_RECOGNITION_POLICY,request:{actorId,action:'record-review-progress',resource:i.obligation,claimedAt:state.head.canonicalTime},evaluationTime:state.head.canonicalTime,authoritative:true,consequential:false});
  assert(authorization.decision==='ALLOW' && authorization.scopeAssurance==='REPLAY_VERIFIED','REVIEW_AUTHORITY_REQUIRED');
  assert(authorization.proof.controllingAuthorityIds.includes(i[`progress-${who}-authority`]),'REVIEW_INDEPENDENT_GRANT_REQUIRED');
  return {who,state,runtime,tenureId,authorization};
}
export function verifyProgressRecords(caseId, config, history, packet, entries) {
  const summary=summarizeProgress(config.selection,entries);
  let previous=null, previousPosition=-1;
  for(const entry of entries) {
    validateProgressEntry(entry);
    assert(entry.caseId===caseId && packet.status==='PACKET_VERIFIED' && entry.packetManifestSha256===packet.manifestSha256,'REVIEW_PACKET_BINDING');
    assert(entry.previousRecordHash===previous,'REVIEW_RECORD_CHAIN');
    assert(entry.historyHead.position>=previousPosition && entry.historyHead.position<history.length,'REVIEW_HISTORY_ORDER');
    const prefix=history.slice(0,entry.historyHead.position+1), check=progressAuthorization(caseId,config,prefix,entry.actorId);
    assert(equal(check.state.head,entry.historyHead),'REVIEW_HISTORY_BINDING');
    assert(entry.runtimeSessionId===check.runtime.id && entry.controlEpoch===check.runtime.controlEpoch && entry.roleTenureId===check.tenureId,'REVIEW_ACTOR_BINDING');
    assert(entry.authorizationProofHash===core.hashCanonical(check.authorization.proof),'REVIEW_AUTHORIZATION_BINDING');
    const {signature,...unsigned}=entry;
    assert(recoverPortableContentHashSigner(core.hashCanonical(unsigned),signature)===check.runtime.credentialAddressKey,'REVIEW_SIGNATURE_INVALID');
    previous=core.hashCanonical(entry); previousPosition=entry.historyHead.position;
  }
  return {...summary,verification:entries.length?'HISTORICAL_SIGNATURE_AND_SCOPE_VERIFIED':'NO_RECORDS',lastRecordHash:previous};
}
function progressRecords(c, state=c.state(), packet=inspectBoundPacket(c,state)) {
  const path=join(c.path,'review-progress');
  if(!existsSync(path)) return {entries:[],summary:verifyProgressRecords(c.config.caseId,c.config,c.store.readAll(),packet,[])};
  directory(path); const names=readdirSync(path).sort();
  assert(names.length<=32 && names.every((name,index)=>name===`${String(index+1).padStart(3,'0')}.json`),'REVIEW_RECORD_MEMBERSHIP');
  const entries=names.map(name=>readJson(join(path,name),32768));
  return {entries,summary:verifyProgressRecords(c.config.caseId,c.config,c.store.readAll(),packet,entries)};
}
export async function recordReviewProgress(caseId, who, fileName, noteId, note) {
  assert(who==='a'||who==='b','REVIEW_ACTOR_UNKNOWN');
  return locked(caseId,c=>recordLoadedProgress(c,who,fileName,noteId,note));
}
export async function recordReviewedProgress(caseId, who, fileName, noteId, note, expectedCaseVersion) {
  const capturedVersion=validateExpectedCaseVersion(expectedCaseVersion);
  assert(who==='a'||who==='b','REVIEW_ACTOR_UNKNOWN');
  return locked(caseId,c=>recordLoadedProgress(c,who,fileName,noteId,note,capturedVersion));
}
export async function recordContextBoundProgress(caseId, who, input) {
  // Capture primitive own-data input before queueing or awaiting anything.
  const captured = captureContextBoundInput(input);
  assert(who === 'a' || who === 'b', 'REVIEW_ACTOR_UNKNOWN');
  return locked(caseId, async c => {
    const history = c.store.readAll(), check = progressAuthorization(caseId, c.config, history, c.i[who]);
    const packet = inspectBoundPacket(c, check.state);
    assert(packet.status === 'PACKET_VERIFIED', 'REVIEW_PACKET_UNAVAILABLE');
    const retained = progressRecords(c, check.state, packet);
    assert(reviewedCaseVersion(inspectLoadedCase(c)) === captured.expectedCaseVersion, 'REVIEW_CONTEXT_CHANGED');
    const bundle = loadReviewSnapshotBundle({ caseId, snapshotId: captured.snapshotId,
      expectedManifestSha256: captured.snapshotManifestSha256 });
    const binding = verifyContextBinding({ caseId, actorId: c.i[who], expectedCaseVersion: captured.expectedCaseVersion,
      snapshotManifestSha256: captured.snapshotManifestSha256, proposalUtf8: captured.proposalUtf8,
      bundle, history, priorEntries: retained.entries });
    const { noteId, fileName, note } = binding.action;
    assert(!retained.entries.some(entry => entry.noteId === noteId), 'REVIEW_NOTE_ID_CONFLICT');
    const file = c.config.selection.find(item => item.name === fileName);
    assert(file, 'REVIEW_FILE_NOT_SELECTED');
    const unsigned = { schemaVersion: 'continuity-review-progress/2', caseId, sequence: retained.entries.length + 1,
      noteId, actorId: c.i[who], runtimeSessionId: check.runtime.id, controlEpoch: check.runtime.controlEpoch,
      roleTenureId: check.tenureId, historyHead: check.state.head, packetManifestSha256: packet.manifestSha256,
      fileName, fileSha256: file.sha256, note, status: 'REVIEWED', previousRecordHash: retained.summary.lastRecordHash,
      authorizationProofHash: core.hashCanonical(check.authorization.proof), reviewedContext: binding.reviewedContext };
    const placeholder = { ...unsigned, signature: `0x${'0'.repeat(130)}` };
    validateProgressEntry(placeholder);
    assert(bytes(placeholder).length <= 32768, 'REVIEW_RECORD_LIMIT');
    const handles = await credentials();
    const entry = { ...unsigned, signature: await handles[who].signHash(core.hashCanonical(unsigned)) };
    verifyProgressRecords(caseId, c.config, history, packet, [...retained.entries, entry]);
    // Reload after the signer yield: the old loaded context caches its supplement.
    // A fresh load covers note-only and supplement-only changes as well as Core.
    const fresh = load(caseId);
    assert(reviewedCaseVersion(inspectLoadedCase(fresh)) === captured.expectedCaseVersion, 'REVIEW_CONTEXT_CHANGED');
    const raw = bytes(entry); assert(raw.length <= 32768, 'REVIEW_RECORD_LIMIT');
    const target = join(c.path, 'review-progress'); if (!existsSync(target)) mkdirSync(target);
    writeNew(join(target, `${String(entry.sequence).padStart(3, '0')}.json`), raw);
    const recordHash = core.hashCanonical(entry);
    return { caseId, status: 'REVIEW_RECORDED', noteId, review: progressRecords(fresh).summary,
      contextCheck: { schemaVersion: 'continuity-reviewed-context-check/1', expectedCaseVersion: captured.expectedCaseVersion, matched: true, scope: 'APPLICATION_LOCK' },
      contextBinding: { schemaVersion: 'continuity-context-bound-note-result/1', expectedCaseVersion: captured.expectedCaseVersion,
        snapshotManifestSha256: binding.reviewedContext.snapshotManifestSha256,
        proposalSha256: binding.reviewedContext.proposalSha256, recordHash, scope: 'APPLICATION_LOCK' } };
  });
}
async function recordLoadedProgress(c, who, fileName, noteId, note, expectedCaseVersion) {
    const caseId=c.config.caseId;
    const history=c.store.readAll(), check=progressAuthorization(caseId,c.config,history,c.i[who]);
    const packet=inspectBoundPacket(c,check.state); assert(packet.status==='PACKET_VERIFIED','REVIEW_PACKET_UNAVAILABLE');
    const retained=progressRecords(c,check.state,packet), existing=retained.entries.find(entry=>entry.noteId===noteId);
    let context={};
    if(expectedCaseVersion!==undefined) {
      assert(reviewedCaseVersion(inspectLoadedCase(c))===expectedCaseVersion,'REVIEW_CONTEXT_CHANGED');
      context={contextCheck:{schemaVersion:'continuity-reviewed-context-check/1',expectedCaseVersion,matched:true,scope:'APPLICATION_LOCK'}};
    }
    if(existing) {
      assert(existing.actorId===c.i[who] && existing.fileName===fileName && existing.note===note,'REVIEW_NOTE_ID_CONFLICT');
      return {caseId,status:'REVIEW_ALREADY_RECORDED',noteId,review:retained.summary,...context};
    }
    const file=c.config.selection.find(item=>item.name===fileName); assert(file,'REVIEW_FILE_NOT_SELECTED');
    const unsigned={schemaVersion:'continuity-review-progress/1',caseId,sequence:retained.entries.length+1,noteId,actorId:c.i[who],runtimeSessionId:check.runtime.id,controlEpoch:check.runtime.controlEpoch,roleTenureId:check.tenureId,historyHead:check.state.head,packetManifestSha256:packet.manifestSha256,fileName,fileSha256:file.sha256,note,status:'REVIEWED',previousRecordHash:retained.summary.lastRecordHash,authorizationProofHash:core.hashCanonical(check.authorization.proof)};
    // Shape-check before signing; the placeholder is never persisted.
    validateProgressEntry({...unsigned,signature:`0x${'0'.repeat(130)}`});
    const handles=await credentials(), entry={...unsigned,signature:await handles[who].signHash(core.hashCanonical(unsigned))};
    verifyProgressRecords(caseId,c.config,history,packet,[...retained.entries,entry]);
    assert(equal(c.state().head,check.state.head),'REVIEW_HEAD_CHANGED');
    const target=join(c.path,'review-progress'); if(!existsSync(target)) mkdirSync(target);
    writeNew(join(target,`${String(entry.sequence).padStart(3,'0')}.json`),bytes(entry));
    return {caseId,status:'REVIEW_RECORDED',noteId,review:progressRecords(c).summary,...context};
}
export async function inspectCase(caseId) { return locked(caseId, c=>inspectLoadedCase(c)); }
function inspectLoadedCase(c) {
  const caseId=c.config.caseId;
  const state=c.state(), duty=state.obligations.get(c.i.obligation), packet=inspectBoundPacket(c,state);
  const admission=state.intentAdmissions.get(c.i.intent), consumed=state.intentConsumptions.get(c.i.intent);
  const progress = progressRecords(c,state,packet);
  const summary = {schemaVersion:`continuity-local-intake-summary/${VERSION}`,caseId,domain:c.config.domain,adapterProfile:c.config.adapterProfile,head:state.head,review:progress.summary,stage:duty?'REVIEW_DUTY':admission?'RECONCILIATION_REQUIRED':'AWAITING_INTAKE',packet,admission:admission?{intentId:c.i.intent,consumed:Boolean(consumed)}:null,duty:duty?{bearer:duty.record.durableRoleId,performer:duty.performanceAssigneeId,status:duty.status,description:duty.record.description}:null,successorGrant:state.authorities.get(c.i['review-authority']),predecessorEpoch:state.agents.get(c.i.a).currentControlEpoch,scope:{data:'SYNTHETIC',executorKind:c.config.adapterProfile.profileId===core.SIMULATED_ADAPTER_ID?'SIMULATOR':'LOCAL_PACKET_WRITE',execution:packet.status==='PACKET_VERIFIED'?'RETAINED_PACKET_VERIFIED':packet.status==='SIMULATED_ACKNOWLEDGMENT_RECORDED'?'SIMULATED':admission?'UNCERTAIN':'NOT_STARTED',engine:'COMMON_CORE_0.2',finality:'LOCAL_ONLY',externalOutcome:c.config.adapterProfile.profileId===core.SIMULATED_ADAPTER_ID?'SIMULATED':'NOT_PROVEN',host:'TRUSTED_COOPERATIVE_OPERATOR',signing:'PUBLIC_DEVELOPMENT_KEYS'},limitations:['A packet and receipt do not prove incident resolution.','Historical evidence does not authorize a fresh action.','No hostile-host isolation, production custody or exactly-once crash guarantee.']};
  if (c.reviewSupplement !== null) {
    summary.schemaVersion = SUPPLEMENT_SUMMARY_SCHEMA;
    summary.reviewSupplement = c.reviewSupplement.reference;
  }
  if (progress.entries.some(entry => entry.schemaVersion === 'continuity-review-progress/2')) summary.schemaVersion = SIGNED_CONTEXT_SUMMARY_SCHEMA;
  return summary;
}
export async function exportCase(caseId) {
 return locked(caseId, c => {
  const target=join(c.path,'export');
  assert(!existsSync(target),'EXPORT_ALREADY_EXISTS');
  const prepared=prepareExport(c);
  mkdirSync(target);
  writeExport(target,prepared);
  return {caseId,status:'EXPORTED',directory:target,files:prepared.manifest.files.length,head:prepared.manifest.head};
 });
}

export async function captureReviewSnapshot(caseId, snapshotId) {
 const selectedId=validateReviewSnapshotId(snapshotId);
 return locked(caseId, c => {
  const target=reviewSnapshotDirectory(c.path,selectedId), parent=dirname(target);
  // lstat sees dangling symlinks too; directory rejects aliases in any ancestor.
  if(lstatSync(parent,{throwIfNoEntry:false})) directory(parent);
  assert(!lstatSync(target,{throwIfNoEntry:false}),'REVIEW_SNAPSHOT_EXISTS');
  const prepared=prepareExport(c), version=reviewedCaseVersion(prepared.summary);
  if(!lstatSync(parent,{throwIfNoEntry:false})) mkdirSync(parent);
  directory(parent);
  try { mkdirSync(target); }
  catch(error) {
    if(error.code==='EEXIST') throw new Error('REVIEW_SNAPSHOT_EXISTS');
    throw error;
  }
  directory(target);
  // A failed write leaves this name reserved. No partial capture is overwritten.
  writeExport(target,prepared);
  return {caseId,status:'SNAPSHOT_CAPTURED',snapshotId:selectedId,directory:target,files:prepared.manifest.files.length,head:prepared.manifest.head,manifestSha256:sha(prepared.manifestBytes),reviewedCaseVersion:version};
 });
}

// These helpers run only inside the caller's existing command lock.
function prepareExport(c) {
  const caseId=c.config.caseId, history=c.store.readAll(), state=replay(history);
  const summary=inspectLoadedCase(c), queryBase={operationVersion:core.PORTABLE_QUERY_VERSION,evaluationEvents:history,observedEvents:history,authorizationDomain:c.config.domain,evaluationTime:c.now()};
  const request={actorId:c.i.b,action:'record-collection-disposition',resource:c.i.obligation,claimedAt:c.now()};
  const queries={successor:core.whyPortable({...queryBase,request,disclosure:core.portablePublicQueryDisclosure('WHY')}),survives:core.survivesPortable({operationVersion:core.PORTABLE_QUERY_VERSION,observedEvents:history,targetAgentId:c.i.a,evaluationTime:c.now(),disclosure:core.portablePublicQueryDisclosure('SURVIVES')})};
  if(existsSync(join(c.path,'admission.json'))) {
    const source=readJson(join(c.path,'admission.json')).input;
    const sourceQuery={operationVersion:core.PORTABLE_QUERY_VERSION,evaluationEvents:source.events,observedEvents:history,authorizationDomain:source.domain,evaluationTime:source.evaluationTime,request:source.request,consequentialBinding:source.binding};
    queries.sourceAtEvaluation=core.whyPortable({...sourceQuery,observedEvents:source.events,disclosure:core.portablePublicQueryDisclosure('WHY')});
    queries.sourceHistorical=core.whyPortable({...sourceQuery,disclosure:core.portablePublicQueryDisclosure('WHY')});
    queries.responsible=core.responsiblePortable({...sourceQuery,disclosure:core.portablePublicQueryDisclosure('RESPONSIBLE')});
  }
  const payload={'summary.json':bytes(summary),'history.json':bytes(history),'graph.json':bytes(graph(state)),'queries.json':bytes(queries),'terms.json':bytes(c.config.terms),'review-progress.json':bytes(progressRecords(c,state).entries)};
  const receiptPath=join(c.path,'receipt.json');
  if(existsSync(receiptPath)) {
    const receipt=readJson(receiptPath), recordIndex=history.findIndex(item=>item.type==='RECEIPT_RECORDED');
    payload['receipt.json']=readFileSync(receiptPath);
    payload['receipt-verification.json']=bytes(core.verifyPortableReceipt({operationVersion:core.PORTABLE_RECEIPT_VERIFICATION_VERSION,artifact:receipt,issuanceEvents:recordIndex<0?history:history.slice(0,recordIndex+1),observedEvents:history,expectedDomain:c.config.domain,verifierTime:c.now()}));
  }
  for(const name of ['admission.json','invocation.json','before-effect.json','stale-request.json']) if(existsSync(join(c.path,name))) payload[name]=readFileSync(join(c.path,name));
  if(summary.packet.status==='PACKET_VERIFIED') {
    for(const name of ['attempt.json','ack.json']) payload[name]=readFileSync(join(c.path,'execution',name));
    payload['packet-manifest.json']=readFileSync(join(c.path,'execution','packet','manifest.json'));
    for(const file of summary.packet.files) payload[`packet-file-${file.name}`]=readFileSync(join(c.path,'execution','packet','files',file.name));
  }
  if (c.reviewSupplement !== null) {
    payload['review-supplement.log'] = c.reviewSupplement.sourceBytes;
    payload['review-supplement-manifest.json'] = c.reviewSupplement.manifestBytes;
  }
  const exportSchema = summary.schemaVersion === SIGNED_CONTEXT_SUMMARY_SCHEMA ? SIGNED_CONTEXT_EXPORT_SCHEMA : c.reviewSupplement === null ? `continuity-local-intake-export/${VERSION}` : SUPPLEMENT_EXPORT_SCHEMA;
  const manifest={schemaVersion:exportSchema,caseId,domain:c.config.domain,head:state.head,disclosure:'SYNTHETIC_LOCAL_CASE',files:Object.entries(payload).map(([name,data])=>({name,bytes:data.length,sha256:sha(data)}))};
  return {summary,payload,manifest,manifestBytes:Buffer.from(JSON.stringify(manifest,null,2)+'\n')};
}
function writeExport(target, prepared) {
  for(const [name,data] of Object.entries(prepared.payload)) writeNew(join(target,name),data);
  writeNew(join(target,'MANIFEST.json'),prepared.manifestBytes);
}
