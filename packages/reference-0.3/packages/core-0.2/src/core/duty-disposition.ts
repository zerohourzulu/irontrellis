/** Fixed D1 finding semantics. Internal reducers use complete prior replay state. */
import { canonicalEncode, hashCanonical, immutableProtocolValue, type ContentHash } from './canonical.ts';
import { DUTY_POLICY_VERSION, DUTY_POLICY_RULES_HASH, type PortableDutyDocumentDigest, type PortableDutyPolicyActivation } from './duty-policy.ts';
import { createPortableAdministrativePolicyProof, recoverPortableContentHashSigner, type PortableAuthorityReplayState, type PortableAdministrativeRequirements, type PortableAuthorizationProof } from './portable-authority-engine.ts';
import { isPortableReplayState, type PortableReplayState, type PortableAuthorizationDomain, type PortableHistoryHead, type PortableAttemptDutyState } from './portable-replay.ts';
import type { AcceptedCanonicalEventShape } from './event-schema.ts';
export const DUTY_FINDING_VERSION = 'continuity-duty-finding/1' as const;
export const DUTY_CRITERIA = ['SOURCE_REVIEWED','HISTORY_REVIEWED','FINDING_RECORDED','CONTROL_REVIEWED'] as const;
export type PortableDutyChecklist = Readonly<Record<typeof DUTY_CRITERIA[number], Readonly<{state:'SATISFIED'|'UNAVAILABLE'|'UNRESOLVED';reason:string}>>>;
export type PortableDutyDispositionOperation = Readonly<{ disposition:'COMPLETED_UNDER_POLICY'|'ESCALATED'; checklist:PortableDutyChecklist; reportDigest:PortableDutyDocumentDigest; nextStep:string|null }>;
export type PortableDutyContestOperation = Readonly<{targetDispositionEventId:string;reason:string;reportDigest:PortableDutyDocumentDigest}>;
export type PortableDutyOperation = PortableDutyDispositionOperation | PortableDutyContestOperation;
export type PortableDutyTransitionType = 'ATTEMPT_DUTY_DISPOSITION_RECORDED'|'ATTEMPT_DUTY_CONTEST_RECORDED';
export type PortableDutyFindingChallenge = Readonly<{
 version:typeof DUTY_FINDING_VERSION; purpose:'DISPOSITION'|'CONTEST'; domain:PortableAuthorizationDomain;
 rulesHash:typeof DUTY_POLICY_RULES_HASH; descriptorHash:ContentHash; activationEventId:string; dutyId:string; sourceAdmissionEventId:string;
 transitionEventId:string; transitionEventType:PortableDutyTransitionType; evaluationTime:number; priorHead:PortableHistoryHead;
 latestAssignmentEventId:string; previousDispositionEventId:string|null; evidenceIndexHash:ContentHash; operation:PortableDutyOperation;
 attesterId:string; runtimeSessionId:string; credentialKeyId:string; controlEpoch:number; roleId:string; roleTenureId:string;
 attestationAuthorityId:string; dispositionAuthorityId:string; authorityProofHash:ContentHash;
}>;
export type PortableDutyFinding = Readonly<{challenge:PortableDutyFindingChallenge;runtimeSignature:`0x${string}`} >;
export type PortableDutyDispositionData = Readonly<{version:typeof DUTY_POLICY_VERSION;rulesHash:typeof DUTY_POLICY_RULES_HASH;dutyId:string;actorId:string;dispositionAuthorityId:string;finding:PortableDutyFinding}>;
export type PortableDutyFindingRequest = Readonly<{dutyId:string;actorId:string;attesterId:string;attesterRuntimeSessionId:string;attestationAuthorityId:string;dispositionAuthorityId:string;operation:PortableDutyOperation}>;
export type DutyDispositionState = PortableAuthorityReplayState & Readonly<{attemptDuties:ReadonlyMap<string,PortableAttemptDutyState>;attemptDutyPolicies:ReadonlyMap<string,PortableDutyPolicyActivation>}>;
export type DutyUnsignedTransition = Readonly<{id:string;type:PortableDutyTransitionType;timestamp:number;data:PortableDutyDispositionData}>;
const same = (a:unknown,b:unknown) => canonicalEncode(a) === canonicalEncode(b);
export function portableDutyRecords(state:DutyDispositionState,dutyId:string,type:PortableDutyTransitionType) {
 return state.events.filter(e => e.type===type && e.data.dutyId===dutyId);
}
export function derivePortableDutyEvidenceIndex(state:DutyDispositionState,dutyId:string) {
 const duty=state.attemptDuties.get(dutyId),policy=state.attemptDutyPolicies.get(dutyId);
 if(!duty||!policy) throw new TypeError('Duty policy unavailable.');
 const sourceTypes=['TRANSACTION_INTENT_DECLARED','TRANSACTION_INTENT_ADMITTED','TRANSACTION_INTENT_CONSUMED','TRANSACTION_OUTCOME_RECORDED','RECEIPT_RECORDED','OUTCOME_OBSERVATION_RECORDED'];
 const dutyTypes=['ATTEMPT_DUTY_ASSIGNED','ATTEMPT_DUTY_REVIEW_CLOSED','ATTEMPT_DUTY_CONTEST_RECORDED'];
 const records=state.events.filter(e=>e.id===duty.creationEventId||e.id===policy.eventId||
   (sourceTypes.includes(e.type)&&e.data.intentId===duty.record.sourceIntentId)||
   (dutyTypes.includes(e.type)&&e.data.dutyId===dutyId)).map(e=>({eventId:e.id,eventType:e.type,contentHash:hashCanonical(e)}));
 const counts:Record<string,number>={}; for(const r of records) counts[r.eventType]=(counts[r.eventType]??0)+1;
 return immutableProtocolValue({version:'continuity-duty-evidence-index/1',domain:state.genesis.domain,dutyId,
   dutyCreationEventId:duty.creationEventId,activationEventId:policy.eventId,sourceAdmissionEventId:duty.record.sourceAdmissionEventId,
   latestAssignmentEventId:duty.assignments.at(-1)?.eventId??duty.creationEventId,recordCount:records.length,counts,records});
}
export function portableDutyRequirements(state:DutyDispositionState,dutyId:string,actorId:string,authorityId:string,attestation:boolean,time:number):PortableAdministrativeRequirements|undefined {
 const policy=state.attemptDutyPolicies.get(dutyId), duty=state.attemptDuties.get(dutyId); if(!policy||!duty) return;
 const role=state.roles.get(attestation?policy.descriptor.acceptedAttesterRoleId:duty.record.durableRoleId);
 const tenure=role?.currentTenureId===undefined?undefined:state.tenures.get(role.currentTenureId);
 const actor=state.agents.get(actorId);
 if(!role||role.principalId!==policy.descriptor.principalId||!tenure||tenure.closed||tenure.agentId!==actorId||!actor||actor.terminated||
   (!attestation&&duty.currentAssigneeId!==actorId)) return;
 return {request:{actorId,action:attestation?'ATTEST_DUTY_FINDING':'RECORD_DUTY_DISPOSITION',resource:`duty:${policy.descriptorHash}`,claimedAt:time},
   requiredPrincipalId:role.principalId,requiredAuthorityIds:[authorityId],roleId:role.id,roleTenureId:tenure.id};
}
function sessionEligible(state:DutyDispositionState,requirements:PortableAdministrativeRequirements,sessionId:string,time:number) {
 const session=state.runtimeSessions.get(sessionId),actor=state.agents.get(requirements.request.actorId);
 return session&&actor&&!actor.terminated&&session.agentId===actor.id&&session.controlEpoch===actor.currentControlEpoch&&
   (session.expiresAt===undefined||time<session.expiresAt)?session:undefined;
}
function operationEligible(state:DutyDispositionState,dutyId:string,type:PortableDutyTransitionType,operation:PortableDutyOperation) {
 const policy=state.attemptDutyPolicies.get(dutyId);if(!policy)return false;
 if(type==='ATTEMPT_DUTY_DISPOSITION_RECORDED') {
  if(policy.dispositionCount>=4||!('disposition'in operation))return false;
  const all=DUTY_CRITERIA.every(k=>operation.checklist[k].state==='SATISFIED');
  return operation.disposition==='COMPLETED_UNDER_POLICY'?all&&policy.contestCount===0&&operation.nextStep===null:
   (!all||policy.contestCount>0)&&typeof operation.nextStep==='string'&&operation.nextStep.trim().length>0;
 }
 return policy.contestCount<2&&'targetDispositionEventId'in operation&&portableDutyRecords(state,dutyId,'ATTEMPT_DUTY_DISPOSITION_RECORDED').some(e=>e.id===operation.targetDispositionEventId);
}
/** Internal: request has already undergone the closed schema capture. */
export function derivePortableDutyFinding(state:DutyDispositionState,event:Readonly<{id:string;type:PortableDutyTransitionType;timestamp:number;data:PortableDutyFindingRequest}>) {
 const d=event.data,policy=state.attemptDutyPolicies.get(d.dutyId);
 if(!policy||event.timestamp<state.head.canonicalTime||!operationEligible(state,d.dutyId,event.type,d.operation))throw new TypeError('Invalid duty operation.');
 const req=portableDutyRequirements(state,d.dutyId,d.attesterId,d.attestationAuthorityId,true,event.timestamp);
 const outer=portableDutyRequirements(state,d.dutyId,d.actorId,d.dispositionAuthorityId,false,event.timestamp);
 if(!req||!outer||!createPortableAdministrativePolicyProof(state,outer,event.timestamp))throw new TypeError('Duty authority unavailable.');
 const session=sessionEligible(state,req,d.attesterRuntimeSessionId,event.timestamp);
 const proof=createPortableAdministrativePolicyProof(state,req,event.timestamp);
 if(!session||!proof)throw new TypeError('Finding authority unavailable.');
 const index=derivePortableDutyEvidenceIndex(state,d.dutyId);
 return immutableProtocolValue({version:DUTY_FINDING_VERSION,purpose:event.type==='ATTEMPT_DUTY_DISPOSITION_RECORDED'?'DISPOSITION':'CONTEST',
  domain:state.genesis.domain,rulesHash:DUTY_POLICY_RULES_HASH,descriptorHash:policy.descriptorHash,activationEventId:policy.eventId,dutyId:d.dutyId,
  sourceAdmissionEventId:policy.descriptor.sourceAdmissionEventId,transitionEventId:event.id,transitionEventType:event.type,evaluationTime:event.timestamp,
  priorHead:state.head,latestAssignmentEventId:index.latestAssignmentEventId,previousDispositionEventId:portableDutyRecords(state,d.dutyId,'ATTEMPT_DUTY_DISPOSITION_RECORDED').at(-1)?.id??null,
  evidenceIndexHash:hashCanonical(index),operation:d.operation,attesterId:d.attesterId,runtimeSessionId:session.id,credentialKeyId:session.credentialKeyId,
  controlEpoch:session.controlEpoch,roleId:req.roleId,roleTenureId:req.roleTenureId,attestationAuthorityId:d.attestationAuthorityId,
  dispositionAuthorityId:d.dispositionAuthorityId,authorityProofHash:hashCanonical(proof)} as const);
}
export function validatePortableDutyFinding(state:DutyDispositionState,event:DutyUnsignedTransition):boolean {
 try {
  const d=event.data,c=d.finding.challenge;
  if(d.version!==DUTY_POLICY_VERSION||d.rulesHash!==DUTY_POLICY_RULES_HASH)return false;
  const expected=derivePortableDutyFinding(state,{id:event.id,type:event.type,timestamp:event.timestamp,data:{dutyId:d.dutyId,actorId:d.actorId,
   attesterId:c.attesterId,attesterRuntimeSessionId:c.runtimeSessionId,attestationAuthorityId:c.attestationAuthorityId,dispositionAuthorityId:d.dispositionAuthorityId,operation:c.operation}});
  const session=state.runtimeSessions.get(c.runtimeSessionId);
  return same(c,expected)&&session!==undefined&&recoverPortableContentHashSigner(hashCanonical(c),d.finding.runtimeSignature)===session.credentialAddressKey;
 }catch{return false;}
}
// Exact selected grant routes are stable identities within the unchanged head.
// Time-dependent request/evaluation fields are intentionally not compared.
function authorityRoute(proof:PortableAuthorizationProof) {
 return {recognizedRoot:proof.recognizedRoot,permissionPath:proof.permissionPath.map(grant=>grant.authorityId),
  intersections:proof.intersections.map(part=>({requiredAuthorityId:part.requiredAuthorityId,requiredByAuthorityIds:part.requiredByAuthorityIds,
   recognizedRoot:part.recognizedRoot,path:part.path.map(grant=>grant.authorityId)}))};
}
/** Original signed time is checked first; new eligibility never substitutes into the signed challenge. */
export function validatePortableDutyFreshEligibility(state:PortableReplayState,event:DutyUnsignedTransition,outerRuntimeSessionId:string,freshTime:number):boolean {
 if(!isPortableReplayState(state)||!Number.isSafeInteger(freshTime)||Object.is(freshTime,-0)||freshTime<event.timestamp||freshTime<state.head.canonicalTime||!validatePortableDutyFinding(state,event))return false;
 const d=event.data,c=d.finding.challenge;
 const att=portableDutyRequirements(state,d.dutyId,c.attesterId,c.attestationAuthorityId,true,freshTime);
 const outer=portableDutyRequirements(state,d.dutyId,d.actorId,d.dispositionAuthorityId,false,freshTime);
 if(!att||!outer||!sessionEligible(state,att,c.runtimeSessionId,freshTime)||!sessionEligible(state,outer,outerRuntimeSessionId,freshTime))return false;
 const originalAtt=portableDutyRequirements(state,d.dutyId,c.attesterId,c.attestationAuthorityId,true,event.timestamp);
 const originalOuter=portableDutyRequirements(state,d.dutyId,d.actorId,d.dispositionAuthorityId,false,event.timestamp);
 if(!originalAtt||!originalOuter)return false;
 const oldAttProof=createPortableAdministrativePolicyProof(state,originalAtt,event.timestamp),oldOuterProof=createPortableAdministrativePolicyProof(state,originalOuter,event.timestamp);
 const freshAttProof=createPortableAdministrativePolicyProof(state,att,freshTime),freshOuterProof=createPortableAdministrativePolicyProof(state,outer,freshTime);
 return !!oldAttProof&&!!oldOuterProof&&!!freshAttProof&&!!freshOuterProof&&
  same(authorityRoute(oldAttProof),authorityRoute(freshAttProof))&&same(authorityRoute(oldOuterProof),authorityRoute(freshOuterProof));
}
export function portableDutyDispositionProjection(state:DutyDispositionState,dutyId:string) {
 const last=portableDutyRecords(state,dutyId,'ATTEMPT_DUTY_DISPOSITION_RECORDED').at(-1);
 if(!last)return {dutyDisposition:state.attemptDutyPolicies.get(dutyId)!.contestCount?'CONTESTED':'OPEN',outstanding:true,lastRecordedDisposition:null,reasons:['NO_DISPOSITION_RECORDED']} as const;
 const c=(last.data.finding as PortableDutyFinding).challenge,operation=c.operation as PortableDutyDispositionOperation;
 const contested=state.attemptDutyPolicies.get(dutyId)!.contestCount>0;
 const stale=c.evidenceIndexHash!==hashCanonical(derivePortableDutyEvidenceIndex(state,dutyId));
 const disposition=contested?'CONTESTED':stale?'NEEDS_REVIEW':operation.disposition;
 return {dutyDisposition:disposition,outstanding:disposition!=='COMPLETED_UNDER_POLICY',lastRecordedDisposition:{eventId:last.id,eventPosition:state.events.indexOf(last),timestamp:last.timestamp,disposition:operation.disposition,findingHash:hashCanonical(last.data.finding),evidenceIndexHash:c.evidenceIndexHash,reportDigest:operation.reportDigest},
  reasons:[contested?'ACCEPTED_CONTEST':stale?'RELEVANT_EVIDENCE_CHANGED':operation.disposition==='ESCALATED'?'ATTENTION_REQUESTED':'ALL_LOCAL_CRITERIA_SATISFIED']} as const;
}
