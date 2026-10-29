// Trusted example host: source/report files and signing callbacks are never worker input.
import assert from 'node:assert/strict';
import {openSync,closeSync,fstatSync,readFileSync,writeFileSync,constants} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {openLocalOwner} from '../../packages/core-0.3/src/local-owner.ts';
import {openLocalDutyPolicy} from '../../packages/core-0.3/src/duties.ts';
import {openConfiguredEventStore} from '../../packages/core-0.3/src/configured-store.ts';
import {observeContinuationHistory} from '../../packages/core-0.3/src/observation.ts';
import {canonicalEncode,stateOf} from '../../packages/core-0.3/src/adapter.ts';

export function readDocumentDigest(path,expected) {
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try {
  const before=fstatSync(fd);if(!before.isFile()||before.nlink!==1||before.size>65536)throw Error('DOCUMENT_UNSUPPORTED');
  const bytes=readFileSync(fd),after=fstatSync(fd);
  if(before.size!==bytes.length||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw Error('DOCUMENT_CHANGED');
  const digest={algorithm:'sha256',value:'0x'+createHash('sha256').update(bytes).digest('hex')};
  if(expected&&(expected.algorithm!==digest.algorithm||expected.value!==digest.value))throw Error('DOCUMENT_DIGEST_MISMATCH');
  return digest;
 }finally{closeSync(fd);}
}
const criteria={
 SOURCE_REVIEWED:{state:'SATISFIED',reason:'Host read the selected incident bytes and verified their digest.'},
 HISTORY_REVIEWED:{state:'SATISFIED',reason:'Host reviewed the full case and its uncertainty at the report head.'},
 FINDING_RECORDED:{state:'SATISFIED',reason:'Local report states the result and remaining outside uncertainty.'},
 CONTROL_REVIEWED:{state:'SATISFIED',reason:'Host checked current assignment, revoked and spent powers; restoration is separate.'},
};

/** Continue a real, already-created E5/E6 case. Never creates/replaces a case or dispatches a tool. */
export async function investigateDuty({local,dutyId,sourceFile,sourceDigest,reportDirectory,observeAgain,onStage=()=>{}}) {
 if(typeof observeAgain!=='function')throw Error('A real later observation callback is required for this walkthrough');
 const owner=openLocalOwner(local),store=openConfiguredEventStore(local).directoryStore;
 const original=owner.exportHistory(),before=stateOf(original),duty=before.attemptDuties.get(dutyId);
 assert.ok(duty,'Existing duty required');assert.equal(before.attemptDutyPolicies.has(dutyId),false,'Do not silently restart an investigation');
 const source=readDocumentDigest(sourceFile,sourceDigest);
 const actor=before.runtimeSessions.get(local.session).agentId;assert.equal(duty.currentAssigneeId,actor);
 const duties=openLocalDutyPolicy(local),selection=duties.describe({duty:dutyId,incidentSourceDigest:source,attesterRole:duty.record.durableRoleId});
 const saved={version:'continuity-investigation-example/1',dutyId,sourceFile,sourceDigest:source,operations:[],documents:[]};
 const emit=(stage,extra={})=>onStage({stage,...extra});
 owner.grant({id:'investigation:activate',to:actor,actions:[selection.activationAction],resources:[selection.activationResource],expiresAt:10000});
 await duties.activate({id:'investigation:rules',descriptor:selection.descriptor,activationAuthority:'investigation:activate'});
 const resource='duty:'+selection.descriptorHash;
 for(const [id,action] of [['investigation:attest','ATTEST_DUTY_FINDING'],['investigation:dispose','RECORD_DUTY_DISPOSITION']])owner.grant({id,to:actor,actions:[action],resources:[resource],expiresAt:10000});
 const document=(name,body)=>{
  const path=join(reportDirectory,name);writeFileSync(path,JSON.stringify(body,null,2)+'\n',{flag:'wx',mode:0o600});
  const digest=readDocumentDigest(path);saved.documents.push({path,digest});return digest;
 };
 let signs=0;
 const signHash=hash=>{readDocumentDigest(sourceFile,source);for(const doc of saved.documents)readDocumentDigest(doc.path,doc.digest);signs++;return local.signHash(hash);};
 const writer=openLocalDutyPolicy({...local,signHash});
 const permission={attestationAuthority:'investigation:attest',dispositionAuthority:'investigation:dispose'};
 const complete=async(id,note)=>{
  const history=store.snapshot().history;
  const reportDigest=document(id+'.json',{purpose:'Local investigation report',sourceDigest:source,observedHead:history.head,note,externalOutcome:'NOT_PROVEN',restoration:'Requires its own permission; it cannot finish this investigation.'});
  const input={id,duty:dutyId,disposition:'COMPLETED_UNDER_POLICY',checklist:criteria,reportDigest,nextStep:null,...permission};
  const result=await writer.dispose(input);saved.operations.push({method:'dispose',input});
  assert.equal(result.view.dutyDisposition,'COMPLETED_UNDER_POLICY');assert.equal(result.view.externalOutcome,'NOT_PROVEN');
  emit('investigation-completed',{eventId:result.eventId,reportDigest,head:result.head,externalOutcome:result.view.externalOutcome});return result;
 };
 const first=await complete('investigation:first','The original result was recovered without repeating restriction. No required local review remains; the outside result is still not proven.');
 await observeAgain();assert.equal(writer.inspect(dutyId).policy.dutyDisposition,'NEEDS_REVIEW');
 emit('later-report-needs-review',{priorDisposition:first.eventId,current:'NEEDS_REVIEW'});
 const second=await complete('investigation:updated','The later recorded service observation was reviewed. It adds an attributed report, not external proof.');
 const challengeDigest=document('investigation-challenge.json',{purpose:'Attributed challenge',target:second.eventId,reason:'Request another review of whether the source report fully describes the incident.',externalOutcome:'NOT_PROVEN'});
 const contest={id:'investigation:challenge',duty:dutyId,targetDispositionId:second.eventId,reason:'Challenge the completeness of the incident description.',reportDigest:challengeDigest,...permission};
 const challenged=await writer.contest(contest);saved.operations.push({method:'contest',input:contest});
 assert.equal(challenged.view.dutyDisposition,'CONTESTED');assert.equal(challenged.view.outstanding,true);
 assert.equal(challenged.view.lastRecordedDisposition.eventId,second.eventId);
 const head=store.snapshot().history.head,events=owner.exportHistory();
 assert.equal(canonicalEncode(events.slice(0,original.length)),canonicalEncode(original));
 assert.equal(canonicalEncode([...stateOf(events).authorityUsage]),canonicalEncode([...before.authorityUsage]));
 const query=observeContinuationHistory(store.snapshot().history).survives(actor);
 assert.equal(query.answer.attemptDuties.find(row=>row.dutyId===dutyId).currentView.dutyDisposition,'CONTESTED');
 saved.head=head;saved.eventCount=events.length;
 const retryFile=join(reportDirectory,'investigation-retry.json');writeFileSync(retryFile,JSON.stringify(saved,null,2)+'\n',{flag:'wx',mode:0o600});
 emit('investigation-contested',{eventId:challenged.eventId,current:'CONTESTED',outstanding:true,originalCreation:duty.record.status,signatures:signs});
 return {retryFile,head,eventCount:events.length,sourceDigest:source,disposition:'CONTESTED',outstanding:true,externalOutcome:'NOT_PROVEN',signatures:signs};
}

/** A fresh host can retry the exact recorded operations after permission expiry. */
export async function retryInvestigation(local,file) {
 const saved=JSON.parse(readFileSync(file,'utf8'));
 readDocumentDigest(saved.sourceFile,saved.sourceDigest);for(const doc of saved.documents)readDocumentDigest(doc.path,doc.digest);
 let signatures=0;const duties=openLocalDutyPolicy({...local,now:()=>10001,signHash:()=>{signatures++;throw Error('RETRY_MUST_NOT_SIGN');}});
 const store=openConfiguredEventStore(local).directoryStore,before=store.snapshot();
 for(const operation of saved.operations){const result=await duties[operation.method](operation.input);assert.equal(result.alreadyRecorded,true);assert.equal(result.view.dutyDisposition,'CONTESTED');assert.equal(result.view.externalOutcome,'NOT_PROVEN');}
 const after=store.snapshot();assert.equal(canonicalEncode(after.revision),canonicalEncode(before.revision));assert.equal(canonicalEncode(after.history.head),canonicalEncode(saved.head));assert.equal(signatures,0);
 return {pid:process.pid,signatures,appended:false,current:'CONTESTED',head:after.history.head};
}
