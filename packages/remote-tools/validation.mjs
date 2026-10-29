import * as core from '@ramex-labs/irontrellis/adapter';
import {stateOf} from '@ramex-labs/irontrellis/adapter';
import {admissionControlIsCurrent} from '@ramex-labs/irontrellis/adapter';
import {evaluateReceiptPolicy} from '@ramex-labs/irontrellis/adapter';
import {captureData,record,identifier,requireCondition} from '@ramex-labs/irontrellis/adapter';

export const REFERENCE_TOOLS = Object.freeze([
  {id:'ticket.create',action:'create-ticket',resource:'queue:security',fields:{title:'text'}},
  {id:'document.access',action:'set-access',resource:'document:synthetic',fields:{level:['closed','reviewer']}},
  {id:'document.read',action:'read-document',resource:'document:synthetic',fields:{}},
  {id:'incident.note',action:'record-note',resource:'case:incident',fields:{note:'text'}},
]);
const equal=(a,b)=>core.canonicalEncode(a)===core.canonicalEncode(b);

/** Application-selected contracts; no model-generated schema or resolver code. */
export function createToolRegistry(input) {
  const config=record(input,['serviceId','account','tools']);
  const serviceId=identifier(config.serviceId),account=identifier(config.account);
  requireCondition(Array.isArray(config.tools)&&config.tools.length>0&&config.tools.length<=32);
  const definitions=config.tools.map(value=>{
    const tool=record(value,['id','action','resource','fields'],['projection','compensates']);
    const fields=captureData(tool.fields);
    requireCondition(fields!==null&&typeof fields==='object'&&!Array.isArray(fields)&&Object.keys(fields).length<=16);
    for(const [name,type] of Object.entries(fields)) {
      identifier(name);
      requireCondition(['text','integer','boolean','amount','identifier'].includes(type)||(Array.isArray(type)&&type.length>0&&type.length<=16&&type.every(x=>typeof x==='string'&&x.length<=128)));
    }
    let projection,compensates;
    if(Object.hasOwn(tool,'projection')) {
      projection=record(tool.projection,[],['amount','counterparty','unit']);
      requireCondition(Object.hasOwn(projection,'amount')||Object.hasOwn(projection,'counterparty'));
      if(Object.hasOwn(projection,'amount')) {
        requireCondition(fields[identifier(projection.amount)]==='amount'&&Object.hasOwn(projection,'unit'));
        identifier(projection.unit);
      } else requireCondition(!Object.hasOwn(projection,'unit'));
      if(Object.hasOwn(projection,'counterparty'))requireCondition(fields[identifier(projection.counterparty)]==='identifier');
    }
    if(Object.hasOwn(tool,'compensates')) {
      compensates=record(tool.compensates,['tool','businessKeyField']);
      identifier(compensates.tool);requireCondition(fields[identifier(compensates.businessKeyField)]==='identifier');
    }
    return {id:identifier(tool.id),action:identifier(tool.action),resource:identifier(tool.resource),fields,
      ...(projection?{projection}:{}),...(compensates?{compensates}:{})};
  });
  requireCondition(new Set(definitions.map(x=>x.id)).size===definitions.length);
  requireCondition(new Set(definitions.filter(x=>x.projection?.amount).map(x=>x.projection.unit)).size<=1,'MIXED_AMOUNT_UNITS');
  for(const tool of definitions)if(tool.compensates)requireCondition(definitions.some(x=>x.id===tool.compensates.tool&&!x.compensates),'INVALID_COMPENSATION');
  const contractId=core.hashCanonical({version:'continuity-tool-contract/1',serviceId,account,tools:definitions},'sha256');
  const capture=(input)=>{
    const operation=record(input,['intentId','tool','arguments','businessKey','contractId']);
    const intentId=identifier(operation.intentId),toolId=identifier(operation.tool),businessKey=identifier(operation.businessKey);
    requireCondition(operation.contractId===contractId,'CONTRACT_MISMATCH');
    const tool=definitions.find(x=>x.id===toolId);requireCondition(tool,'UNKNOWN_TOOL');
    const args=record(operation.arguments,Object.keys(tool.fields));
    for(const [field,type] of Object.entries(tool.fields)) {
      const value=args[field];
      if(Array.isArray(type))requireCondition(type.includes(value));
      else if(type==='text')requireCondition(typeof value==='string'&&value.length>0&&value.length<=1024&&!/[\u0000-\u001f\u007f]/.test(value));
      else if(type==='amount')requireCondition(typeof value==='bigint'&&value>=0n&&value<(1n<<256n));
      else if(type==='identifier')identifier(value);
      else if(type==='integer')requireCondition(Number.isSafeInteger(value)&&value>=0&&!Object.is(value,-0));
      else requireCondition(typeof value==='boolean');
    }
    const wire=core.immutableProtocolValue({intentId,tool:toolId,arguments:args,businessKey,contractId});
    const termsCommitment=core.hashCanonical({version:'continuity-tool-terms/1',serviceId,account,tool:toolId,arguments:args,businessKey,contractId},'sha256');
    const quantities={...(tool.projection?.amount?{amount:args[tool.projection.amount]}:{}),
      ...(tool.projection?.counterparty?{counterparty:args[tool.projection.counterparty]}:{})};
    return {wire,action:tool.action,resource:tool.resource,termsCommitment,quantities};
  };
  return Object.freeze({contractId,serviceId,account,tools:core.immutableProtocolValue(definitions),capture,
    validateOperation(events,input,now,destinationState) {
      requireCondition(Number.isSafeInteger(now)&&now>=0&&!Object.is(now,-0));
      const selected=capture(input),state=stateOf(events);
      requireCondition(now>=state.head.canonicalTime,'CLOCK_REGRESSION');
      const admission=state.intentAdmissions.get(selected.wire.intentId),intent=state.intentDeclarations.get(selected.wire.intentId)?.data;
      requireCondition(admission&&intent&&intent.adapterProfile.profileId===core.REMOTE_SERVICE_REPORT_ADAPTER_ID,'ADMISSION_REQUIRED');
      requireCondition(admissionControlIsCurrent(state,intent.intentId,now),'RUNTIME_NOT_CURRENT');
      requireCondition(!state.intentOutcomeStates.get(intent.intentId)?.terminal,'TERMINAL_INTENT');
      requireCondition(intent.action===selected.action&&intent.resource===selected.resource&&intent.termsCommitment===selected.termsCommitment,'INTENT_MISMATCH');
      requireCondition(Object.hasOwn(intent,'amount')===Object.hasOwn(selected.quantities,'amount')&&intent.amount===selected.quantities.amount&&
        Object.hasOwn(intent,'counterpartyId')===Object.hasOwn(selected.quantities,'counterparty')&&intent.counterpartyId===selected.quantities.counterparty,'PROJECTION_MISMATCH');
      const tool=definitions.find(x=>x.id===selected.wire.tool);
      if(tool.compensates) {
        requireCondition(destinationState?.serviceId===serviceId,'COMPENSATION_SOURCE_REQUIRED');
        const original=destinationState.attempts.find(x=>x.operation.businessKey===selected.wire.arguments[tool.compensates.businessKeyField]);
        requireCondition(original&&original.report.state==='APPLIED'&&original.operation.tool===tool.compensates.tool&&
          original.operation.contractId===contractId,'COMPENSATION_SOURCE_REQUIRED');
      }
      const proof=state.events[admission.admissionEventPosition].data.authorizationProof;
      requireCondition(proof.recognizedRoot.principalId===state.roles.get(intent.roleId).principalId,'WRONG_PRINCIPAL');
      requireCondition(evaluateReceiptPolicy(state,proof,now).live,'POLICY_NOT_LIVE');
      return core.immutableProtocolValue({...selected.wire,idempotencyKey:admission.adapterIdentity.idempotencyKey,
        submissionFingerprint:admission.adapterIdentity.submissionFingerprint});
    },
  });
}
