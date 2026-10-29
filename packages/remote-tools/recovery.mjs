import {createHash} from 'node:crypto';
import * as core from '@ramex-labs/irontrellis/adapter';
import {openConfiguredEventStore} from '@ramex-labs/irontrellis/adapter';
import {record,requireCondition} from '@ramex-labs/irontrellis/adapter';

/** Application-owned recovery. Neither method dispatches or re-prepares work. */
export function createCooperativeRecovery({local,client,registry}) {
  const store=openConfiguredEventStore(local);
  const select=input=>{
    const value=record(input,['operationId','businessKey','tool','arguments']);
    const selected=registry.capture({intentId:value.operationId,businessKey:value.businessKey,
      tool:value.tool,arguments:value.arguments,contractId:registry.contractId});
    const state=store.state();
    requireCondition(core.canonicalEncode(state.genesis.domain)===core.canonicalEncode(local.domain),'DOMAIN_MISMATCH');
    const admission=state.intentAdmissions.get(value.operationId),intent=state.intentDeclarations.get(value.operationId)?.data;
    requireCondition(admission&&intent,'ADMISSION_REQUIRED');
    requireCondition(intent.action===selected.action&&intent.resource===selected.resource&&intent.termsCommitment===selected.termsCommitment,'OPERATION_CONFLICT');
    requireCondition(intent.amount===selected.quantities.amount&&intent.counterpartyId===selected.quantities.counterparty,'OPERATION_CONFLICT');
    return {selected,identity:admission.adapterIdentity};
  };
  const bind=(reply,{selected,identity})=>{
    let report=reply.result;
    if(report.state==='TOO_LATE')report=report.report;
    requireCondition(report.key===identity.idempotencyKey,'REPORT_MISMATCH');
    if(['APPLIED','CANCELLED','PENDING'].includes(report.state)) {
      requireCondition(report.fingerprint===identity.submissionFingerprint&&report.intentId===selected.wire.intentId&&
        report.tool===selected.wire.tool&&report.businessKey===selected.wire.businessKey&&report.contractId===registry.contractId,'REPORT_MISMATCH');
    } else requireCondition(report.state==='UNKNOWN','REPORT_UNAVAILABLE');
    const observationAcknowledgment=report.state==='APPLIED'
      ?core.createRemoteServiceReportAcknowledgment(identity,'0x'+createHash('sha256').update(core.canonicalEncode(report)).digest('hex')):null;
    return Object.freeze({serviceReport:reply,observationAcknowledgment,externalOutcome:'NOT_PROVEN',
      dispatchPerformed:false,retryPolicy:'NO_AUTOMATIC_REDELIVERY'});
  };
  return Object.freeze({
    close(){store.close();},
    async lookup(input){const selected=select(input);return bind(await client.status(selected.identity.idempotencyKey),selected);},
    // Coordinator privilege: expose this only to the application's operator.
    async cancel(input){const selected=select(input);return bind(await client.cancel(selected.identity.idempotencyKey),selected);},
  });
}
