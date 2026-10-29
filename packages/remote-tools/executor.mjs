import {createHash} from 'node:crypto';
import * as core from '@ramex-labs/irontrellis/adapter';
import {openConfiguredEventStore} from '@ramex-labs/irontrellis/adapter';
import {openLocalExecution} from '@ramex-labs/irontrellis/adapter';
import {record,identifier,requireCondition} from '@ramex-labs/irontrellis/adapter';

/** Trusted application factory. Model arguments cannot select identity or client. */
export function createCooperativeExecutor({local,client,registry,role,tenure}) {
  requireCondition(local.additionalPolicy === undefined, "UNSUPPORTED_ADDITIONAL_POLICY");
  const store=openConfiguredEventStore(local);
  const profile=core.approvedAdapterProfileForPolicy(core.ADAPTER_POLICY_E5_HASH,core.REMOTE_SERVICE_REPORT_ADAPTER_ID);
  role=identifier(role);tenure=identifier(tenure);
  const select=input=>{
    const value=record(input,['operationId','businessKey','tool','arguments']);
    const selected=registry.capture({intentId:identifier(value.operationId),businessKey:value.businessKey,
      tool:value.tool,arguments:value.arguments,contractId:registry.contractId});
    return {...selected,op:{id:selected.wire.intentId,intentId:selected.wire.intentId,action:selected.action,resource:selected.resource,role,tenure,termsCommitment:selected.termsCommitment,...selected.quantities}};
  };
  const retained=new Map();
  // Why a run stopped before anything was dispatched, in plain words; the recorded adapter outcome is unchanged.
  const diagnostics=new Map();
  // Neutral: REQUIRE_OWNER is one possible cause; a clock or history conflict gives the same refusal.
  const CHECKPOINT_REFUSED='The destination refused the checkpoint before anything was dispatched. One possible cause is a destination that requires an owner-attested head (REQUIRE_OWNER): give the executor the owner signer, or use COORDINATOR_AUTHENTICATED. A clock or history conflict also refuses it.';
  const adapterFor=selected=>{
    const unknown=i=>({status:'OUTCOME_UNKNOWN',idempotencyKey:i.idempotencyKey,submissionFingerprint:i.submissionFingerprint});
    const convert=(reply,i,status)=>{
      const report=reply.result;
      if(report.state!=='APPLIED') {
        requireCondition(report.key === undefined || report.key === i.idempotencyKey, "REPORT_MISMATCH");
        retained.set(i.intentId,reply);
        return unknown(i);
      }
      requireCondition(report.key===i.idempotencyKey&&report.fingerprint===i.submissionFingerprint&&report.intentId===i.intentId&&
        report.tool===selected.wire.tool&&report.businessKey===selected.wire.businessKey&&report.contractId===registry.contractId,'REPORT_MISMATCH');
      retained.set(i.intentId,reply);
      const digest='0x'+createHash('sha256').update(core.canonicalEncode(report)).digest('hex');
      const acknowledgment=core.createRemoteServiceReportAcknowledgment(i,digest);
      const evidence=core.adapterAcknowledgmentEvidence(i,acknowledgment);
      return {status,idempotencyKey:i.idempotencyKey,submissionFingerprint:i.submissionFingerprint,
        acknowledgment,...(status==='RETRY'?{retainedEvidence:evidence}:{evidence})};
    };
    return {adapterProfile:profile,
      async submit(submission) {
        const i=core.deriveAdapterIdentity(submission);
        try {
          const checkpoint=await client.checkpointHistory(store);
          if(checkpoint.result.state!=='CHECKPOINTED'){
            if(checkpoint.result.code==='CHECKPOINT_CONFLICT')diagnostics.set(i.intentId,CHECKPOINT_REFUSED);
            return unknown(i);
          }
          const prepared=await client.prepare(selected.wire);
          if(prepared.result.state==='APPLIED')return convert(prepared,i,'RETRY');
          if(prepared.result.state!=='PENDING')return convert(prepared,i,'RETRY');
          return convert(await client.commit(i.idempotencyKey),i,'SUBMITTED');
        } catch {return unknown(i);}
      },
      async reconcile(submission) {
        const i=core.deriveAdapterIdentity(submission);
        try {return convert(await client.status(i.idempotencyKey),i,'RETRY');}
        catch {return unknown(i);}
      },
    };
  };
  return Object.freeze({
    close(){store.close();},
    async run(input) {
      const selected=select(input);
      const execution=await openLocalExecution(local,adapterFor(selected),'REMOTE_REPORT').run(selected.op);
      const diagnostic=diagnostics.get(selected.wire.intentId);
      return Object.freeze({execution,serviceReport:retained.get(selected.wire.intentId)??null,
        externalOutcome:'NOT_PROVEN',revocationBoundary:'DESTINATION_ACKNOWLEDGED_CHECKPOINT',...(diagnostic===undefined?{}:{diagnostic})});
    },
    // Publishing a checkpoint is an owner/application action, not an agent tool.
    checkpoint(){return client.checkpointHistory(store);},
  });
}
