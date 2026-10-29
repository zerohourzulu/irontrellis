import {mkdtempSync,mkdirSync,realpathSync,rmSync,copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {generateKeyPair,signHashWith} from '@ramex-labs/irontrellis';
import {createLocalAttemptOwner,createLocalDomain} from '@ramex-labs/irontrellis/local';
import * as core from '@ramex-labs/irontrellis/adapter';
import * as remote from '../index.mjs';

export const code=expected=>error=>error.code===expected||error.message===expected;
let historyNumber=0;
export async function setup(t,{tools=remote.REFERENCE_TOOLS,hooks,historyName,headAuthenticationPolicy='COORDINATOR_AUTHENTICATED',serviceId:configuredServiceId,registryAccount='synthetic',destinationFactory=remote.createCooperativeDestination,destinationConfig={}}={}){
  const dir=realpathSync(mkdtempSync(join(tmpdir(),'irontrellis-cooperative-'))),directory=join(dir,'destination');mkdirSync(directory,{mode:0o700});
  const coordinator=generateKeyPairSync('ed25519'),provider=generateKeyPairSync('ed25519');
  const serviceId=configuredServiceId??('destination:'+randomUUID());let clock=100;
  const registry=remote.createToolRegistry({serviceId,account:registryAccount,tools}),account=generateKeyPair('ed25519','key:bea');
  const local={historyFile:join(dir,'history.jsonl'),domain:createLocalDomain(),owner:'operations',controller:'operator',now:()=>clock,
    session:'session:bea',signHash:signHashWith(account),witness:false};
  const owner=await createLocalAttemptOwner(local);
  await owner.createAgent({id:'bea'});await owner.createRole({id:'operator'});
  await owner.appoint({agent:'bea',role:'operator',tenure:'shift:1',number:1});
  await owner.admitRuntime({agent:'bea',session:local.session,epoch:1,key:'key:bea',credential:account.credential,expiresAt:1000});
  await owner.grant({id:'tools',to:'bea',actions:[...new Set(tools.map(x=>x.action))],resources:[...new Set(tools.map(x=>x.resource))],expiresAt:500});
  const store=core.openConfiguredEventStore(local),historyId=store.state().eventHistoryHashes[0];
  const destinationOptions={directory,domain:local.domain,historyId,headAuthenticationPolicy,serviceId,coordinatorPublicKey:coordinator.publicKey,servicePrivateKey:provider.privateKey,
    now:()=>clock,validateOperation:registry.validateOperation,checkpointHooks:hooks,...destinationConfig};
  let destination=await destinationFactory(destinationOptions);
  if(destinationOptions.initialize===true)destinationOptions.initialize=false;
  const makeClient=url=>remote.createCooperativeClient({url,serviceId,coordinatorPrivateKey:coordinator.privateKey,servicePublicKey:provider.publicKey,timeoutMs:10000});
  let client=makeClient(destination.url);
  const executor=remote.createCooperativeExecutor({local,client,registry,role:'operator',tenure:'shift:1'});
  const request={operationId:'job:1',businessKey:'case:1',tool:tools[0].id,arguments:{title:'Investigate synthetic document'}};
  const wire=(input=request)=>registry.capture({intentId:input.operationId,businessKey:input.businessKey,tool:input.tool,arguments:input.arguments,contractId:registry.contractId}).wire;
  async function admitOnly(input=request){
    const selected=registry.capture(wire(input));
    const adapter={adapterProfile:core.approvedAdapterProfileForPolicy(core.ADAPTER_POLICY_E5_HASH,core.REMOTE_SERVICE_REPORT_ADAPTER_ID),
      submit(submission){const i=core.deriveAdapterIdentity(submission);return {status:'OUTCOME_UNKNOWN',idempotencyKey:i.idempotencyKey,submissionFingerprint:i.submissionFingerprint}},
      reconcile(){throw Error('No test redelivery');}};
    await core.openLocalExecution(local,adapter,'REMOTE_REPORT').run({id:input.operationId,intentId:input.operationId,action:selected.action,resource:selected.resource,role:'operator',tenure:'shift:1',termsCommitment:selected.termsCommitment,...selected.quantities});
    const admission=store.state().intentAdmissions.get(input.operationId);if(!admission)throw Error('Test admission failed');return admission.adapterIdentity.idempotencyKey;
  }
  t.after(async()=>{
    executor.close();store.close();await destination.close();
    if(process.env.IRONTRELLIS_TEST_HISTORY_DIR){const output=resolve(process.env.IRONTRELLIS_TEST_HISTORY_DIR);mkdirSync(output,{recursive:true});copyFileSync(local.historyFile,join(output,(historyName??t.name.replace(/[^a-zA-Z0-9]+/g,'-'))+'.jsonl'));}
    rmSync(dir,{recursive:true,force:true});
  });
  return {dir,directory,coordinator,provider,serviceId,registry,local,owner,executor,request,wire,admitOnly,destinationOptions,store,historyId,
    get destination(){return destination},get client(){return client},setTime(value){clock=value},
    async checkpoint(){return client.checkpointHistory(store)},
    async restart(){await destination.close();destination=await destinationFactory(destinationOptions);client=makeClient(destination.url);return destination;}};
}
export async function prepared(s){const key=await s.admitOnly();if((await s.checkpoint()).result.state!=='CHECKPOINTED')throw Error('checkpoint');if((await s.client.prepare(s.wire())).result.state!=='PENDING')throw Error('prepare');return key;}
