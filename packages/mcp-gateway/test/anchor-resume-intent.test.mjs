import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import {mkdtempSync, realpathSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalEncode, createLocalAttemptOwner, createLocalDomain, openLocalRuntime, openHistoryStore,
  eventHash, historyIdOfGenesis, inspectAdmittedIntentState, ed25519KeyCheck, PRODUCTION_ANCHORING_PROFILE} from '@ramex-labs/irontrellis';
import {createGateway, operationIdentity} from '../dist/gateway.js';
import {deriveNamespace, encodeTrustRoot, encodeAnchorVerifyReport} from '../dist/anchor-profile/index.js';
import {dispatchPaths} from '../dist/dispatch-files.js';
import {openAnchorBarrier} from '../dist/anchor-barrier.js';

// TEST ONLY. Private KeyObjects never leave these closures or get serialized.
function ramSigner(keyId) {
  const {publicKey, privateKey}=generateKeyPairSync('ed25519');
  const credential='0x'+publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
  const signHashSync=hash=>'0x'+sign(null,Buffer.from(hash.slice(2),'hex'),privateKey).toString('hex');
  return Object.freeze({keyId,scheme:'ed25519',credential,signHash:async hash=>signHashSync(hash),signHashSync});
}
const h=c=>'0x'+c.repeat(64);

async function fixture(t) {
  const dir=realpathSync(mkdtempSync(join(tmpdir(),'r9-resume-'))), storage=join(dir,'records'), reports=join(dir,'reports');
  mkdirSync(storage,{mode:0o700});mkdirSync(reports,{mode:0o700});
  const signer=ramSigner('test-owner'), session=ramSigner('test-session'), now=Date.now();
  const local={historyFile:join(dir,'history.jsonl'),domain:createLocalDomain(),owner:'operator',controller:'host',
    session:'test-session',now:()=>now,signHash:session.signHash};
  const owner=await createLocalAttemptOwner({...local,signer,nextKey:false});
  await owner.createAgent({id:'worker'});await owner.createRole({id:'analyst'});
  await owner.appoint({agent:'worker',role:'analyst',tenure:'shift:1',number:1});
  await owner.admitRuntime({agent:'worker',session:local.session,epoch:1,key:session.keyId,credential:session.credential,expiresAt:now+3600000});
  await owner.grant({id:'write',to:'worker',actions:['create-ticket','inspect-operation'],resources:['queue:incident'],expiresAt:now+3600000});
  const state=()=>openHistoryStore(local.historyFile).state(), initial=state();
  const manifest={version:'irontrellis-profile-manifest/1',id:PRODUCTION_ANCHORING_PROFILE.profileId, // T6 (A-195.2): a pair of the class table
   domain:initial.genesis.domain,
    historyId:historyIdOfGenesis(initial.events[0]),genesisEventHash:eventHash(initial.events[0]),chain:{id:'eip155:42793'},publisher:'0x'+'44'.repeat(20),
    operatorKeys:[{keyId:'public-test-base-point',scheme:'ed25519',credential:'0x58'+'66'.repeat(31)}],
    nodes:{evm:{chainId:'eip155:42793',operator:'synthetic-evm'},l1:{chainId:'synthetic-tezos',operator:'synthetic-l1'},ownRollup:null},
    bodyStore:null,maxL1HeadLag:null,supersedes:null};
  const namespace=deriveNamespace(canonicalEncode(manifest)),root={version:'irontrellis-profile-trust-root/1',manifest,
    manifestHash:namespace.manifestHash,namespaceId:namespace.namespaceId,destination:'0x'+'55'.repeat(20)};
  const anchoring={trustRootBytes:encodeTrustRoot(canonicalEncode(root)).canonicalText,reportDirectory:reports,stopFile:join(dir,'stop.json'),waitMs:0,pollMs:5,
    async readInstanceImmutables(){return {destination:root.destination,namespaceId:root.namespaceId,publisher:manifest.publisher,chainId:manifest.chain.id,mode:'CONSENSUS_VERIFIED'};}};
  // Privileged synthetic report/immutable observations test gateway control flow only; no chain qualification is asserted.
  const approval={name:'create_ticket',inputSchema:{type:'object',properties:{title:{type:'string',minLength:1,maxLength:120}},required:['title'],additionalProperties:false}};
  const job={name:'create_incident_ticket',upstream:'tickets',tool:'create_ticket',businessKey:'return-a:ticket',action:'create-ticket',resource:'queue:incident',role:'analyst',tenure:'shift:1',approval};
  const options={local,mode:'exactly-once',storage,operations:[job],anchoring,
    upstreams:[{id:'tickets',command:process.execPath,args:[fileURLToPath(new URL('../dist/demo-upstream.js',import.meta.url)),dir,'tickets']}]};
  const gateways=[];const open=async()=>{const g=await createGateway(options);gateways.push(g);return g;};
  t.after(async()=>{for(const g of gateways)await g.close();rmSync(dir,{recursive:true,force:true,maxRetries:5});});
  const operationId=operationIdentity(local.domain,job.businessKey),paths=dispatchPaths(storage,operationId);
  const count=()=>existsSync(join(dir,'tickets.calls.jsonl'))?readFileSync(join(dir,'tickets.calls.jsonl'),'utf8').trim().split('\n').length:0;
  function persist() {
    const current=state();const report={version:'irontrellis-anchor-verify-report/1',profileId:manifest.id,chainId:manifest.chain.id,
      statement:{digest:h('1'),historyId:manifest.historyId,head:{hash:current.head.hash,position:current.head.position}},
      tx:{hash:h('2'),l2Block:0,l2BlockHash:'SYNTHETIC'},nodes:{evm:{...manifest.nodes.evm,protocol:'synthetic',softwareCommit:'fixture',headLevel:0},
        l1:{...manifest.nodes.l1,protocol:'synthetic',softwareCommit:'fixture',headLevel:102},ownRollup:null},
      finality:{label:'L1_FINAL',mode:'CONSENSUS_VERIFIED',l1Level:100,l1BlockHash:'BKiHLREqU3JkXfzEDYAkmmfX48gBDtYhMrpA98s7Aq4SzbUAB6M',l1BlockTime:1_760_000_000_000,operationHash:'oneev3QMfQJd2fEM3zQPdFwwPY1aohkxffttrK8Qrswemnh2nML',refutationResidual:'OPEN',cementedAt:null},
      sentence:'Synthetic offline test, not actual chain evidence.',observedAt:0,continuity:{previousReportDigest:null,contradiction:false}};
    const encoded=encodeAnchorVerifyReport(canonicalEncode(report));
    writeFileSync(join(reports,encoded.reportDigest.slice(2)+'.json'),encoded.canonicalText,{mode:0o600,flag:'wx'});
  }
  return {dir,storage,local,state,open,operationId,paths,count,persist,anchoring,manifest};
}

test('RETURN(a): accepted effect closes delayed intent; restarted gateway refuses INTENT_NOT_OPEN with zero business calls',async t=>{
  const f=await fixture(t),g=await f.open(),args={title:'Synthetic resume test'};
  const first=await g.run('create_incident_ticket',args);
  assert.equal(first.status,'DELAYED');assert.equal(first.dispatchPerformed,false);
  assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);assert.equal(existsSync(f.paths.barrier),false);
  const before=f.state(),admission=before.intentAdmissions.get(f.operationId);
  assert.ok(admission);assert.equal(before.effects.size,0);assert.equal(before.refusals.size,0);
  await openLocalRuntime(f.local).recordEffect({effectId:'test-effect-closes-resume',intentId:f.operationId,
    measurer:{kind:'SESSION',id:before.runtimeSessions.get(f.local.session).agentId},metric:'test-count',unit:'count',amount:'1',observedAt:f.local.now()});
  const closed=f.state();assert.equal(closed.effects.size,1);assert.equal(closed.events.at(-1).type,'EFFECT_RECORDED');
  assert.equal(closed.effects.get('test-effect-closes-resume').intentId,f.operationId);
  assert.deepEqual(closed.intentAdmissions.get(f.operationId),admission);
  assert.equal(inspectAdmittedIntentState(closed,f.operationId,f.local.now()).status,'ADMITTED');
  f.persist();
  const barrier=await openAnchorBarrier(f.anchoring,closed,f.storage);
  assert.ok(barrier.eligible({operationId:f.operationId,intentId:f.operationId,admissionEventId:admission.admissionEventId,
    admissionHead:admission.admissionHead,submissionIdentity:admission.adapterIdentity,resumed:true},closed),'synthetic privileged report is eligible; refusal is not missing evidence');
  await g.close();const resumed=await f.open();
  const history=readFileSync(f.local.historyFile),stored=readdirSync(f.storage).sort();
  const storedBytes=stored.map(name=>readFileSync(join(f.storage,name)));
  const result=await resumed.run('create_incident_ticket',args);
  assert.equal(result.status,'NOT_DISPATCHED',JSON.stringify(result));assert.equal(result.reason,'INTENT_NOT_OPEN');assert.equal(result.dispatchPerformed,false);
  await resumed.close();const again=await f.open(),repeat=await again.run('create_incident_ticket',args);
  assert.equal(repeat.status,'NOT_DISPATCHED');assert.equal(repeat.reason,'INTENT_NOT_OPEN');assert.equal(repeat.dispatchPerformed,false);
  assert.equal(f.count(),0);assert.equal(existsSync(f.paths.attempt),false);assert.equal(existsSync(f.paths.barrier),false);
  assert.deepEqual(readFileSync(f.local.historyFile),history);
  assert.deepEqual(stored.map(name=>readFileSync(join(f.storage,name))),storedBytes);
  assert.deepEqual(readdirSync(f.storage).sort(),stored);assert.equal(f.state().effects.size,1);assert.equal(f.state().refusals.size,0);
  assert.equal(readdirSync(f.dir).some(n=>/owner-key|next-key|\.key$/.test(n)),false);
});

test('RETURN(c): public Core point checker preserves profile operator acceptance and small-order refusal',async t=>{
  const f=await fixture(t),basepoint='0x58'+'66'.repeat(31),identity='0x01'+'00'.repeat(31);
  assert.equal(ed25519KeyCheck(Buffer.from(basepoint.slice(2),'hex')),'OK');
  assert.equal(ed25519KeyCheck(Buffer.from(identity.slice(2),'hex')),'SMALL_ORDER');
  assert.doesNotThrow(()=>deriveNamespace(canonicalEncode(f.manifest)));
  const invalid={...f.manifest,operatorKeys:[{...f.manifest.operatorKeys[0],credential:identity}]};
  assert.throws(()=>deriveNamespace(canonicalEncode(invalid)));
});
