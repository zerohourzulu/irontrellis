import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign, verify, createHash} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync,readdirSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {canonicalEncode,hashCanonical,createLocalAttemptOwner,createLocalDomain,openHistoryStore,
  eventHash,historyIdOfGenesis,suiteFor,PRODUCTION_ANCHORING_PROFILE} from '@ramex-labs/irontrellis';
import {deriveNamespace} from '@ramex-labs/irontrellis-mcp-gateway';
import {loadProfile} from '../src/profile.ts';
import {decodeClearance} from '../src/clearance.ts';

// Fresh isolated TEST keys, kept only as in-memory KeyObjects. Only public DER is exported.
function ramSigner(keyId) {
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  const credential='0x'+publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
  const signHashSync=hash=>'0x'+sign(null,Buffer.from(hash.slice(2),'hex'),privateKey).toString('hex');
  return {keyId,scheme:'ed25519',credential,signHash:async hash=>signHashSync(hash),signHashSync,publicKey};
}
const canonical=value=>Buffer.from(canonicalEncode(value));

test('RETURN(b): actual owner and admitted session sign the exact clearance digest but cannot clear as the operator',async t=>{
  const dir=realpathSync(mkdtempSync(join(tmpdir(),'r9-clearance-')));t.after(()=>rmSync(dir,{recursive:true,force:true,maxRetries:5}));
  const ownerSigner=ramSigner('test-owner'),sessionSigner=ramSigner('test-session'),operator=ramSigner('test-operator'),now=Date.now();
  const options={historyFile:join(dir,'history.jsonl'),domain:createLocalDomain(),owner:'operator',controller:'host',now:()=>now,signer:ownerSigner,nextKey:false};
  const owner=await createLocalAttemptOwner(options);
  await owner.createAgent({id:'worker'});
  await owner.admitRuntime({agent:'worker',session:'test-session',epoch:1,key:sessionSigner.keyId,credential:sessionSigner.credential,expiresAt:now+3600000});
  const state=openHistoryStore(options.historyFile).state();
  assert.equal(state.genesis.ownerKeys[0].credential,ownerSigner.credential);
  assert.equal(state.runtimeSessions.get('test-session').credentialAddressKey,sessionSigner.credential);
  // T6 (A-195.2): the pair must be in the class table, so this synthetic manifest uses the production literals.
  const manifest={version:'irontrellis-profile-manifest/1',id:PRODUCTION_ANCHORING_PROFILE.profileId,domain:state.genesis.domain,
    historyId:historyIdOfGenesis(state.events[0]),genesisEventHash:eventHash(state.events[0]),chain:{id:'eip155:42793'},publisher:'0x'+'44'.repeat(20),
    operatorKeys:[{keyId:operator.keyId,scheme:'ed25519',credential:operator.credential}],
    nodes:{evm:{chainId:'eip155:42793',operator:'synthetic-evm'},l1:{chainId:'synthetic-tezos',operator:'synthetic-l1'},ownRollup:null},
    bodyStore:null,maxL1HeadLag:null,supersedes:null};
  const derived=deriveNamespace(canonical(manifest)),trustRoot={version:'irontrellis-profile-trust-root/1',manifest,
    manifestHash:derived.manifestHash,namespaceId:derived.namespaceId,destination:'0x'+'55'.repeat(20)};
  const loaded=await loadProfile(canonical(trustRoot),'synthetic-raw-publish-bytes-v1','fixed synthetic fee; no replacement',state,
    async()=>canonical({destination:trustRoot.destination,namespaceId:trustRoot.namespaceId,publisher:manifest.publisher,chainId:manifest.chain.id}));
  // This observed-value callback is synthetic and unqualified. It does not claim actual deployed immutables.
  const unsigned={version:'irontrellis-outbox-clearance/1',namespaceId:trustRoot.namespaceId,chainId:manifest.chain.id,publisher:manifest.publisher,
    nonce:0,attemptId:'0x'+'11'.repeat(32),haltCode:'SIGNING_UNCERTAIN',
    observed:{accountNonce:0,txAtNonce:null,bytesMatchOurs:null,includedStatementDigest:null,l1Level:null,observedAt:0},
    disposition:'RECLAIM_SAME_NONCE_SAME_BYTES',keyExposure:null,canonicalStatementDigest:null,operatorKeyId:operator.keyId};
  const original=canonical(unsigned),digest=hashCanonical(unsigned,'sha256');
  assert.equal(digest,'0x'+createHash('sha256').update(original).digest('hex'));
  const historyBefore=readFileSync(options.historyFile),filesBefore=readdirSync(dir).sort(),suite=suiteFor('ed25519');
  for(const [role,signer] of [['operator',operator],['owner',ownerSigner],['session',sessionSigner]]) {
    const signature=signer.signHashSync(digest),record={...unsigned,signature};
    assert.equal(verify(null,Buffer.from(digest.slice(2),'hex'),signer.publicKey,Buffer.from(signature.slice(2),'hex')),true,role+' valid under its own actual public key');
    assert.equal(suite.verify(digest,signature,signer.credential),true,role+' accepted by actual Core verifier');
    const {signature:removed,...signedFields}=record;
    assert.equal(removed,signature);assert.deepEqual(canonical(signedFields),original,'all unsigned fields and selected operatorKeyId unchanged');
    if(role==='operator')assert.equal(decodeClearance(canonical(record),loaded.selected).signature,signature);
    else {
      assert.equal(suite.verify(digest,signature,operator.credential),false);
      assert.throws(()=>decodeClearance(canonical(record),loaded.selected),e=>e.code==='CLEARANCE_SIGNATURE_INVALID',role+' is not the selected operator');
    }
  }
  assert.deepEqual(readFileSync(options.historyFile),historyBefore);assert.deepEqual(readdirSync(dir).sort(),filesBefore);
  assert.equal(filesBefore.some(n=>/owner-key|next-key|\.key$/.test(n)),false);
});
