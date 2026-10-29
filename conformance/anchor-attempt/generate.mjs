/** SYNTHETIC_TEST_ONLY. Deliberately public, nonsecret test constants below.
 * This generator is approved for offline conformance only. No network, funding,
 * wallet, operator profile, random key generation or production custody exists.
 */
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve,dirname} from 'node:path';
import {publicPublisher,publicOperator,signSyntheticClearance,publisherSignedClearance} from './synthetic-signing-generator.mjs';
import {keccak256,serializeTransaction} from '../../packages/anchor-outbox/node_modules/viem/_esm/index.js';
import {canonicalEncode,hashCanonical,keyPairFromPrivateKey,signHashWith,replayHistory} from '../../packages/core/dist/index.js';
import {deriveNamespace,encodeTrustRoot} from '../../packages/mcp-gateway/dist/index.js';
import {encodeRawStatementCall,decodeClearance} from '../../packages/anchor-outbox/dist/index.js';
const HERE=dirname(fileURLToPath(import.meta.url)),ROOT=resolve(HERE,'../..');
export const FIXTURE_SCOPE='SYNTHETIC_TEST_ONLY';
// Public secp256k1 scalar one: elementary generator-point test constant.
// Public RFC8032 Ed25519 test1 seed: published test input, never a credential.
const publisher=publicPublisher(),operator=publicOperator();
const vector=JSON.parse(readFileSync(resolve(ROOT,'conformance/anchor-statement/vector.json'),'utf8'));
const history=JSON.parse(readFileSync(resolve(ROOT,vector.source.history),'utf8'));
const state=replayHistory(history);
const payload={version:'irontrellis-profile-manifest/1',id:'synthetic-local-anchor',domain:vector.statement.domain,
 historyId:vector.statement.historyId,genesisEventHash:vector.statement.genesisEventHash,chain:{id:'eip155:31337'},publisher:publisher.address.toLowerCase(),
 operatorKeys:[{keyId:operator.keyId,scheme:'ed25519',credential:operator.credential}],
 nodes:{evm:{chainId:'eip155:31337',operator:'synthetic-evm'},l1:{chainId:'synthetic-l1',operator:'synthetic-l1'},ownRollup:null},bodyStore:null,maxL1HeadLag:null,supersedes:null};
const derived=deriveNamespace(canonicalEncode(payload)),root={version:'irontrellis-profile-trust-root/1',manifest:payload,
 manifestHash:derived.manifestHash,namespaceId:derived.namespaceId,destination:'0x00000000000000000000000000000000000a0144'};
encodeTrustRoot(canonicalEncode(root));
const statement={...vector.statement,profile:{id:payload.id,manifestHash:root.manifestHash},chain:{id:payload.chain.id,destination:root.destination}};
const statementBytes=Buffer.from(canonicalEncode(statement)),data=encodeRawStatementCall(statementBytes);
const tx={type:'legacy',chainId:31337,nonce:0,from:payload.publisher,to:root.destination,gas:500000n,gasPrice:1n,value:0n,data};
const identity={statementDigest:hashCanonical(statement),profileManifestHash:root.manifestHash,adapterIdentity:'synthetic-raw-publish-bytes-v1',chainId:payload.chain.id,
 destination:root.destination,publisherAddress:payload.publisher,nonce:0,unsignedTxDigest:keccak256(serializeTransaction(tx))};
const attemptId=hashCanonical(identity),signedTransaction=await publisher.signTransaction(tx),txHash=keccak256(signedTransaction);
const observed=(accountNonce,txAtNonce,bytesMatchOurs,includedStatementDigest,l1Level)=>({accountNonce,txAtNonce,bytesMatchOurs,includedStatementDigest,l1Level,observedAt:0});
const clearances=[];
for(const [haltCode,disposition,o,exposure,canonical] of [
 ['SIGNING_UNCERTAIN','RECLAIM_SAME_NONCE_SAME_BYTES',observed(0,null,null,null,null),null,null],
 ['CONSUMED_BY_OTHER','NONCE_FOREIGN_CONSUMED',observed(1,'0x'+'cc'.repeat(32),false,null,1),'KNOWN_OWN_USE',null],
 ['OUTBOX_CONFLICT','CONFLICT_RESOLVED',observed(0,null,null,null,null),null,identity.statementDigest]
]){
 const unsigned={version:'irontrellis-outbox-clearance/1',namespaceId:root.namespaceId,chainId:payload.chain.id,publisher:payload.publisher,nonce:0,
 attemptId:haltCode==='OUTBOX_CONFLICT'?null:attemptId,haltCode,observed:o,disposition,keyExposure:exposure,canonicalStatementDigest:canonical,operatorKeyId:operator.keyId};
 const signature=(await signSyntheticClearance(unsigned)).signature;
 clearances.push({record:{...unsigned,signature},unsignedDigest:hashCanonical(unsigned),canonicalHex:Buffer.from(canonicalEncode({...unsigned,signature})).toString('hex')});
}
const selected={id:payload.id,manifestHash:root.manifestHash,chainId:payload.chain.id,destination:root.destination,publisher:payload.publisher,
 adapterIdentity:identity.adapterIdentity,feePolicy:'fixed synthetic fee; no replacement',trustRoot:root};
for(const v of clearances)decodeClearance(Buffer.from(canonicalEncode(v.record)),selected);
const publisherMisuse=await publisherSignedClearance(clearances[0].record);
const negativeRecords=[
 {id:'foreign-null-exposure',record:{...clearances[1].record,keyExposure:null}},
 {id:'reclaim-nonnull-exposure',record:{...clearances[0].record,keyExposure:'KNOWN_OWN_USE'}},
 {id:'conflict-nonnull-exposure',record:{...clearances[2].record,keyExposure:'KNOWN_OWN_USE'}},
 {id:'reclaim-false-byte-match',record:{...clearances[0].record,observed:{...clearances[0].record.observed,bytesMatchOurs:false}}},
 {id:'canonical-included-mismatch',record:{...clearances[2].record,observed:{accountNonce:1,txAtNonce:txHash,bytesMatchOurs:true,includedStatementDigest:'0x'+'ee'.repeat(32),l1Level:77,observedAt:0}}},
 {id:'unknown-field',record:{...clearances[0].record,extra:true}},
 {id:'publisher-signed',record:publisherMisuse},
];
for(const v of negativeRecords){let refused=false;try{decodeClearance(Buffer.from(canonicalEncode(v.record)),selected);}catch{refused=true;}if(!refused)throw Error('CLEARANCE_NEGATIVE_ACCEPTED');}
const negatives=negativeRecords.map(v=>({...v,expectedValid:false}));
const independent=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(independent).join(',')+']':'{'+Object.keys(v).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(k=>JSON.stringify(k)+':'+independent(v[k])).join(',')+'}';
if(independent(identity)!==canonicalEncode(identity)||'0x'+createHash('sha256').update(independent(identity)).digest('hex')!==attemptId)throw Error('INDEPENDENT_ATTEMPT_DIGEST');
const signedSubstitutions={};
for(const [field,value] of [['chainId',31338],['nonce',1],['to','0x000000000000000000000000000000000000beef'],['value',1n],['data','0x1234'],['gas',500001n],['gasPrice',2n]]){
 signedSubstitutions[field]=await publisher.signTransaction({...tx,[field]:value});
}
const out={scope:FIXTURE_SCOPE,nonProduction:true,mode:'UNVERIFIED',qualifiedFinalityLabel:null,dispatchAllowed:false,
 provenance:{publisher:'public elementary secp256k1 scalar-one test input; generator only',operator:'RFC8032 section7.1 test1 seed; generator only',
 history:vector.source.history,historySha256:createHash('sha256').update(readFileSync(resolve(ROOT,vector.source.history))).digest('hex'),
 parentVector:'conformance/anchor-statement/vector.json',parentVectorSha256:createHash('sha256').update(readFileSync(resolve(ROOT,'conformance/anchor-statement/vector.json'))).digest('hex'),
 rootHead:state.head.hash,contract:'new publish(bytes) ABI proposal; no deployment or contract equivalence claim'},
 trustRoot:root,statement,attestation:vector.source.attestation,canonicalStatement:statementBytes.toString('hex'),
 identity,attemptId,attemptCanonicalHex:Buffer.from(canonicalEncode(identity)).toString("hex"),negatives,signedSubstitutions,transaction:{...tx,gas:String(tx.gas),gasPrice:String(tx.gasPrice),value:String(tx.value)},signedTransaction,transactionHash:txHash,clearances};
const text=JSON.stringify(out,null,2)+'\n',path=resolve(HERE,'vector.json');
if(process.argv.includes('--check')){if(readFileSync(path,'utf8')!==text)throw new Error('SYNTHETIC_FIXTURE_MISMATCH');console.log('synthetic fixture exact reproduction PASS');}
else {writeFileSync(path,text);console.log('synthetic fixture generated locally; no network or qualification');}
