// Copy into a fresh installed-consumer directory. Public package imports only.
// Raw-call preparation/closed-input smoke; no history, key, RPC or network.
import assert from 'node:assert/strict';
import {canonicalEncode} from '@ramex-labs/irontrellis';
import {openAnchorOutbox,encodeRawStatementCall,createObservedConnector,createSingleHttpSender,decodeClearance} from '@ramex-labs/irontrellis-anchor-outbox';
for(const fn of [openAnchorOutbox,encodeRawStatementCall,createObservedConnector,createSingleHttpSender,decodeClearance])assert.equal(typeof fn,'function');
const h='0x'+'00'.repeat(32),statement={version:'irontrellis-anchor-statement/1',
 domain:{protocol:'irontrellis',version:'2',deploymentId:'installed-smoke'},historyId:h,genesisEventHash:h,
 profile:{id:'installed-smoke',manifestHash:h},head:{hash:h,position:0,canonicalTime:0},stateRoot:h,projectionHead:null,
 attestationDigest:h,sequence:0,predecessor:null,previousHead:null,chain:{id:'eip155:31337',destination:'0x000000000000000000000000000000000000beef'},
 evidence:{manifestDigest:null,certificateDigest:null,checkpointEventId:null},availability:'ANCHOR_ONLY'};
const raw=Buffer.from(canonicalEncode(statement)),call=encodeRawStatementCall(raw);
assert.match(call,/^0x[0-9a-f]+$/);assert.ok(call.length>raw.length*2);assert.equal(call,encodeRawStatementCall(Buffer.from(raw)));
assert.throws(()=>encodeRawStatementCall(Buffer.concat([raw,Buffer.from('\n')])));
await assert.rejects(()=>openAnchorOutbox({}));
console.log('anchor-outbox installed public exports/raw preparation/closed-input smoke PASS');
