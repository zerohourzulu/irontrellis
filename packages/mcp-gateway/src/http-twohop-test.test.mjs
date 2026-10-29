import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {readdirSync,readFileSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {tlsFixture,message} from './http-test-tls.mjs';
test('real HTTPS router and independent mTLS backend execute through actual Core',async t=>{
 const f=await tlsFixture(t),token=await f.token();
 const listed=await f.send({token,headers:{'x-forwarded-host':'evil.test','forwarded':'for=attacker','x-irontrellis-agent':'other'}});assert.equal(listed.status,200,listed.text);assert.ok(listed.json().result.tools.length);
 const run=await f.send({token,object:message('tools/call',{name:'create_incident_ticket',arguments:{title:'Synthetic two-hop'}})});assert.equal(run.status,200,run.text);assert.equal(run.json().result.structuredContent.status,'RESPONSE_RETAINED');
 assert.equal(readFileSync(join(f.f.directory,'tickets.calls.jsonl'),'utf8').includes(token),false);
 assert.equal(readdirSync(f.nonceDirectory).length,2);
});
test('backend independently rejects revoked bearer and retired Core despite router acceptance',async t=>{
 const f=await tlsFixture(t),token=await f.token();f.denyBackend();const r=await f.send({token});assert.equal(r.status,401,r.text);
 const g=await tlsFixture(t),other=await g.token();await g.f.owner.advanceEpoch({agent:'worker',from:1,to:2});assert.equal((await g.send({token:other})).status,400);assert.equal(existsSync(join(g.f.directory,'tickets.calls.jsonl')),false);
});
test('private listener rejects missing or unapproved mTLS client and unknown assertion signing key',async t=>{
 const f=await tlsFixture(t),token=await f.token();await assert.rejects(f.send({privateHop:true,token,client:{}}));
 assert.equal((await f.send({privateHop:true,token,client:f.tls.rogue})).status,400);
 assert.equal((await f.send({privateHop:true,token,signingKey:generateKeyPairSync('ed25519').privateKey})).status,400);
});
test('request assertion rejects body, resource, identity, headers, mapping, tenant, time and channel confusion',async t=>{
 const f=await tlsFixture(t),token=await f.token();
 for(const mutate of [r=>r.bodyDigest='0'.repeat(64),r=>r.resource='https://alias.test/mcp',r=>r.identity.bindingId='other',r=>r.headers['mcp-method']='tools/call',r=>r.revision='mapping-0',r=>r.tenant='other',r=>r.at-=6000,r=>r.at+=10000,r=>r.channel='wrong',r=>r.expiresAt+=1])assert.equal((await f.send({privateHop:true,token,mutate})).status,400);
 assert.equal(readdirSync(f.nonceDirectory).length,0);
});
test('request assertion replay is refused on same authenticated TLS channel and persists nonce custody',async t=>{
 const f=await tlsFixture(t),token=await f.token(),first=await f.send({privateHop:true,token,agent:f.agent});assert.equal(first.status,200,first.text);
 const assertionHeader=f.send.lastAssertion;assert.equal((await f.send({privateHop:true,token,agent:f.agent,assertionHeader})).status,400);assert.equal(readdirSync(f.nonceDirectory).length,1);
 // A new connection also fails because the assertion commits to TLS exporter bytes.
 assert.equal((await f.send({privateHop:true,token,assertionHeader})).status,400);
});
test('router denies backend pin substitution and canonical token on resource aliases',async t=>{
 const f=await tlsFixture(t),token=await f.token();
 await f.restartRouter({bindings:[{...f.routerOptions.bindings[0],backend:{...f.routerOptions.bindings[0].backend,peerFingerprint:'0'.repeat(64)}}]});
 assert.equal((await f.send({token})).status,400);
 assert.equal((await f.send({token,headers:{origin:'https://alias.test'}})).status,403);
 assert.equal((await f.send({token:await f.token({aud:'https://gateway.test/api'})})).status,401);
});
test('two-hop revocation during session signing withholds effect even after authentication on both hops',async t=>{
 const f=await tlsFixture(t,({backendOptions,denyBackend})=>{const local=backendOptions.bindings[0].gateway.local;backendOptions.bindings[0].gateway.local={...local,async signHash(h){denyBackend();return local.signHash(h)}}});
 const result=await f.send({token:await f.token(),object:message('tools/call',{name:'create_incident_ticket',arguments:{title:'Revoke while signing'}})});
 assert.equal(result.status,401,result.text);assert.equal(existsSync(join(f.f.directory,'tickets.calls.jsonl')),false);
});
test('two-hop same-user agent routes remain isolated across independent backend histories',async t=>{
 const {createDemoCase}=await import('../dist/demo.js'),{serveGatewayBackend}=await import('../dist/http.mjs');
 const f=await tlsFixture(t),second=await createDemoCase(join(f.root,'tenant-b')),nonceDirectory=join(f.root,'nonces-b');
 const {mkdirSync}=await import('node:fs');mkdirSync(nonceDirectory,{mode:0o700});
 const binding={...f.binding,id:'agent-b',tenant:'tenant-b',revision:'mapping-b'};
 const backend=await serveGatewayBackend({...f.backendOptions,bindings:[{...binding,gateway:{...second.config,operations:second.config.operations.slice(0,1),local:second.local,connectorSigner:second.connectorSigner}}],privateChannel:{...f.backendOptions.privateChannel,nonceDirectory}});f.onCleanup(async()=>{await backend.close();if(process.env.IRONTRELLIS_TEST_HISTORY_DIR){const {copyFileSync}=await import('node:fs');copyFileSync(second.local.historyFile,join(process.env.IRONTRELLIS_TEST_HISTORY_DIR,'twohop-agent-b-history.jsonl'))}});
 await f.restartRouter({bindings:[...f.routerOptions.bindings,{...binding,backend:{url:`https://127.0.0.1:${backend.port}/mcp`,servername:'localhost',peerFingerprint:f.tls.backend.fingerprint}}]});
 const a=await f.token(),b=await f.token({irontrellis_binding:'agent-b'});const listed=await f.send({token:b});assert.equal(listed.status,200);assert.equal(listed.json().result.tools.some(t=>t.name==='create_incident_ticket'),false);
 const applied=await f.send({token:a,object:message('tools/call',{name:'create_incident_ticket',arguments:{title:'Only A'}})});assert.equal(applied.json().result.structuredContent.status,'RESPONSE_RETAINED');assert.equal(existsSync(join(second.directory,'tickets.calls.jsonl')),false);
 // Deliberately misroute the signed binding to A: independent backend bearer mapping rejects it.
 await f.restartRouter({bindings:[{...binding,backend:f.routerOptions.bindings[0].backend}]});assert.equal((await f.send({token:b})).status,401);
});
