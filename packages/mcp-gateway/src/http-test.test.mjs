import {test} from 'node:test';
import assert from 'node:assert/strict';
import {request as httpRequest} from 'node:http';
import {writeFileSync,readFileSync,readdirSync} from 'node:fs';
import {join} from 'node:path';
import {CompactSign,generateKeyPair} from 'jose';
import {discoverOAuthProtectedResourceMetadata} from '@modelcontextprotocol/client';
import {fixture} from './http-test-helpers.mjs';

test('HTTP official MCP 2.2 client, resource metadata, real Core, immutable business repeat',async t=>{
 const f=await fixture(t);const missing=await f.raw();assert.equal(missing.status,401);assert.ok(missing.headers.get('www-authenticate').includes(f.service.metadataUrl));
 const metadata=await discoverOAuthProtectedResourceMetadata(f.service.resourceUrl);assert.equal(metadata.resource,f.service.resourceUrl);assert.deepEqual(metadata.authorization_servers,[f.issuer.issuer]);
 const c=await f.client(await f.token());assert.equal((await f.call(c)).status,'RESPONSE_RETAINED');f.advance();assert.equal((await f.call(c)).status,'RECONCILIATION_ONLY');assert.equal(f.count(0),1);
});
test('same user two immutable agent contexts isolate catalog, history, results and effects',async t=>{
 const f=await fixture(t,({config})=>{config.bindings[1].gateway.operations=config.bindings[1].gateway.operations.slice(0,1)});
 const a=await f.client(await f.token()),b=await f.client(await f.token({irontrellis_binding:'agent-b'}));
 assert.equal((await b.listTools({cursor:''})).tools.some(x=>x.name==='create_incident_ticket'),false);
 assert.equal((await f.call(a)).status,'RESPONSE_RETAINED');assert.equal(f.count(0),1);assert.equal(f.count(1),0);
 assert.equal((await f.raw(await f.token({irontrellis_binding:'agent-b',sub:'bob'}))).status,401);
});
test('pinned auth rejects wrong issuer, resource, audience array, old binding, actor, client and ID token',async t=>{
 const f=await fixture(t);
 for(const claims of [{iss:'https://other.test/'},{aud:'https://other.test/mcp'},{aud:f.service.resourceUrl.replace('/mcp','/api')},{aud:[f.service.resourceUrl]},{sub:'bob'},{client_id:'other'},{irontrellis_binding:'absent'},{continuity_binding:'agent-a'},{irontrellis_binding:null}])assert.equal((await f.raw(await f.token(claims))).status,401,JSON.stringify(claims));
 for(const header of [{typ:'JWT'},{kid:'other'},{jku:'http://169.254.169.254/keys'},{jwk:{}},{x5u:'http://[::1]/cert'}])assert.equal((await f.raw(await f.token({},header))).status,401);
 assert.equal(f.count(0),0);
});
test('duplicate claims, noncanonical JWT and forged signature cannot erase validation',async t=>{
 const f=await fixture(t),valid=await f.token(),parts=valid.split('.');
 const duplicate=await new CompactSign(Buffer.from('{"sub":"alice","sub":"bob"}')).setProtectedHeader({alg:'ES256',typ:'at+jwt',kid:'synthetic'}).sign(f.issuer.privateKey);
 const other=await generateKeyPair('ES256'),forged=await new CompactSign(Buffer.from(parts[1],'base64url')).setProtectedHeader({alg:'ES256',typ:'at+jwt',kid:'synthetic'}).sign(other.privateKey);
 for(const value of [duplicate,forged,parts[0]+'=.'+parts[1]+'.'+parts[2],valid.slice(0,-9)])assert.equal((await f.raw(value)).status,401);
});
test('finite integer times, maximum life, future/expired access and missing scope fail closed',async t=>{
 const f=await fixture(t),at=Math.floor(f.clock()/1000);
 for(const claims of [{exp:at},{iat:at+60},{nbf:at+60},{exp:at+301},{exp:at+.5},{jti:''},{exp:null},{iat:-1}])assert.equal((await f.raw(await f.token(claims))).status,401,JSON.stringify(claims));
 assert.equal((await f.raw(await f.token({scope:'profile'}))).status,403);
});
test('revocation policy exception, promise and rejected promise deny synchronously and redact errors',async t=>{
 const f=await fixture(t),token=await f.token();
 for(const policy of [()=>false,()=>{throw Error('SECRET_FILE')},async()=>true,async()=>{throw Error('SECRET_FILE')}]){
  f.setPolicy(policy);const r=await f.raw(token);assert.equal(r.status,401);assert.equal((await r.text()).includes('SECRET_FILE'),false);
 }
});
test('revocation at signing prevents any upstream effect',async t=>{
 const f=await fixture(t,({config,disable})=>{const local=config.bindings[0].gateway.local;config.bindings[0].gateway.local={...local,async signHash(h){disable();return local.signHash(h)}}});
 const c=await f.client(await f.token());await assert.rejects(f.call(c));assert.equal(f.count(0),0);
});
test('token expiry during signing and clock rollback prevent disclosure and dispatch',async t=>{
 const f=await fixture(t,({config,setClock})=>{const local=config.bindings[0].gateway.local;config.bindings[0].gateway.local={...local,async signHash(h){setClock(Date.now()+400000);return local.signHash(h)}}});
 await assert.rejects(f.call(await f.client(await f.token())));assert.equal(f.count(0),0);
 const g=await fixture(t),token=await g.token();await g.raw(token);g.setClock(g.clock()-60000);assert.equal((await g.raw(token)).status,401);
});
test('revocation after an effect withholds output; renewed authority inspects without redelivery',async t=>{
 const f=await fixture(t);writeFileSync(join(f.cases[0].directory,'tickets.control.json'),JSON.stringify({delay:300}),{mode:0o600});
 const c=await f.client(await f.token()),pending=f.call(c);
 for(let i=0;i<200&&!f.count(0);i++)await new Promise(r=>setTimeout(r,10));assert.equal(f.count(0),1);f.disable();await assert.rejects(pending);
 f.enable();f.advance();assert.equal((await f.call(await f.client(await f.token()))).status,'RECONCILIATION_ONLY');assert.equal(f.count(0),1);
});
test('Core retirement fences still-valid bearer before tool catalog or effect',async t=>{
 const f=await fixture(t),c=await f.client(await f.token());await f.cases[0].owner.advanceEpoch({agent:'worker',from:1,to:2});
 await assert.rejects(f.call(c));assert.equal(f.count(0),0);
});
test('Host Origin path content bounds duplicate headers and forwarding stripping protect listener',async t=>{
 const f=await fixture(t),token=await f.token();
 for(const headers of [{origin:'null'},{origin:'https://evil.test'}])assert.equal((await f.raw(token,{headers})).status,403);
 for(const options of [{path:'/mcp?token=secret'},{body:'{"method":"tools/list","method":"tools/call"}'},{body:'['.repeat(40)+'0'+']'.repeat(40)}])assert.equal((await f.raw(token,options)).status,400);
 assert.equal((await f.raw(token,{headers:{'content-type':'text/plain'}})).status,415);
 assert.equal((await f.raw(token,{body:'x'.repeat(32769)})).status,413);
 const url=new URL(f.service.resourceUrl),status=await new Promise((resolve,reject)=>{const r=httpRequest(url,{method:'POST',headers:['Host',url.host,'Authorization','Bearer '+token,'Authorization','Bearer '+token,'Content-Type','application/json']},res=>{res.resume();resolve(res.statusCode)});r.on('error',reject);r.end('{}')});assert.equal(status,400);
 const c=await f.client(token,{'x-forwarded-host':'evil.test','x-irontrellis-agent':'agent-b'});assert.equal((await f.call(c)).status,'RESPONSE_RETAINED');assert.equal(f.count(1),0);
});
test('binding rate and mutation limits refuse before second admission',async t=>{
 const f=await fixture(t),c=await f.client(await f.token());await f.call(c);await assert.rejects(f.call(c));assert.equal(f.count(0),1);
});
test('incoming bearer is absent from history and durable gateway/upstream records',async t=>{
 const f=await fixture(t),token=await f.token();await f.call(await f.client(token));const dir=f.cases[0].directory;
 for(const path of [join(dir,'history.jsonl'),join(dir,'tickets.calls.jsonl'),...readdirSync(join(dir,'records')).map(n=>join(dir,'records',n))])assert.equal(readFileSync(path,'utf8').includes(token),false);
});
