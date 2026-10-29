import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {setup} from '../../remote-tools/test/helpers.mjs';
import {lossyRelay} from './cooperative-test-relay.mjs';
import {createCooperativeGateway,cancellationIdentity} from '../dist/cooperative.mjs';
import {createTaskManager,routeTaskRequest,TASKS_EXTENSION} from '../dist/tasks.mjs';
import {operationIdentity} from '../dist/gateway.js';
async function fixture(t){
 const f=await setup(t),relay=await lossyRelay(f.destination.url),storage=join(f.dir,'gateway');mkdirSync(storage,{mode:0o700});
 const tool=f.registry.tools[0];await f.owner.grant({id:'inspect',to:'bea',actions:['inspect-operation'],resources:[tool.resource],expiresAt:500});
 const config={local:f.local,storage,registry:{serviceId:f.registry.serviceId,account:f.registry.account,tools:f.registry.tools},destination:{url:relay.url,serviceId:f.serviceId,coordinatorPrivateKey:f.coordinator.privateKey,servicePublicKey:f.provider.publicKey},operations:[{name:'job',tool:tool.id,businessKey:'synthetic:1',role:'operator',tenure:'shift:1'}]};
 const gateways=[];t.after(async()=>{for(const g of gateways)await g.close();await relay.close()});
 return {...f,relay,config,operationId:operationIdentity(f.local.domain,'synthetic:1'),async open(extra={}){const g=await createCooperativeGateway({...config,...extra});gateways.push(g);return g}};
}
const args={title:'Synthetic gateway job'};
test('cooperative actual format2 engine executes once and recovers exact immutable request',async t=>{
 const f=await fixture(t),g=await f.open(),first=await g.run('job',args);assert.equal(first.status,'RESPONSE_RETAINED',JSON.stringify(first));assert.equal(first.serviceState,'APPLIED');
 assert.equal(f.store.state().intentAdmissions.has(f.operationId),true);assert.equal((await g.run('job',args)).status,'RECONCILIATION_ONLY');
 assert.equal((await g.run('job',{title:'changed'})).reason,'OPERATION_CONFLICT');assert.equal(f.destination.inspect().effects.length,1);
 await g.close();const next=await f.open();assert.equal((await next.recover('job')).serviceState,'APPLIED');assert.equal(f.destination.inspect().effects.length,1);
});
test('cooperative separate cancellation admission reports too late without redispatch',async t=>{
 const f=await fixture(t),g=await f.open();await g.run('job',args);
 assert.equal((await g.cancel('job')).reason,'INSPECTION_DENIED');await f.owner.grant({id:'cancel',to:'bea',actions:['cancel-operation'],resources:[f.operationId],expiresAt:500});
 const cancelled=await g.cancel('job');assert.equal(cancelled.serviceState,'TOO_LATE',JSON.stringify(cancelled));
 assert.ok(f.store.state().intentAdmissions.has(cancellationIdentity(f.local.domain,'synthetic:1')));assert.equal(f.destination.inspect().effects.length,1);
 assert.equal((await g.cancel('job')).cancellationRequestSent,false);
});
test('cooperative auth revocation during signing prevents Core admission and external effects',async t=>{
 const f=await fixture(t);let active=true;const g=await f.open({local:{...f.local,async signHash(h){active=false;return f.local.signHash(h)}}});
 const guard=()=>{if(!active)throw Object.assign(new Error('ACCESS_NOT_CURRENT'),{code:'ACCESS_NOT_CURRENT'})};
 const result=await g.run('job',args,{assertCurrent:guard});assert.equal(result.status,'REFUSED');assert.equal(f.destination.inspect().effects.length,0);assert.equal(f.store.state().intentAdmissions.size,0);
});
test('cooperative Core retirement denies recovery after a prior authorized effect',async t=>{
 const f=await fixture(t),g=await f.open();await f.owner.revoke('tools');await f.owner.grant({id:'new',to:'bea',actions:[f.registry.tools[0].action],resources:[f.registry.tools[0].resource],expiresAt:500});
 const result=await g.run('job',args);assert.equal(result.serviceState,'APPLIED');await f.owner.advanceEpoch({agent:'bea',from:1,to:2});assert.equal((await g.recover('job')).reason,'RUNTIME_NOT_CURRENT');assert.equal(f.destination.inspect().effects.length,1);
});
test('tasks use fixed business identity and recheck authority on cached result and restart',async t=>{
 const f=await fixture(t),g=await f.open(),binding={id:'a',subject:'alice',clientId:'client'},m=createTaskManager({gateway:g,config:f.config,binding,now:()=>100});
 t.after(()=>m.close());let active=true;const guard=()=>{if(!active)throw Object.assign(new Error('ACCESS_NOT_CURRENT'),{code:'ACCESS_NOT_CURRENT'})};
 const started=await m.start('job',args,guard);assert.equal(started.resultType,'task');await m.close();
 const complete=await m.get(started.taskId,guard);assert.equal(complete.status,'completed',JSON.stringify(complete));assert.equal(f.destination.inspect().effects.length,1);
 await assert.rejects(m.start('job',{title:'changed'},guard));active=false;await assert.rejects(m.get(started.taskId,guard));active=true;
 const next=createTaskManager({gateway:g,config:f.config,binding,now:()=>101});assert.equal((await next.get(started.taskId,guard)).status,'completed');assert.equal(f.destination.inspect().effects.length,1);await next.close();
});
test('task handles, capabilities, mirrored protocol version and immutable arguments do not confer authority',async t=>{
 const f=await fixture(t),g=await f.open(),m=createTaskManager({gateway:g,config:f.config,binding:{id:'a',subject:'alice',clientId:'client'},now:()=>100});t.after(()=>m.close());
 const meta={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{extensions:{[TASKS_EXTENSION]:{}}}};
 const req={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'job',arguments:args,_meta:meta}},headers={'mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':'job'};
 assert.ok((await routeTaskRequest(m,req,{...headers,'mcp-name':'other'},()=>{})).error);
 const response=await routeTaskRequest(m,req,headers,()=>{});assert.equal(response.result.resultType,'task');await m.close();
 await assert.rejects(m.get('irontrellis-task:wrong',()=>{}));
});
test('lost cooperative commit reply remains unknown and recovers without redelivery after restart',async t=>{
 const f=await fixture(t),g=await f.open();f.relay.behavior.dropAfter='commit';
 assert.equal((await g.run('job',args)).status,'OUTCOME_UNKNOWN');assert.equal(f.destination.inspect().effects.length,1);await g.close();
 const next=await f.open(),recovered=await next.recover('job');assert.equal(recovered.serviceState,'APPLIED');assert.equal(recovered.dispatchPerformed,false);assert.equal(f.relay.counts.commit,1);assert.equal(f.relay.counts.prepare,1);
});
test('revocation after prepare prevents commit even when replacement grant allows the same operation',async t=>{
 const f=await fixture(t),g=await f.open();f.relay.behavior.after=async operation=>{if(operation==='prepare'){await f.owner.revoke('tools');await f.owner.grant({id:'replacement',to:'bea',actions:[f.registry.tools[0].action],resources:[f.registry.tools[0].resource],expiresAt:500})}};
 assert.equal((await g.run('job',args)).status,'OUTCOME_UNKNOWN');assert.equal(f.relay.counts.prepare,1);assert.equal(f.relay.counts.commit,0);assert.equal(f.destination.inspect().effects.length,0);
 assert.equal((await g.recover('job')).serviceState,'PENDING');
});
test('pending cancellation has its own Core admission and no original redispatch',async t=>{
 const f=await fixture(t),g=await f.open();f.relay.behavior.dropBefore='commit';assert.equal((await g.run('job',args)).status,'OUTCOME_UNKNOWN');
 await f.owner.grant({id:'cancel',to:'bea',actions:['cancel-operation'],resources:[f.operationId],expiresAt:500});
 const result=await g.cancel('job');assert.equal(result.serviceState,'CANCELLED');assert.ok(f.store.state().intentAdmissions.has(result.cancellationId));assert.equal(f.destination.inspect().effects.length,0);
 assert.equal((await g.cancel('job')).cancellationRequestSent,false);assert.equal(f.relay.counts.cancel,1);
});
test('lost cancellation reply stays unknown; signed status recovers without resending cancellation',async t=>{
 const f=await fixture(t),g=await f.open();f.relay.behavior.dropBefore='commit';await g.run('job',args);await f.owner.grant({id:'cancel',to:'bea',actions:['cancel-operation'],resources:[f.operationId],expiresAt:500});
 f.relay.behavior.dropAfter='cancel';assert.equal((await g.cancel('job')).status,'OUTCOME_UNKNOWN');assert.equal((await g.cancel('job')).status,'OUTCOME_UNKNOWN');assert.equal(f.relay.counts.cancel,1);
 assert.equal((await g.recover('job')).serviceState,'CANCELLED');assert.equal(f.relay.counts.cancel,1);
});
test('observation requires separate current authority and records retained report with no dispatch',async t=>{
 const f=await fixture(t),g=await f.open();await g.run('job',args);assert.equal((await g.observe('job')).reason,'INSPECTION_DENIED');
 await f.owner.grant({id:'observe',to:'bea',actions:['OBSERVE_OUTCOME'],resources:[f.operationId],expiresAt:500});
 const result=await g.observe('job');assert.equal(result.status,'OBSERVATION_RECORDED',JSON.stringify(result));assert.equal(result.externalOutcome,'NOT_PROVEN');assert.equal(result.dispatchPerformed,false);assert.equal(f.relay.counts.commit,1);
});
test('task context crossing fails despite same durable task handle',async t=>{
 const f=await fixture(t),g=await f.open(),first=createTaskManager({gateway:g,config:f.config,binding:{id:'a',subject:'alice',clientId:'client'},now:()=>100});
 const result=await first.start('job',args,()=>{});await first.close();const other=createTaskManager({gateway:g,config:f.config,binding:{id:'b',subject:'alice',clientId:'client'},now:()=>100});
 await assert.rejects(other.get(result.taskId,()=>{}));await other.close();assert.equal(f.destination.inspect().effects.length,1);
});
test('asynchronous guards and thenables cannot authorize cooperative work or tasks',async t=>{
 const f=await fixture(t),g=await f.open();
 for(const assertCurrent of [async()=>{},async()=>{throw Error('PRIVATE')},()=>({then(){}}),()=>true])assert.equal((await g.run('job',args,{assertCurrent})).status,'REFUSED');
 const m=createTaskManager({gateway:g,config:f.config,binding:{id:'a',subject:'alice',clientId:'client'},now:()=>100});await assert.rejects(m.start('job',args,async()=>{}));await m.close();assert.equal(f.destination.inspect().effects.length,0);
});
test('manual task routing rejects malformed envelopes and legacy namespaces before admission',async t=>{
 const f=await fixture(t),g=await f.open(),m=createTaskManager({gateway:g,config:f.config,binding:{id:'a',subject:'alice',clientId:'client'},now:()=>100});t.after(()=>m.close());
 const meta={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{extensions:{[TASKS_EXTENSION]:{}}}};
 const base={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'job',arguments:args,_meta:meta}},headers={'mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':'job'};
 for(const req of [{...base,extra:true},{...base,id:null},{...base,params:{...base.params,actor:'other'}},{...base,params:{...base.params,arguments:[]}}, {...base,params:{...base.params,_meta:{...meta,'io.modelcontextprotocol/protocolVersion':'2025-03-26'}}},JSON.parse('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"__proto__":{"name":"job"}}}')]){
  const reply=await routeTaskRequest(m,req,headers,()=>{});assert.ok(reply===null||reply.error);
 }
 assert.equal(await routeTaskRequest(m,{...base,method:'continuity_tasks/get'},headers,()=>{}),null);
 const getter={get method(){throw Error('Should not execute getter')}};assert.ok((await routeTaskRequest(m,getter,headers,()=>{})).error);assert.equal(f.destination.inspect().effects.length,0);
});
test('revocation during checkpoint begin prevents all subsequent private history hops',async t=>{
 const f=await fixture(t),g=await f.open();let active=true;const observed=[];
 f.relay.behavior.before=operation=>observed.push({operation,active});f.relay.behavior.after=operation=>{if(operation==='checkpoint-begin')active=false};
 const result=await g.run('job',args,{assertCurrent(){if(!active)throw Object.assign(Error('ACCESS_NOT_CURRENT'),{code:'ACCESS_NOT_CURRENT'})}});
 assert.equal(result.status,'REFUSED');assert.deepEqual(observed,[{operation:'checkpoint-begin',active:true}]);assert.equal(f.destination.inspect().effects.length,0);
});
test('malformed task JSON-RPC IDs produce null-ID Invalid Request responses',async t=>{
 const f=await fixture(t),g=await f.open(),m=createTaskManager({gateway:g,config:f.config,binding:{id:'a',subject:'alice',clientId:'client'},now:()=>100});t.after(()=>m.close());
 for(const id of [null,true,{},[],1.5]){const response=await routeTaskRequest(m,{jsonrpc:'2.0',id,method:'tasks/get',params:{taskId:'untrusted'}},{},()=>{});assert.equal(response.id,null);assert.equal(response.error.code,-32600)}
 assert.equal(f.destination.inspect().effects.length,0);
});
