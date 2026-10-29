import { preserveHistories } from './preserve.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createAgent,createMiddleware,fakeModel,AIMessage} from 'langchain';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {createDemo} from '@ramex-labs/irontrellis-protected-evidence-mcp/setup';
import {evidenceTool} from '../tool.mjs';
async function setup(t){const root=mkdtempSync(join(tmpdir(),'irontrellis-framework-'));t.after(() => { preserveHistories(root); rmSync(root, {recursive:true,force:true}); });
 const demo=await createDemo(join(root,'case')),client=new Client({name:'actual-langchain-test',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});t.after(()=>client.close());
 await client.connect(new StdioClientTransport({command:process.execPath,args:[fileURLToPath(new URL(import.meta.resolve('@ramex-labs/irontrellis-protected-evidence-mcp/server'))),'--config',demo.configFile],stderr:'pipe'}));return{...demo,client};}
function model(args={resource:'incident:42'}){return fakeModel().respondWithTools([{name:'collect_evidence',args,id:'transport-call-not-operation'}]).respond(new AIMessage('Done.'));}
const answer=result=>JSON.parse(result.messages.find(m=>m.getType()==='tool').content);
test('actual framework agent dispatch reaches protected MCP, not a manual fake hook',async t=>{
 const {client,owner}=await setup(t);const scripted=model();const agent=createAgent({model:scripted,tools:[evidenceTool(client,{operationId:'framework:42',resource:'incident:42'})]});
 const result=await agent.invoke({messages:[{role:'user',content:'Collect.'}]},{recursionLimit:6});assert.equal(answer(result).status,'RECORDED');assert.equal(scripted.callCount,2);
 assert.equal(owner.exportHistory().filter(e=>e.type==='TRANSACTION_INTENT_CONSUMED').length,1);
});
test('wrapToolCall retry preserves the application operation ID and does not duplicate the effect',async t=>{
 const {client,owner,config}=await setup(t);let calls=0;
 const retry=createMiddleware({name:'ExplicitRetryTest',wrapToolCall:async(request,handler)=>{await handler(request);calls++;const result=await handler(request);calls++;return result}});
 const agent=createAgent({model:model(),middleware:[retry],tools:[evidenceTool(client,{operationId:'retry:42',resource:'incident:42'})]});
 const result=await agent.invoke({messages:[{role:'user',content:'Collect.'}]},{recursionLimit:6});assert.equal(calls,2);assert.equal(answer(result).status,'RECONCILIATION_ONLY');
 assert.equal(owner.exportHistory().filter(e=>e.type==='TRANSACTION_INTENT_CONSUMED').length,1);assert.equal(readdirSync(config.outputDirectory).length,1);
});
test('framework cannot grant a retired session a new effect',async t=>{
 const {client,owner,config}=await setup(t);await owner.advanceEpoch({agent:'bea',from:1,to:2});
 const agent=createAgent({model:model(),tools:[evidenceTool(client,{operationId:'obsolete:42',resource:'incident:42'})]});
 const result=await agent.invoke({messages:[{role:'user',content:'Collect.'}]},{recursionLimit:6});assert.equal(answer(result).reason,'RUNTIME_NOT_CURRENT');assert.deepEqual(readdirSync(config.outputDirectory),[]);
});
test('the model cannot replace the host-owned operation ID through tool arguments',async t=>{
 const {client,config}=await setup(t);const agent=createAgent({model:model({resource:'incident:42',operationId:'invented'}),tools:[evidenceTool(client,{operationId:'host:42',resource:'incident:42'})]});
 await agent.invoke({messages:[{role:'user',content:'Collect.'}]},{recursionLimit:6});assert.deepEqual(readdirSync(config.outputDirectory),[]);
});
