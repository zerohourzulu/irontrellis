import {createServer} from 'node:http';
import {AsyncLocalStorage} from 'node:async_hooks';
import {createServer as createHttpsServer} from 'node:https';
import {openConfiguredEventStore} from '@ramex-labs/irontrellis/adapter';
import {createMcpHandler} from '@modelcontextprotocol/server';
import {createGateway} from './gateway.js';
import {createCooperativeGateway} from './cooperative.mjs';
import {acquireHostLease} from './operations.js';
import {createTaskManager,routeTaskRequest} from './tasks.mjs';
import {httpGatewayServer} from './http-server.mjs';
import {createAccessVerifier,issuerUrl} from './access-http.mjs';
import {parseStrictJson} from './strict-json.js';
import {check,id,data,hash,privateDirectory} from './data.js';
import {body,boundary,bodyHeaders,selectedHeaders,resource,metadataUrl,challenge,json,listener,listen,stop,serverOptions,limiter,MAX_BODY} from './http-common.mjs';
import {createAssertionVerifier} from './http-private.mjs';

/** Local evaluation uses HTTP only on IPv4 loopback. Public mode is the explicit mTLS backend below. */
export const serveGatewayHttp=options=>serve(options,false);
/** Private authority half of the canonical HTTPS resource. It accepts only the configured mTLS router peer. */
export const serveGatewayBackend=options=>serve(options,true);
async function serve(options,privateHop){
 const now=options.now??Date.now,issuer=issuerUrl(options.issuer,options.allowTestIssuer);
 check(Array.isArray(options.bindings)&&options.bindings.length>0&&options.bindings.length<=16);
 if(privateHop)check(options.bindings.length===1,'PRIVATE_TENANT_ISOLATION_REQUIRED');
 const bindings=new Map(),histories=new Set(),directories=new Set(),domains=new Set(),credentials=new Set(),gateways=[],leases=[],stores=[],handlers=new Map(),tasks=new Map();
 const limits=limiter(now);let ready=false,canonical=privateHop?resource(options.resource):null,verifier,assertionVerifier;
 let publicMetadata=canonical?metadataUrl(canonical.href):'';
 const transport=listener(handle,()=>publicMetadata);
 const server=privateHop?createHttpsServer({...serverOptions,...options.tls,minVersion:'TLSv1.3',requestCert:true,rejectUnauthorized:true},transport.request):createServer(serverOptions,transport.request);
 async function cleanup(){transport.close();await stop(server);await Promise.allSettled([...tasks.values()].map(t=>t.close()));await Promise.allSettled([...handlers.values()].map(h=>h.close()));await Promise.allSettled(gateways.map(g=>g.close()));for(const store of stores)store.close();for(const lease of leases)lease.release();}
 async function handle(req){
  check(ready,'GATEWAY_UNAVAILABLE');boundary(req,canonical,{privateHop});
  if(privateHop)assertionVerifier.assertPeer(req.socket);
  if(!privateHop&&req.url===new URL(publicMetadata).pathname&&req.method==='GET')return {response:json(200,{resource:canonical.href,authorization_servers:[issuer],scopes_supported:['mcp:access'],bearer_methods_supported:['header'],resource_name:'IronTrellis gateway'})};
  if(req.url!==canonical.pathname)return {response:json(404,{error:'not_found'})};
  const authorization=req.headers.authorization;let access;
  try{check(typeof authorization==='string'&&/^Bearer [A-Za-z0-9_.-]+$/.test(authorization),'ACCESS_NOT_CURRENT');access=await verifier.verify(authorization.slice(7));}
  catch(error){return {response:challenge(publicMetadata,error?.code==='INSUFFICIENT_SCOPE'?'insufficient_scope':'invalid_token')};}
  const context=bindings.get(access.binding.id),guard=()=>{access.assertCurrent();context.assertCore();};guard();bodyHeaders(req);
  const bytes=await body(req,guard),parsed=parseStrictJson(bytes,{maxBytes:MAX_BODY,maxDepth:32,maxNodes:4096});
  check(parsed&&typeof parsed==='object'&&!Array.isArray(parsed));
  if(privateHop)assertionVerifier.verify(req,bytes,access);
  guard();limits(access.binding,parsed);
  const request=new Request(canonical.href,{method:'POST',headers:selectedHeaders(req),body:bytes});
  const taskManager=tasks.get(access.binding.id);
  const taskResponse=taskManager?await context.scope.run(guard,()=>routeTaskRequest(taskManager,parsed,req.headers,guard)):null;guard();
  const response=taskResponse?json(200,taskResponse):await context.scope.run(guard,()=>handlers.get(access.binding.id).fetch(request,{parsedBody:parsed,authInfo:{token:'',clientId:access.binding.clientId,scopes:['mcp:access'],extra:{assertCurrent:guard}}}));
  try{guard();}catch(error){await response.body?.cancel().catch(()=>{});throw error;}
  return {response,guard};
 }
 try{
  for(const input of options.bindings){
   id(input.id);id(input.subject);id(input.clientId);check(!bindings.has(input.id));
   if(privateHop){id(input.tenant);id(input.revision);}
   const config=input.gateway,store=openConfiguredEventStore(config.local);stores.push(store);
   const state=store.state(),session=state.runtimeSessions.get(config.local.session),history=store.path,directory=privateDirectory(config.storage),domain=hash(config.local.domain);
   check(state.format==='irontrellis-event/2'&&session&&session.controllerId===config.local.controller,'PROFILE_MISMATCH');
   const credential=session.credentialScheme+':'+session.credentialAddressKey;
   check(!histories.has(history)&&!directories.has(directory)&&!domains.has(domain)&&!credentials.has(credential),'DUPLICATE_BINDING_CONTEXT');
   histories.add(history);directories.add(directory);domains.add(domain);credentials.add(credential);
   const lease=acquireHostLease(directory);leases.push(lease);
   const binding=data({id:input.id,subject:input.subject,clientId:input.clientId,tenant:input.tenant??input.id,revision:input.revision??hash({domain,history,session:session.id})});
   const coreNow=config.local.now;
   const assertCore=()=>{
    lease.assertOwned();const current=store.state(),at=coreNow(),agent=current.agents.get(session.agentId),currentSession=current.runtimeSessions.get(session.id);
    check(hash(current.genesis.domain)===domain&&currentSession?.admissionEventId===session.admissionEventId,'RUNTIME_NOT_CURRENT');
    check(Number.isSafeInteger(at)&&at>=current.head.canonicalTime&&agent&&!agent.terminated&&agent.currentControlEpoch===session.controlEpoch&&(session.expiresAt===undefined||at<session.expiresAt),'RUNTIME_NOT_CURRENT');
   };
   assertCore();check(input.kind===undefined||input.kind==='cooperative');
   const scope=new AsyncLocalStorage();
   const guardedSigner=signHash=>async h=>{const guard=scope.getStore();check(typeof guard==='function','ACCESS_NOT_CURRENT');guard();const signed=await signHash(h);guard();return signed;};
   const guardedConfig={...config,local:{...config.local,signHash:guardedSigner(config.local.signHash)},...(config.connectorSigner?{connectorSigner:{...config.connectorSigner,signHash:guardedSigner(config.connectorSigner.signHash)}}:{})};
   const gateway=await (input.kind==='cooperative'?createCooperativeGateway:createGateway)(guardedConfig);gateways.push(gateway);
   bindings.set(binding.id,{binding,assertCore,scope});
   check(input.tasks===undefined||input.tasks===true);check(!input.tasks||input.kind==='cooperative');
   if(input.tasks)tasks.set(binding.id,createTaskManager({gateway,config,binding,now,assertOwned:assertCore}));
   handlers.set(binding.id,createMcpHandler(ctx=>{
    const assertCurrent=ctx.authInfo?.extra?.assertCurrent;check(typeof assertCurrent==='function','ACCESS_NOT_CURRENT');
    return httpGatewayServer(gateway,{tasks:input.tasks===true,assertCurrent});
   },{legacy:'reject',responseMode:'json',maxSubscriptions:0,onerror:()=>{}}));
  }
  if(privateHop)assertionVerifier=createAssertionVerifier({...options.privateChannel,now,resource:canonical.href});
  await listen(server,{port:options.port??0,host:privateHop?(options.host??'127.0.0.1'):'127.0.0.1'});
  if(!privateHop){canonical=resource(`http://127.0.0.1:${server.address().port}/mcp`,{test:true});publicMetadata=metadataUrl(canonical.href);}
  verifier=await createAccessVerifier({issuer,keys:options.keys,resource:canonical.href,bindings:new Map([...bindings].map(([k,v])=>[k,v.binding])),isActive:options.isActive,now});ready=true;
  return Object.freeze({resourceUrl:canonical.href,metadataUrl:publicMetadata,port:server.address().port,close:cleanup});
 }catch(error){await cleanup();throw error;}
}
export {serveGatewayRouter} from './http-router.mjs';
