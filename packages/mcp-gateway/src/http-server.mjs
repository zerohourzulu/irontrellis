import {assertSynchronous} from './access-http-guard.mjs';
import {Server} from '@modelcontextprotocol/server';
import {catalog,reply,SERVER_INFO} from './server.js';
/** Request-local guard applies to catalog, inspection and every asynchronous result. */
export function httpGatewayServer(gateway,{tasks=false,assertCurrent}={}){
 const server=new Server(SERVER_INFO,{capabilities:{tools:{},...(tasks?{extensions:{'io.modelcontextprotocol/tasks':{}}}:{})}});
 const recovery=[['recover','irontrellis_recover'],['cancel','irontrellis_cancel'],['observe','irontrellis_observe']].filter(([method])=>typeof gateway[method]==='function');
 const tools=()=>{
  assertSynchronous(assertCurrent);
  const base=catalog({...gateway,mode:gateway.mode??'exactly-once'});
  for(const [method,name] of recovery)base.push({name,description:method==='recover'?'Inspect the original attempt without redelivery.':method==='cancel'?'Separately authorized cancellation; does not undo prior effects.':'Record the retained authenticated report; it is not proof of external effect.',
   inputSchema:{type:'object',properties:{job:{type:'string',enum:gateway.tools().map(t=>t.name)}},required:['job'],additionalProperties:false},annotations:{readOnlyHint:method==='recover',destructiveHint:method!=='recover',openWorldHint:true,idempotentHint:true}});
  return base;
 };
 server.setRequestHandler('tools/list',()=>({tools:tools()}));
 server.setRequestHandler('tools/call',async({params})=>{
  assertSynchronous(assertCurrent);const args=params.arguments??{},name=params.name;
  const method=recovery.find(([,n])=>n===name)?.[0];let result;
  if(method||name==='irontrellis_status'||name==='irontrellis_why'){
   const allowed=name==='irontrellis_why'?['job','arguments']:['job'];
   if(typeof args.job!=='string'||Object.keys(args).some(k=>!allowed.includes(k)))result={status:'REFUSED',reason:'INVALID_ARGUMENTS'};
   else if(method)result=await gateway[method](args.job,{assertCurrent});
   else if(name==='irontrellis_status'&&gateway.mode!=='per-call')result=gateway.status(args.job);
   else if(name==='irontrellis_why')result=gateway.why(args.job,args.arguments);
   else result={status:'REFUSED',reason:'UNKNOWN_TOOL'};
  }else result=await gateway.run(name,args,{assertCurrent});
  assertSynchronous(assertCurrent);return server.projectCallToolResult(reply(result),undefined);
 });return server;
}
