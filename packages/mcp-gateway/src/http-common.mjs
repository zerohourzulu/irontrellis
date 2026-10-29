import {assertSynchronous} from './access-http-guard.mjs';
import {createHash} from 'node:crypto';
import {check} from './data.js';
export const MAX_BODY=32768,MAX_RESPONSE=262144;
export const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
export const json=(status,value,headers={})=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json','cache-control':'no-store',...headers}});
export const challenge=(metadata,code='invalid_token')=>json(code==='insufficient_scope'?403:401,{error:code},{'www-authenticate':`Bearer resource_metadata="${metadata}", scope="mcp:access", error="${code}"`});
export function resource(value,{test=false}={}){
 const url=new URL(value);check(url.href===value&&!url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==='/mcp');
 check(url.protocol==='https:'||(test&&url.protocol==='http:'&&url.hostname==='127.0.0.1'));return url;
}
export const metadataUrl=value=>new URL('/.well-known/oauth-protected-resource/mcp',value).href;
export function boundary(req,canonical,{privateHop=false}={}){
 const seen=new Set();
 for(let i=0;i<req.rawHeaders.length;i+=2){const key=req.rawHeaders[i].toLowerCase();check(!seen.has(key),'INVALID_HEADERS');seen.add(key);}
 check(req.headers.host===canonical.host,'INVALID_HOST');
 check(req.headers.origin===undefined||req.headers.origin===canonical.origin,'INVALID_ORIGIN');
 check(!req.headers['transfer-encoding']||!req.headers['content-length'],'INVALID_HEADERS');
 check(typeof req.url==='string'&&req.url.startsWith('/')&&!req.url.startsWith('//')&&!req.url.includes('?')&&!req.url.includes('#')&&!req.url.includes('%'),'INVALID_PATH');
 if(req.socket.encrypted&&req.socket.servername)check(req.socket.servername===canonical.hostname||privateHop,'INVALID_HOST');
 // Ingress forwarding and identity headers are stripped: none survives selectedHeaders.
 if(!privateHop)check(req.headers['irontrellis-request-assertion']===undefined,'INVALID_HEADERS');
}
export const selectedHeaders=req=>Object.fromEntries(['accept','content-type','mcp-protocol-version','mcp-method','mcp-name','origin'].filter(k=>typeof req.headers[k]==='string').map(k=>[k,req.headers[k]]));
export function bodyHeaders(req){
 check(req.method==='POST','METHOD_NOT_ALLOWED');
 check(/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type']??''),'CONTENT_TYPE');
 check(req.headers['content-encoding']===undefined,'CONTENT_TYPE');
 check(req.headers['content-length']===undefined||/^\d+$/.test(req.headers['content-length']),'INVALID_HEADERS');
 check(Number(req.headers['content-length']??0)<=MAX_BODY,'REQUEST_LIMIT');
}
export async function body(req,guard=()=>{}){
 assertSynchronous(guard);const chunks=[];let size=0;
 const timer=setTimeout(()=>req.destroy(),3000);timer.unref();
 try{for await(const chunk of req){assertSynchronous(guard);size+=chunk.length;check(size<=MAX_BODY,'REQUEST_LIMIT');chunks.push(chunk);}assertSynchronous(guard);return Buffer.concat(chunks);}
 finally{clearTimeout(timer);}
}
export async function send(res,response,guard=()=>{}){
 const reader=response.body?.getReader(),chunks=[];let size=0;
 assertSynchronous(guard);if(reader)try{while(true){const {value,done}=await reader.read();assertSynchronous(guard);if(done)break;size+=value.length;check(size<=MAX_RESPONSE,'RESPONSE_LIMIT');chunks.push(value);}}
 catch(error){await reader.cancel().catch(()=>{});throw error;}
 assertSynchronous(guard);if(res.destroyed)return;
 res.writeHead(response.status,{...Object.fromEntries(response.headers),'cache-control':'no-store','x-content-type-options':'nosniff'});res.end(Buffer.concat(chunks));
}
export const failure=(error,metadata)=>{
 const code=error?.code;
 if(code==='ACCESS_NOT_CURRENT'||code==='INSUFFICIENT_SCOPE')return challenge(metadata,code==='INSUFFICIENT_SCOPE'?'insufficient_scope':'invalid_token');
 if(code==='INVALID_HOST'||code==='INVALID_ORIGIN')return json(403,{error:'invalid_request'});
 if(code==='METHOD_NOT_ALLOWED')return json(405,{error:'method_not_allowed'},{allow:'POST'});
 if(code==='CONTENT_TYPE')return json(415,{error:'content_type'});
 if(code==='REQUEST_LIMIT')return json(413,{error:'request_limit'});
 if(code==='RATE_LIMIT')return json(429,{error:'rate_limit'},{'retry-after':'12'});
 return json(400,{error:'invalid_request'});
};
export function listener(handle,metadata){
 let active=0,closing=false;
 return {async request(req,res){
  if(closing||active>=8){res.writeHead(503,{'connection':'close'});res.end();return;}
  active++;
  try{const {response,guard}=await handle(req);await send(res,response,guard);}
  catch(error){if(!res.headersSent&&!res.destroyed)await send(res,failure(error,metadata())).catch(()=>res.destroy());else res.destroy();}
  finally{active--;}
 },close(){closing=true;}};
}
export const serverOptions={maxHeaderSize:16384,requestTimeout:10000,headersTimeout:10000,keepAliveTimeout:1000};
export async function listen(server,{port=0,host='127.0.0.1'}={}){
 check(Number.isInteger(port)&&port>=0&&port<=65535);server.maxConnections=32;
 server.on('clientError',(_error,socket)=>socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'));
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>{server.removeListener('error',reject);resolve();});});
}
export async function stop(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
export function limiter(now){
 const buckets=new Map();let last=0;
 return (binding,parsed)=>{const at=now();check(Number.isSafeInteger(at)&&at>=last,'ACCESS_NOT_CURRENT');last=at;
  const mutation=parsed.method==='tools/call'&&!['irontrellis_status','irontrellis_why','irontrellis_recover'].includes(parsed.params?.name)||parsed.method==='tasks/cancel';
  for(const kind of mutation?['request','mutation']:['request']){
   const key=binding.id+':'+kind,capacity=kind==='request'?5:1,period=kind==='request'?2000:12000;
   const previous=buckets.get(key)??{tokens:capacity,at};const tokens=Math.min(capacity,previous.tokens+(at-previous.at)/period);
   check(tokens>=1,'RATE_LIMIT');buckets.set(key,{tokens:tokens-1,at});
  }
 };
}
