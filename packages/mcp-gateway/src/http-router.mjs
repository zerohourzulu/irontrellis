import {createServer,request as httpsRequest} from 'node:https';
import {checkServerIdentity} from 'node:tls';
import {isIP} from 'node:net';
import {createAccessVerifier,issuerUrl} from './access-http.mjs';
import {check,id,data} from './data.js';
import {parseStrictJson} from './strict-json.js';
import {createRequestAssertion,fingerprint} from './http-private.mjs';
import {body,boundary,bodyHeaders,selectedHeaders,resource,metadataUrl,challenge,json,listener,listen,stop,serverOptions,limiter,MAX_BODY,MAX_RESPONSE} from './http-common.mjs';

/** Thin canonical HTTPS router. Configuration contains no Core signer or history. */
export async function serveGatewayRouter(options){
 const canonical=resource(options.resource),metadata=metadataUrl(canonical.href),issuer=issuerUrl(options.issuer,options.allowTestIssuer),now=options.now??Date.now;
 check(Array.isArray(options.bindings)&&options.bindings.length>0&&options.bindings.length<=16);
 const bindings=new Map(),routes=new Map(),limits=limiter(now);
 for(const raw of options.bindings){
  const binding=data({id:raw.id,subject:raw.subject,clientId:raw.clientId,tenant:raw.tenant,revision:raw.revision});for(const v of Object.values(binding))id(v);check(!bindings.has(binding.id));
  const url=new URL(raw.backend.url);check(url.protocol==='https:'&&url.href===raw.backend.url&&!url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==='/mcp'&&isIP(url.hostname),'INVALID_BACKEND');
  check(/^[a-f0-9]{64}$/.test(raw.backend.peerFingerprint));
  bindings.set(binding.id,binding);routes.set(binding.id,Object.freeze({...raw.backend,url}));
 }
 const verifier=await createAccessVerifier({issuer,keys:options.keys,resource:canonical.href,bindings,isActive:options.isActive,now});
 const transport=listener(handle,()=>metadata);
 const server=createServer({...serverOptions,...options.tls,minVersion:'TLSv1.3',requestCert:false},transport.request);
 async function forward(req,bytes,access){
  const route=routes.get(access.binding.id),headers={...selectedHeaders(req),host:canonical.host,authorization:req.headers.authorization,'content-length':String(bytes.length)};
  access.assertCurrent();
  const response=await new Promise((resolve,reject)=>{
   const pending=httpsRequest(route.url,{method:'POST',headers,agent:false,key:options.privateChannel.key,cert:options.privateChannel.cert,ca:options.privateChannel.ca,minVersion:'TLSv1.3',rejectUnauthorized:true,
    ...(route.servername?{servername:route.servername}:{}),checkServerIdentity(host,cert){const error=checkServerIdentity(host,cert);if(error)return error;return undefined;}},res=>{
     const chunks=[];let size=0;
     res.on('data',chunk=>{try{access.assertCurrent();size+=chunk.length;check(size<=MAX_RESPONSE,'RESPONSE_LIMIT');chunks.push(chunk);}catch(error){res.destroy(error);}});
     res.on('error',reject);res.on('end',()=>{try{access.assertCurrent();check(!res.headers['content-encoding']&&res.headers['content-type']?.startsWith('application/json'),'PRIVATE_RESPONSE_INVALID');
      resolve(new Response(Buffer.concat(chunks),{status:res.statusCode,headers:{'content-type':'application/json',...(res.headers['www-authenticate']?{'www-authenticate':res.headers['www-authenticate']}:{}),...(res.headers['retry-after']?{'retry-after':res.headers['retry-after']}:{})}}));}catch(error){reject(error);}});
    });
   pending.on('error',reject);pending.setTimeout(30000,()=>pending.destroy(Object.assign(new Error('PRIVATE_TIMEOUT'),{code:'PRIVATE_TIMEOUT'})));
   pending.on('socket',socket=>socket.once('secureConnect',()=>{
    try{access.assertCurrent();check(socket.authorized&&fingerprint(socket)===route.peerFingerprint,'PRIVATE_CHANNEL_REQUIRED');
     const assertion=createRequestAssertion({resource:canonical.href,method:'POST',path:canonical.pathname,headers:selectedHeaders(req),bytes,access,socket,now},options.privateChannel.assertionPrivateKey);
     pending.setHeader('irontrellis-request-assertion',assertion);access.assertCurrent();pending.end(bytes);
    }catch(error){pending.destroy(error);}
   }));
  });access.assertCurrent();return response;
 }
 async function handle(req){
  boundary(req,canonical);
  if(req.url===new URL(metadata).pathname&&req.method==='GET')return {response:json(200,{resource:canonical.href,authorization_servers:[issuer],scopes_supported:['mcp:access'],bearer_methods_supported:['header'],resource_name:'IronTrellis gateway'})};
  if(req.url!==canonical.pathname)return {response:json(404,{error:'not_found'})};
  let access;try{const auth=req.headers.authorization;check(typeof auth==='string'&&/^Bearer [A-Za-z0-9_.-]+$/.test(auth),'ACCESS_NOT_CURRENT');access=await verifier.verify(auth.slice(7));}
  catch(error){return {response:challenge(metadata,error?.code==='INSUFFICIENT_SCOPE'?'insufficient_scope':'invalid_token')};}
  bodyHeaders(req);const bytes=await body(req,access.assertCurrent),parsed=parseStrictJson(bytes,{maxBytes:MAX_BODY,maxDepth:32,maxNodes:4096});
  check(parsed&&typeof parsed==='object'&&!Array.isArray(parsed));access.assertCurrent();limits(access.binding,parsed);
  return {response:await forward(req,bytes,access),guard:access.assertCurrent};
 }
 try{await listen(server,{port:options.port??0,host:options.host??'127.0.0.1'});return Object.freeze({resourceUrl:canonical.href,metadataUrl:metadata,port:server.address().port,async close(){transport.close();await stop(server);}});}
 catch(error){transport.close();await stop(server);throw error;}
}
