import {mkdtempSync,rmSync,mkdirSync,copyFileSync,readFileSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,basename} from 'node:path';
import {randomUUID} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {createDemoCase} from '../dist/demo.js';
import {serveGatewayHttp} from '../dist/http.mjs';
export async function testIssuer(now=Date.now){
 const {privateKey,publicKey}=await generateKeyPair('ES256'),jwk={...await exportJWK(publicKey),kid:'synthetic',alg:'ES256',use:'sig'},issuer='https://issuer.test/';
 return {issuer,keys:[jwk],privateKey,async issue(resource,claims={},header={}){const at=Math.floor(now()/1000);return new SignJWT({iss:issuer,aud:resource,sub:'alice',client_id:'example-client',irontrellis_binding:'agent-a',scope:'mcp:access',iat:at,exp:at+300,jti:randomUUID(),...claims}).setProtectedHeader({alg:'ES256',typ:'at+jwt',kid:jwk.kid,...header}).sign(privateKey);}};
}
export async function fixture(t,customize=()=>{}){
 const root=mkdtempSync(join(tmpdir(),'irontrellis-http-')),clients=[],cases=[];let clock=Date.now(),active=true,policy=()=>active,service;
 const issuer=await testIssuer(()=>clock),revoked=new Set();
 for(const name of ['a','b'])cases.push(await createDemoCase(join(root,name)));
 const bindings=cases.map((f,i)=>({id:'agent-'+['a','b'][i],subject:'alice',clientId:'example-client',gateway:{...f.config,local:f.local,connectorSigner:f.connectorSigner}}));
 const config={issuer:issuer.issuer,keys:issuer.keys,bindings,isActive:i=>{const result=policy(i);return result===true?!revoked.has(i.tokenId):result},now:()=>clock};
 t.after(async()=>{await Promise.allSettled(clients.map(c=>c.close()));await service?.close();
  if(process.env.IRONTRELLIS_TEST_HISTORY_DIR){const directory=resolve(process.env.IRONTRELLIS_TEST_HISTORY_DIR);mkdirSync(directory,{recursive:true});for(const [i,c]of cases.entries())copyFileSync(c.local.historyFile,join(directory,t.name.replace(/[^a-zA-Z0-9]+/g,'-')+'-'+basename(root)+'-'+i+'.jsonl'));}
  rmSync(root,{recursive:true,force:true});});
 customize({config,cases,disable:()=>{active=false},setClock:v=>{clock=v},setPolicy:p=>{policy=p}});service=await serveGatewayHttp(config);
 return {root,cases,issuer,bindings,config,get service(){return service},revoked,disable:()=>{active=false},enable:()=>{active=true},advance:(n=12000)=>{clock+=n},clock:()=>clock,setClock:v=>{clock=v},setPolicy:p=>{policy=p},
  token:(claims={},header={})=>issuer.issue(service.resourceUrl,claims,header),
  count:i=>{const p=join(cases[i].directory,'tickets.calls.jsonl');return existsSync(p)?readFileSync(p,'utf8').trim().split('\n').length:0},
  async raw(token,{path='/mcp',headers={},method='POST',body='{}'}={}){return fetch(new URL(path,service.resourceUrl),{method,headers:{'content-type':'application/json',accept:'application/json, text/event-stream',...(token?{authorization:'Bearer '+token}:{}),...headers},...(method==='POST'?{body}:{})})},
  async client(token,extra={}){const c=new Client({name:'untrusted-client',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});clients.push(c);await c.connect(new StreamableHTTPClientTransport(new URL(service.resourceUrl),{requestInit:{headers:{Authorization:'Bearer '+token,...extra}}}));return c},
  async call(c,name='create_incident_ticket',args={title:'Synthetic ticket'}){const tools=await c.listTools({cursor:''},{cacheMode:'refresh'}),definition=tools.tools.find(t=>t.name===name);return (await c.callTool({name,arguments:args},{toolDefinition:definition})).structuredContent},
  async restart(){const port=service.port;await service.close();service=await serveGatewayHttp({...config,port})},
 };
}
