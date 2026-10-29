import {mkdtempSync,readFileSync,writeFileSync,mkdirSync,rmSync,realpathSync,copyFileSync} from 'node:fs';
import {join,basename} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {X509Certificate,createHash,generateKeyPairSync,sign} from 'node:crypto';
import {request,Agent} from 'node:https';
import {createDemoCase} from '../dist/demo.js';
import {serveGatewayBackend} from '../dist/http.mjs';
import {serveGatewayRouter} from '../dist/http-router.mjs';
import {createAccessVerifier} from '../dist/access-http.mjs';
import {createRequestAssertion} from '../dist/http-private.mjs';
import {testIssuer} from './http-test-helpers.mjs';
const read=p=>readFileSync(p);
function certificates(root){
 const run=args=>execFileSync('openssl',args,{stdio:'ignore'});
 run(['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(root,'ca.key'),'-out',join(root,'ca.pem'),'-days','2','-subj','/CN=synthetic-local-test-ca']);
 const result={ca:read(join(root,'ca.pem'))};
 for(const [name,san,usage]of [['public','DNS:gateway.test','serverAuth'],['backend','DNS:localhost,IP:127.0.0.1','serverAuth'],['client','DNS:router.internal','clientAuth'],['rogue','DNS:unapproved.internal','clientAuth']]){
  const key=join(root,name+'.key'),csr=join(root,name+'.csr'),cert=join(root,name+'.pem'),ext=join(root,name+'.ext');
  run(['req','-new','-newkey','rsa:2048','-nodes','-keyout',key,'-out',csr,'-subj','/CN='+name]);
  writeFileSync(ext,'subjectAltName='+san+'\nextendedKeyUsage='+usage+'\n');
  run(['x509','-req','-in',csr,'-CA',join(root,'ca.pem'),'-CAkey',join(root,'ca.key'),'-CAcreateserial','-out',cert,'-days','2','-extfile',ext]);
  result[name]={key:read(key),cert:read(cert),fingerprint:createHash('sha256').update(new X509Certificate(read(cert)).raw).digest('hex')};
 }return result;
}
export const protocol='2026-07-28';
export function message(method='tools/list',params={cursor:''}){return {jsonrpc:'2.0',id:1,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':protocol,'io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'test',version:'1'}}}};}
export async function tlsFixture(t,customize=()=>{}){
 const root=realpathSync(mkdtempSync(join(tmpdir(),'irontrellis-twohop-'))),tls=certificates(root),issuer=await testIssuer(()=>clock),assertion=generateKeyPairSync('ed25519'),f=await createDemoCase(join(root,'tenant'));
 const resource='https://gateway.test/mcp',binding={id:'agent-a',subject:'alice',clientId:'example-client',tenant:'tenant-a',revision:'mapping-1'};
 const extraCleanup=[];let routerActive=true,backendActive=true,clock=Date.now(),backend,router;
 const nonceDirectory=join(root,'nonces');mkdirSync(nonceDirectory,{mode:0o700});
 const backendOptions={resource,issuer:issuer.issuer,keys:issuer.keys,bindings:[{...binding,gateway:{...f.config,local:f.local,connectorSigner:f.connectorSigner}}],now:()=>clock,isActive:()=>backendActive,
  tls:{...tls.backend,ca:tls.ca},privateChannel:{peerFingerprint:tls.client.fingerprint,assertionPublicKey:assertion.publicKey,nonceDirectory,servername:'localhost'}};
 customize({backendOptions,f,denyBackend:()=>{backendActive=false},denyRouter:()=>{routerActive=false}});
 backend=await serveGatewayBackend(backendOptions);
 const routerOptions={resource,issuer:issuer.issuer,keys:issuer.keys,now:()=>clock,isActive:()=>routerActive,bindings:[{...binding,backend:{url:`https://127.0.0.1:${backend.port}/mcp`,servername:'localhost',peerFingerprint:tls.backend.fingerprint}}],tls:tls.public,
  privateChannel:{...tls.client,ca:tls.ca,assertionPrivateKey:assertion.privateKey}};
 router=await serveGatewayRouter(routerOptions);
 const agent=new Agent({keepAlive:true,maxSockets:1});t.after(async()=>{agent.destroy();await router?.close();await backend?.close();for(const cleanup of extraCleanup)await cleanup();if(process.env.IRONTRELLIS_TEST_HISTORY_DIR){mkdirSync(process.env.IRONTRELLIS_TEST_HISTORY_DIR,{recursive:true});copyFileSync(f.local.historyFile,join(process.env.IRONTRELLIS_TEST_HISTORY_DIR,t.name.replace(/[^a-zA-Z0-9]+/g,'-')+'-'+basename(root)+'.jsonl'))}rmSync(root,{recursive:true,force:true})});
 const token=claims=>issuer.issue(resource,claims);
 const verifier=await createAccessVerifier({issuer:issuer.issuer,keys:issuer.keys,resource,bindings:new Map([[binding.id,binding]]),isActive:()=>true,now:()=>clock});
 async function send({privateHop=false,token:bearer,object=message(),headers={},assertionHeader,mutate,rawBytes,client=tls.client,agent:givenAgent=false,assertionAccess,signingKey=assertion.privateKey,path='/mcp'}={}){
  const bytes=rawBytes??Buffer.from(JSON.stringify(object)),selected={'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':protocol,'mcp-method':object.method,...(object.params?.name?{'mcp-name':object.params.name}:{}),...headers};
  const access=privateHop&&bearer?(assertionAccess??await verifier.verify(bearer)):undefined;
  return new Promise((resolve,reject)=>{
   const r=request({hostname:'127.0.0.1',port:privateHop?backend.port:router.port,path,method:'POST',servername:privateHop?'localhost':'gateway.test',ca:tls.ca,...(privateHop?{key:client.key,cert:client.cert}:{}),agent:givenAgent,
    headers:{...selected,host:'gateway.test',...(bearer?{authorization:'Bearer '+bearer}:{}),'content-length':bytes.length}},res=>{const parts=[];res.on('data',p=>parts.push(p));res.on('end',()=>{const text=Buffer.concat(parts).toString();resolve({status:res.statusCode,headers:res.headers,text,json:()=>JSON.parse(text)})});res.on('error',reject)});
   r.on('error',reject);r.on('socket',socket=>{
    const ready=()=>{try{
     if(privateHop&&access){let value=assertionHeader??createRequestAssertion({resource,method:'POST',path,headers:selected,bytes,access,socket,now:()=>clock},signingKey);
      if(mutate){const row=JSON.parse(Buffer.from(value.split('.')[0],'base64url'));mutate(row);const b=Buffer.from(JSON.stringify(row));value=b.toString('base64url')+'.'+sign(null,b,signingKey).toString('base64url')}
      r.setHeader('irontrellis-request-assertion',value);send.lastAssertion=value;
     }r.end(bytes);
    }catch(error){r.destroy(error)}};
    if(socket.connecting)socket.once('secureConnect',ready);else ready();
   });
  });
 }
 return {onCleanup:fn=>extraCleanup.push(fn),root,tls,assertion,binding,backendOptions,routerOptions,f,token,send,agent,resource,nonceDirectory,denyBackend:()=>{backendActive=false},denyRouter:()=>{routerActive=false},advance:()=>{clock+=12000},get backend(){return backend},get router(){return router},async restartRouter(changes={}){await router.close();router=await serveGatewayRouter({...routerOptions,...changes})}};
}
