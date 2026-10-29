// Port of the pinned-key Continuity verifier. No token-derived network lookup.
import {importJWK,jwtVerify} from 'jose';
import {parseStrictJson} from './strict-json.js';
import {check,data,exact,id} from './data.js';
export {issuerUrl} from './access-policy.js';

export async function createAccessVerifier({issuer,keys,resource,bindings,isActive,now=Date.now}) {
 check(typeof isActive==='function'&&typeof now==='function');
 const publicKeys=new Map(),fixed=new Map();
 for(const [key,value] of bindings){const binding=data(value);check(key===binding.id&&!fixed.has(key));fixed.set(key,binding);}
 check(Array.isArray(keys)&&keys.length>0&&keys.length<=8);
 for(const raw of keys){
  const key=exact(data(raw),['kty','crv','x','y','kid'],['alg','use']);id(key.kid);
  check(key.kty==='EC'&&key.crv==='P-256'&&(!key.alg||key.alg==='ES256')&&(!key.use||key.use==='sig')&&!publicKeys.has(key.kid));
  publicKeys.set(key.kid,await importJWK(key,'ES256'));
 }
 let last=0;
 function time(){const value=now();check(Number.isSafeInteger(value)&&value>=last,'ACCESS_NOT_CURRENT');last=value;return Math.floor(value/1000);}
 function current(claims,identity){
  const at=time();check(at>=claims.iat&&at<claims.exp&&(claims.nbf===undefined||at>=claims.nbf),'ACCESS_NOT_CURRENT');
  const active=isActive(identity);
  if(active instanceof Promise)void active.catch(()=>{});
  check(active===true,'ACCESS_NOT_CURRENT');
 }
 return Object.freeze({async verify(token){
  check(typeof token==='string'&&token.length<=8192,'ACCESS_NOT_CURRENT');
  const parts=token.split('.');check(parts.length===3&&parts.every(p=>/^[A-Za-z0-9_-]+$/.test(p)),'ACCESS_NOT_CURRENT');
  const decode=p=>{const bytes=Buffer.from(p,'base64url');check(bytes.toString('base64url')===p,'ACCESS_NOT_CURRENT');return parseStrictJson(bytes,{maxBytes:8192,maxDepth:8,maxNodes:128});};
  const header=exact(decode(parts[0]),['alg','typ','kid']);
  check(header.alg==='ES256'&&header.typ==='at+jwt'&&publicKeys.has(header.kid),'ACCESS_NOT_CURRENT');
  exact(decode(parts[1]),['iss','sub','aud','exp','iat','jti','client_id','scope','irontrellis_binding'],['nbf']);
  const {payload}=await jwtVerify(token,publicKeys.get(header.kid),{algorithms:['ES256'],issuer,audience:resource,typ:'at+jwt',
   requiredClaims:['iss','sub','aud','exp','iat','jti','client_id','scope','irontrellis_binding'],currentDate:new Date(time()*1000),clockTolerance:0});
  const claims=data(payload);
  check(claims.iss===issuer&&claims.aud===resource&&Number.isSafeInteger(claims.exp)&&Number.isSafeInteger(claims.iat)&&claims.iat>=0&&claims.exp>claims.iat&&claims.exp-claims.iat<=300,'ACCESS_NOT_CURRENT');
  if(claims.nbf!==undefined)check(Number.isSafeInteger(claims.nbf),'ACCESS_NOT_CURRENT');
  for(const key of ['sub','client_id','jti','irontrellis_binding'])id(claims[key]);
  const binding=fixed.get(claims.irontrellis_binding);
  check(binding&&binding.subject===claims.sub&&binding.clientId===claims.client_id,'ACCESS_NOT_CURRENT');
  check(typeof claims.scope==='string'&&/^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/.test(claims.scope)&&claims.scope.split(' ').includes('mcp:access'),'INSUFFICIENT_SCOPE');
  const identity=Object.freeze({issuer,subject:claims.sub,clientId:claims.client_id,bindingId:binding.id,tokenId:claims.jti});
  current(claims,identity);
  return Object.freeze({binding,identity,expiresAt:claims.exp,assertCurrent:()=>current(claims,identity)});
 }});
}
