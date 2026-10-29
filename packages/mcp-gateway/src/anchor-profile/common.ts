import {canonicalEncode,captureValue,hashCanonical,parseStrictJson} from '@ramex-labs/irontrellis';
import type {ContentHash} from '@ramex-labs/irontrellis';
export const MAX_CODEC_BYTES=16777216;
export const requireValue=(ok:unknown,reason:string):void=>{if(!ok)throw new Error(reason)};
export function wellFormed(s:unknown):asserts s is string{
 requireValue(typeof s==='string','STRING_REQUIRED');const v=s as string;
 for(let i=0;i<v.length;i++){const c=v.charCodeAt(i);if(c>=0xd800&&c<=0xdbff){const d=v.charCodeAt(++i);requireValue(d>=0xdc00&&d<=0xdfff,'LONE_SURROGATE')}else requireValue(!(c>=0xdc00&&c<=0xdfff),'LONE_SURROGATE')}
}
const typed:object=Object.getPrototypeOf(Uint8Array.prototype) as object;
const lengthOf=Object.getOwnPropertyDescriptor(typed,'byteLength')!.get!;
const offsetOf=Object.getOwnPropertyDescriptor(typed,'byteOffset')!.get!;
const bufferOf=Object.getOwnPropertyDescriptor(typed,'buffer')!.get!;
export function captureCodecBytes(input:unknown):Buffer{
 if(typeof input==='string'){requireValue(input.length<=MAX_CODEC_BYTES&&Buffer.byteLength(input,'utf8')<=MAX_CODEC_BYTES,'LOCAL_CAPTURE_LIMIT');wellFormed(input);return Buffer.from(input,'utf8')}
 requireValue(input instanceof Uint8Array&&[Uint8Array.prototype,Buffer.prototype].includes(Object.getPrototypeOf(input)),'TEXT_OR_BYTES_REQUIRED');
 const n=lengthOf.call(input) as number,b=bufferOf.call(input) as ArrayBufferLike,o=offsetOf.call(input) as number;requireValue(n<=MAX_CODEC_BYTES,'LOCAL_CAPTURE_LIMIT');requireValue(!(typeof SharedArrayBuffer!=='undefined'&&b instanceof SharedArrayBuffer),'SHARED_INPUT_REFUSED');return Buffer.from(new Uint8Array(b,o,n));
}
export function parseCodecBytes(bytes:Uint8Array):unknown{
 const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes),value=parseStrictJson(text,32);
 function noMarkers(v:unknown):void{if(v!==null&&typeof v==='object')for(const[k,x]of Object.entries(v)){requireValue(!k.startsWith('$continuity.'),'RESERVED_KEY');noMarkers(x)}}
 noMarkers(value);return captureValue(value);
}
export const canonical=canonicalEncode;
export const digest=(value:unknown):ContentHash=>hashCanonical(value,'sha256');
export function closed(v:unknown,keys:readonly string[],path:string):asserts v is Record<string,unknown>{requireValue(v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k)),path+':CLOSED_FIELDS')}
export function protocol(v:unknown,path:string):void{wellFormed(v);requireValue(Buffer.byteLength(v,'utf8')<=4096,path+':PROTOCOL_STRING')}
export function identifier(v:unknown,path:string):void{wellFormed(v);requireValue(Buffer.byteLength(v)>=1&&Buffer.byteLength(v)<=256&&!/[\x00-\x1f\x7f]/.test(v),path+':IDENTIFIER')}
export function contentHash(v:unknown,path:string):void{requireValue(typeof v==='string'&&v.length===66&&/^0x[0-9a-f]{64}$/.test(v),path+':CONTENT_HASH')}
export function u53(v:unknown,path:string):void{requireValue(typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&!Object.is(v,-0),path+':U53')}
export function nullable(v:unknown,check:(value:unknown,path:string)=>void,path:string):void{if(v!==null)check(v,path)}
