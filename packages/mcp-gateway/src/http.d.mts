import type {ServerOptions} from 'node:https';
import type {KeyObject} from 'node:crypto';
import type {JWK} from 'jose';
import type {GatewayOptions} from './gateway.js';
import type {AccessIdentity} from './access-policy.js';
import type {CooperativeOptions} from './cooperative.mjs';
export type HttpBinding=Readonly<{id:string;subject:string;clientId:string;tenant?:string;revision?:string}>&(Readonly<{kind?:never;gateway:GatewayOptions&Readonly<{storage:string}>;tasks?:never}>|Readonly<{kind:'cooperative';gateway:CooperativeOptions;tasks?:true}>);
export type HttpOptions=Readonly<{port?:number;issuer:string;keys:readonly JWK[];bindings:readonly HttpBinding[];isActive:(identity:AccessIdentity)=>boolean;now?:()=>number;allowTestIssuer?:boolean}>;
export type HttpHandle=Readonly<{resourceUrl:string;metadataUrl:string;port:number;close():Promise<void>}>;
export type BackendOptions=Omit<HttpOptions,'bindings'>&Readonly<{resource:string;host?:string;tls:ServerOptions;bindings:readonly (HttpBinding&Readonly<{tenant:string;revision:string}>)[];privateChannel:Readonly<{peerFingerprint:string;assertionPublicKey:KeyObject;nonceDirectory:string;servername?:string}>}>;
/** Loopback-only evaluation. Canonical public hosting requires the explicit router/backend profile. */
export declare function serveGatewayHttp(options:HttpOptions):Promise<HttpHandle>;
/** mTLS authority backend; requires a pinned peer, channel-bound assertions and independently checked bearer/Core authority. */
export declare function serveGatewayBackend(options:BackendOptions):Promise<HttpHandle>;
export {serveGatewayRouter,type RouterOptions} from './http-router.mjs';
