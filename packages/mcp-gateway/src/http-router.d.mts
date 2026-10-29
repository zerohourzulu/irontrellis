import type {ServerOptions,RequestOptions} from 'node:https';
import type {KeyObject} from 'node:crypto';
import type {JWK} from 'jose';
import type {AccessIdentity} from './access-policy.js';
import type {HttpBindingIdentity} from './access-http.mjs';
import type {HttpHandle} from './http.mjs';
export type RouterOptions=Readonly<{resource:string;port?:number;host?:string;issuer:string;keys:readonly JWK[];allowTestIssuer?:boolean;now?:()=>number;isActive:(identity:AccessIdentity)=>boolean;
 bindings:readonly (HttpBindingIdentity&Readonly<{backend:Readonly<{url:string;servername?:string;peerFingerprint:string}>}>)[];
 tls:ServerOptions;privateChannel:Pick<RequestOptions,'key'|'cert'|'ca'>&Readonly<{assertionPrivateKey:KeyObject}>}>;
/** Canonical HTTPS entrance: no Core history or owner/session signing capability belongs on this host. */
export declare function serveGatewayRouter(options:RouterOptions):Promise<HttpHandle>;
