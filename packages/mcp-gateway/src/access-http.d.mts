import type {JWK} from 'jose';
import type {AccessIdentity} from './access-policy.js';
export {issuerUrl} from './access-policy.js';
export type HttpBindingIdentity=Readonly<{id:string;subject:string;clientId:string;tenant:string;revision:string}>;
export type HttpAccess=Readonly<{binding:HttpBindingIdentity;identity:AccessIdentity;expiresAt:number;assertCurrent:()=>void}>;
export type AccessVerifierOptions=Readonly<{issuer:string;resource:string;keys:readonly JWK[];bindings:ReadonlyMap<string,HttpBindingIdentity>;isActive:(identity:AccessIdentity)=>boolean;now?:()=>number}>;
export declare function createAccessVerifier(options:AccessVerifierOptions):Promise<Readonly<{verify(token:string):Promise<HttpAccess>}>>;
