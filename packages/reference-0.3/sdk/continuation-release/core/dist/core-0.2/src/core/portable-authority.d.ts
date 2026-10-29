export * from "./portable-authority-engine.ts";
import { type PortableAuthorizationResult } from "./portable-authority-engine.ts";
/** Authoritative replay-bound authorization. */
export declare const authorizePortable: (input: unknown) => PortableAuthorizationResult;
