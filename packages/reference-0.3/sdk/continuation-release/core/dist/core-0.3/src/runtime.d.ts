import type { LocalOwnerOptions, WriteResult } from "./local-owner.ts";
import type { SignHash } from "./simulation.ts";
export type LocalRuntimeOptions = LocalOwnerOptions & Readonly<{
    session: string;
    signHash: SignHash;
}>;
export type Obligation = Readonly<{
    id: string;
    operation: string;
    description: string;
    deadline: number;
    succession: string;
    reviewAuthority: string;
}>;
export type Assignment = Readonly<{
    id: string;
    obligation: string;
}>;
/** Signed duty operations; no root grants, role changes or external effects. */
export declare function openLocalRuntime(options: LocalRuntimeOptions): Readonly<{
    obligate(input: Obligation): Promise<WriteResult>;
    assign(input: Assignment): Promise<WriteResult>;
}>;
export type LocalRuntime = ReturnType<typeof openLocalRuntime>;
