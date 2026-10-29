import * as core from "../../core-0.2/src/core/index.ts";
/** The trusted application supplies the evaluator and durable audit sink. */
export type PolicyRequest = Readonly<{
    identity: string;
    requestHash: core.ContentHash;
    domain: core.PortableAuthorizationDomain;
    actor: string;
    action: string;
    resource: string;
    session: string;
    epoch: number;
    role: string;
    tenure: string;
    operationId: string;
    termsCommitment: core.ContentHash;
    historyHead: core.ContentHash;
    amount?: bigint;
    counterparty?: string;
}>;
export type PolicyDecision = Readonly<{
    identity: string;
    requestHash: core.ContentHash;
    decision: "ALLOW" | "DENY" | "ERROR";
    diagnostics: readonly string[];
}>;
export type PolicyEvidence = Readonly<{
    request: PolicyRequest;
    result: PolicyDecision;
    evaluatedAt: number;
}>;
export type AdditionalPolicy = Readonly<{
    identity: string;
    evaluate: (request: PolicyRequest, signal: AbortSignal) => Promise<PolicyDecision> | PolicyDecision;
    record: (evidence: PolicyEvidence) => Promise<void> | void;
}>;
export declare function capturePolicy(value: AdditionalPolicy | undefined): AdditionalPolicy | undefined;
export declare function evaluatePolicy(policy: AdditionalPolicy, fields: Omit<PolicyRequest, "identity" | "requestHash">, now: () => number): Promise<PolicyEvidence>;
