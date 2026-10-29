import { ConfiguredDirectoryEventStore, type HistoryLocation } from "./configured-store.ts";
import { capacityOf } from "./capacity.ts";
import * as core from "../../core-0.2/src/core/index.ts";
import { type Action, type Observation, type ObservationOptions } from "./observation.ts";
export type LocalOwnerOptions = HistoryLocation & Readonly<{
    domain: core.PortableAuthorizationDomain;
    owner: string;
    controller: string;
    now: () => number;
}>;
export type WriteResult = Readonly<{
    eventId: string;
    head: core.PortableHistoryHead;
}>;
export type Grant = Readonly<{
    id: string;
    to: string;
    actions: readonly string[];
    resources: readonly string[];
    expiresAt: number;
    notBefore?: number;
    maxAmount?: bigint;
    maxCumulativeAmount?: bigint;
    maxTransactions?: number;
}>;
export type Appointment = Readonly<{
    agent: string;
    role: string;
    tenure: string;
    number: number;
    succession?: string;
}>;
export type RuntimeAdmission = Readonly<{
    session: string;
    agent: string;
    epoch: number;
    key: string;
    address: `0x${string}`;
    expiresAt: number;
}>;
export type Succession = Readonly<{
    id: string;
    rule: string;
    fromAgent: string;
    fromTenure: string;
    toAgent: string;
    toTenure: string;
    role: string;
    number: number;
}>;
export interface LocalOwner {
    /** This whole handle is privileged host configuration; do not give it to an agent. */
    createAgent(input: Readonly<{
        id: string;
    }>): WriteResult;
    createRole(input: Readonly<{
        id: string;
        exclusive?: boolean;
    }>): WriteResult;
    grant(input: Grant): WriteResult;
    revoke(authority: string): WriteResult;
    appoint(input: Appointment): WriteResult;
    declareSuccession(input: Readonly<{
        id: string;
        from: string;
        to: string;
        role: string;
    }>): WriteResult;
    succeed(input: Succession): Readonly<{
        status: "HANDOVER_RECORDED";
        eventIds: readonly string[];
        head: core.PortableHistoryHead;
    }>;
    admitRuntime(input: RuntimeAdmission): WriteResult;
    advanceEpoch(input: Readonly<{
        agent: string;
        from: number;
        to: number;
    }>): WriteResult;
    observe(options?: ObservationOptions): Observation;
    authorize(action: Action): ReturnType<Observation["authorize"]>;
    why(action: Action): ReturnType<Observation["why"]>;
    responsible(action: Action): ReturnType<Observation["responsible"]>;
    survives(agent: string): ReturnType<Observation["survives"]>;
    capacity(): ReturnType<typeof capacityOf> | ReturnType<ConfiguredDirectoryEventStore["directoryStore"]["snapshot"]>["capacity"];
    exportHistory(): readonly core.PortableCanonicalEvent[];
}
/** Create a new, operator-owned local policy history. No runtime keys or effects. */
export declare function createLocalOwner(options: LocalOwnerOptions): LocalOwner;
/** Explicit E5 attempt-record history; existing histories are not migrated. */
export declare function createLocalAttemptOwner(options: LocalOwnerOptions): LocalOwner;
/** Explicit E6 opt-in for a new history; does not migrate or reinterpret E5 histories. */
export declare function createLocalReviewOwner(options: LocalOwnerOptions): LocalOwner;
/** Reopen only the explicitly selected local profile. Does not prove global freshness. */
export declare function openLocalOwner(options: LocalOwnerOptions): LocalOwner;
/** Fresh local namespace; the legacy chain/address fields carry no chain claim. */
export declare function createLocalDomain(): core.PortableAuthorizationDomain;
