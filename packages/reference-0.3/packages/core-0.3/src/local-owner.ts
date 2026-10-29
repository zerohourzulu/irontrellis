import { openConfiguredEventStore, ConfiguredDirectoryEventStore, type HistoryLocation } from "./configured-store.ts";
import { appendContinuationEvent } from "./history.ts";
import { historyCapacity } from "./history-store/capacity.ts";
import { observeContinuationHistory } from "./observation.ts";
import { assertCapacityTransition, capacityOf } from "./capacity.ts";
import { openSync, closeSync } from "node:fs";
import { randomUUID } from "node:crypto";
import * as core from "../../core-0.2/src/core/index.ts";
import { ManagedLocalEventStore as PortableFileEventStore } from "./capacity.ts";
import {
  ContinuityError,
  identifier,
  identifiers,
  record,
  requireCondition,
  time,
} from "./input.ts";
import {
  captureHistory,
  observeHistory,
  type Action,
  type Observation,
  type ObservationOptions,
} from "./observation.ts";

import {
  POLICY,
  configuration,
  event,
  read,
  append,
  stateOf,
  type Config,
} from "./local-store.ts";
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
  createAgent(input: Readonly<{ id: string }>): WriteResult;
  createRole(input: Readonly<{ id: string; exclusive?: boolean }>): WriteResult;
  grant(input: Grant): WriteResult;
  revoke(authority: string): WriteResult;
  appoint(input: Appointment): WriteResult;
  declareSuccession(
    input: Readonly<{ id: string; from: string; to: string; role: string }>,
  ): WriteResult;
  succeed(
    input: Succession,
  ): Readonly<{
    status: "HANDOVER_RECORDED";
    eventIds: readonly string[];
    head: core.PortableHistoryHead;
  }>;
  admitRuntime(input: RuntimeAdmission): WriteResult;
  advanceEpoch(
    input: Readonly<{ agent: string; from: number; to: number }>,
  ): WriteResult;
  observe(options?: ObservationOptions): Observation;
  authorize(action: Action): ReturnType<Observation["authorize"]>;
  why(action: Action): ReturnType<Observation["why"]>;
  responsible(action: Action): ReturnType<Observation["responsible"]>;
  survives(agent: string): ReturnType<Observation["survives"]>;
  capacity(): ReturnType<typeof capacityOf> | ReturnType<ConfiguredDirectoryEventStore["directoryStore"]["snapshot"]>["capacity"];
  exportHistory(): readonly core.PortableCanonicalEvent[];
}
function attach(store: PortableFileEventStore, config: Config): LocalOwner {
  read(store, config);
  const write = (
    type: core.PortableCanonicalEvent["type"],
    data: object,
  ): WriteResult => {
    const events = read(store, config);
    return append(store, config, event(type, config.now(), data), events);
  };
  const observe = (options: ObservationOptions = {}) =>
    store instanceof ConfiguredDirectoryEventStore ? observeContinuationHistory(store.directoryStore.snapshot().history, options) : observeHistory(read(store, config), options);
  return Object.freeze({
    createAgent(input: Readonly<{ id: string }>) {
      const r = record(input, ["id"]);
      return write("AGENT_CREATED", {
        agentId: identifier(r.id),
        principalId: config.owner,
        controllerId: config.controller,
        initialControlEpoch: 1,
      });
    },
    createRole(input: Readonly<{ id: string; exclusive?: boolean }>) {
      const r = record(input, ["id"], ["exclusive"]);
      if (Object.hasOwn(r, "exclusive"))
        requireCondition(typeof r.exclusive === "boolean");
      return write("ROLE_CREATED", {
        roleId: identifier(r.id),
        principalId: config.owner,
        exclusive: r.exclusive ?? true,
      });
    },
    grant(input: Grant) {
      const r = record(
        input,
        ["id", "to", "actions", "resources", "expiresAt"],
        ["notBefore", "maxAmount", "maxCumulativeAmount", "maxTransactions"],
      );
      const id = identifier(r.id);
      for (const field of ["maxAmount", "maxCumulativeAmount"] as const) {
        if (Object.hasOwn(r, field)) {
          const value = r[field];
          requireCondition(typeof value === "bigint" && value >= 0n && value < (1n << 256n));
        }
      }
      return write("AUTHORITY_GRANTED", {
        grant: {
          kind: "PERMISSION",
          authorityId: id,
          grantorId: config.owner,
          granteeId: identifier(r.to),
          rootAuthorityId: id,
          independent: true,
          constraints: {
            actions: identifiers(r.actions),
            resources: identifiers(r.resources),
            quantitative: Object.hasOwn(r, "maxAmount") || Object.hasOwn(r, "maxCumulativeAmount"),
            expiresAt: time(r.expiresAt),
            ...(Object.hasOwn(r, "notBefore")
              ? { notBefore: time(r.notBefore) }
              : {}),
            ...(Object.hasOwn(r, "maxAmount") ? { maxAmount: r.maxAmount as bigint } : {}),
            ...(Object.hasOwn(r, "maxCumulativeAmount") ? { maxCumulativeAmount: r.maxCumulativeAmount as bigint } : {}),
            ...(Object.hasOwn(r, "maxTransactions") ? { maxTransactions: time(r.maxTransactions) } : {}),
            maxDelegationDepth: 0,
            requiredIntersectionIds: [],
          },
        },
      });
    },
    revoke(authority: string) {
      return write("AUTHORITY_REVOKED", {
        authorityId: identifier(authority),
        revokerId: config.owner,
      });
    },
    appoint(input: Appointment) {
      const r = record(
        input,
        ["agent", "role", "tenure", "number"],
        ["succession"],
      );
      const number = time(r.number);
      requireCondition(number > 0);
      return write("AGENT_APPOINTED", {
        agentId: identifier(r.agent),
        roleId: identifier(r.role),
        roleTenureId: identifier(r.tenure),
        tenureNumber: number,
        principalId: config.owner,
        ...(Object.hasOwn(r, "succession")
          ? { successionRuleId: identifier(r.succession) }
          : {}),
      });
    },
    declareSuccession(
      input: Readonly<{ id: string; from: string; to: string; role: string }>,
    ) {
      const r = record(input, ["id", "from", "to", "role"]);
      return write("SUCCESSION_RULE_DECLARED", {
        ruleId: identifier(r.id),
        principalId: config.owner,
        predecessorAgentId: identifier(r.from),
        successorAgentId: identifier(r.to),
        roleId: identifier(r.role),
        trigger: "AGENT_TERMINATED",
        permittedEventTypes: [
          "AGENT_TERMINATED",
          "ROLE_TRANSFERRED",
          "OBLIGATION_PERFORMANCE_ASSIGNED",
        ],
      });
    },
    succeed(input: Succession) {
      const r = record(input, [
        "id",
        "rule",
        "fromAgent",
        "fromTenure",
        "toAgent",
        "toTenure",
        "role",
        "number",
      ]);
      const id = identifier(r.id),
        rule = identifier(r.rule),
        fromAgent = identifier(r.fromAgent),
        fromTenure = identifier(r.fromTenure);
      const toAgent = identifier(r.toAgent),
        toTenure = identifier(r.toTenure),
        role = identifier(r.role),
        number = time(r.number);
      requireCondition(number > 0);
      const steps = [
        {
          id: `handover:${id}:retire`,
          type: "AGENT_TERMINATED" as const,
          data: {
            agentId: fromAgent,
            principalId: config.owner,
            successionRuleId: rule,
            roleId: role,
            roleTenureId: fromTenure,
          },
        },
        {
          id: `handover:${id}:transfer`,
          type: "ROLE_TRANSFERRED" as const,
          data: {
            roleId: role,
            fromAgentId: fromAgent,
            fromRoleTenureId: fromTenure,
            toAgentId: toAgent,
            toRoleTenureId: toTenure,
            toTenureNumber: number,
            principalId: config.owner,
            transferKind: "SUCCESSION",
            successionRuleId: rule,
          },
        },
      ];
      let events = read(store, config);
      const remaining = steps.filter((step) => {
        const existing = events.find((e) => e.id === step.id);
        if (existing)
          requireCondition(
            existing.type === step.type &&
              core.canonicalEncode(existing.data) ===
                core.canonicalEncode(step.data),
            "OPERATION_CONFLICT",
          );
        return !existing;
      });
      if (remaining.length) {
        const at = config.now();
        requireCondition(
          at >= stateOf(events).head.canonicalTime,
          "CLOCK_INVALID",
        );
        const prospective = remaining.map(
          (step) => ({ ...step, timestamp: at }) as core.PortableCanonicalEvent,
        );
        requireCondition(
          events.length + prospective.length <= (store instanceof ConfiguredDirectoryEventStore ? 1024 : 256),
          "HISTORY_LIMIT",
        );
        requireCondition(
          core.replayPortable({
            operationVersion: core.PORTABLE_REPLAY_VERSION,
            events: [...events, ...prospective],
          }).status === "ACCEPTED",
          "TRANSITION_REJECTED",
        );
        if (store instanceof ConfiguredDirectoryEventStore) {
          const snapshot = store.directoryStore.snapshot();
          let history = snapshot.history;
          for (const next of prospective) history = appendContinuationEvent(history, next);
          requireCondition(historyCapacity(history, snapshot.manifest.segments.length + prospective.length).compatible, "CAPACITY_RESERVED");
        } else assertCapacityTransition(events, prospective);
        // Each durable event is visible. Resume this exact command after an
        // interrupted handover; never roll retirement back.
        for (const next of prospective) {
          append(store, config, next, events);
          events = read(store, config);
        }
      }
      return Object.freeze({
        status: "HANDOVER_RECORDED" as const,
        eventIds: Object.freeze(steps.map((step) => step.id)),
        head: stateOf(events).head,
      });
    },
    admitRuntime(input: RuntimeAdmission) {
      const r = record(input, [
        "session",
        "agent",
        "epoch",
        "key",
        "address",
        "expiresAt",
      ]);
      requireCondition(
        typeof r.address === "string" && /^0x[0-9a-fA-F]{40}$/.test(r.address),
      );
      const epoch = time(r.epoch);
      requireCondition(epoch > 0);
      return write("RUNTIME_SESSION_ADMITTED", {
        sessionId: identifier(r.session),
        agentId: identifier(r.agent),
        controllerId: config.controller,
        controlEpoch: epoch,
        credentialKeyId: identifier(r.key),
        credentialAddress: r.address,
        expiresAt: time(r.expiresAt),
      });
    },
    advanceEpoch(input: Readonly<{ agent: string; from: number; to: number }>) {
      const r = record(input, ["agent", "from", "to"]);
      const from = time(r.from),
        to = time(r.to);
      requireCondition(from > 0 && to === from + 1);
      return write("CONTROL_EPOCH_ADVANCED", {
        agentId: identifier(r.agent),
        controllerId: config.controller,
        fromEpoch: from,
        toEpoch: to,
      });
    },
    observe,
    authorize(action: Action) {
      return observe({ at: config.now() }).authorize(action);
    },
    why(action: Action) {
      return observe({ at: config.now() }).why(action);
    },
    responsible(action: Action) {
      return observe({ at: config.now() }).responsible(action);
    },
    survives(agent: string) {
      return observe({ at: config.now() }).survives(agent);
    },
    capacity() { return store instanceof ConfiguredDirectoryEventStore ? store.directoryStore.snapshot().capacity : capacityOf(read(store, config)); },
    exportHistory() {
      return read(store, config);
    },
  });
}
/** Create a new, operator-owned local policy history. No runtime keys or effects. */
export function createLocalOwner(options: LocalOwnerOptions): LocalOwner {
  return createLocalOwnerWithPolicy(options, core.PORTABLE_ADAPTER_POLICY_HASH);
}
/** Explicit E5 attempt-record history; existing histories are not migrated. */
export function createLocalAttemptOwner(options: LocalOwnerOptions): LocalOwner {
  return createLocalOwnerWithPolicy(options, core.PORTABLE_ADAPTER_POLICY_E5_HASH);
}
/** Explicit E6 opt-in for a new history; does not migrate or reinterpret E5 histories. */
export function createLocalReviewOwner(options: LocalOwnerOptions): LocalOwner {
  return createLocalOwnerWithPolicy(options, core.PORTABLE_ADAPTER_POLICY_E6_HASH);
}
function createLocalOwnerWithPolicy(options: LocalOwnerOptions, adapterPolicyHash: core.ContentHash): LocalOwner {
  const config = configuration(options);
  requireCondition(config.historyProfile === undefined, "PROFILE_MISMATCH");
  const timestamp = config.now();
  const initial = [
    event("DEPLOYMENT_INITIALIZED", timestamp, {
      domain: config.domain,
      adapterPolicyHash,
      canonicalLineageId: `lineage:${randomUUID()}`,
      versions: {
        eventSchemaVersion: "continuity-event/0.2",
        receiptSchemaVersion: "continuity-receipt/0.2",
        queryEnvelopeVersion: "continuity-query-envelope/0.2",
        authorizationProofVersion: "continuity-authorization-proof/0.2",
        runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2",
        administrativeAuthorizationVersion:
          "continuity-administrative-authorization/0.2",
        signatureScheme: "eip191-personal-sign-keccak256",
      },
      policyVersion: POLICY,
      rootRecognitionPolicy: core.PORTABLE_ROOT_RECOGNITION_POLICY,
      globalPolicySourceId: `policy:${randomUUID()}`,
      timeSource: "EVENT_TIMESTAMP",
      finality: "LOCAL_ONLY",
    }),
    event("PRINCIPAL_CREATED", timestamp, { principalId: config.owner }),
  ];
  captureHistory(initial); // Refuse invalid setup before creating a file.
  const store = new PortableFileEventStore(config.historyFile);
  try {
    const fd = openSync(config.historyFile, "wx", 0o600);
    closeSync(fd);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST")
      throw new ContinuityError("HISTORY_EXISTS");
    throw new ContinuityError("WRITE_UNCONFIRMED", true);
  }
  try {
    store.appendAll(initial);
  } catch {
    throw new ContinuityError("WRITE_UNCONFIRMED", true);
  }
  return attach(store, config);
}
/** Reopen only the explicitly selected local profile. Does not prove global freshness. */
export function openLocalOwner(options: LocalOwnerOptions): LocalOwner {
  const config = configuration(options);
  return attach(openConfiguredEventStore(config), config);
}

/** Fresh local namespace; the legacy chain/address fields carry no chain claim. */
export function createLocalDomain(): core.PortableAuthorizationDomain {
  return Object.freeze({
    protocol: "continuity",
    version: "0.2",
    deploymentId: `local:${randomUUID()}`,
    chainId: "31337",
    verifyingContract: "0x0000000000000000000000000000000000000000",
  });
}
