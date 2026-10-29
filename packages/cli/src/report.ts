/**
 * The offboarding report over a replayed state: the same derivation as
 * `LocalOwner.handover` in the core (packages/core/src/owner.ts), computed here
 * from the store's state so that histories written under another owner
 * profile (a migrated archive, a fixture) get the same report. The CLI test
 * compares this against the core's report on the demo history.
 */
import { publicQueryDisclosure, survivesState, type HandoverReport, type ReplayState } from "@ramex-labs/irontrellis";
import { CliError } from "./history.ts";

const OPEN_STATUSES: ReadonlySet<string> = new Set(["OPEN", "OUTCOME_UNKNOWN", "DISPUTED"]);
const live = (expiresAt: number | undefined, notBefore: number | undefined, at: number): boolean =>
  (expiresAt === undefined || at < expiresAt) && (notBefore === undefined || at >= notBefore);

export function handoverReport(state: ReplayState, agentId: string, at: number): HandoverReport {
  const agent = state.agents.get(agentId);
  if (agent === undefined) throw new CliError("INVALID_INPUT", `the history has no agent "${agentId}"`);
  const tenures = [...(state.currentTenureIdsByAgent.get(agentId) ?? [])].map((id) => state.tenures.get(id)).filter((t) => t !== undefined)
    .map((t) => Object.freeze({ roleId: t.roleId, tenureId: t.id, tenureNumber: t.tenureNumber, ...(t.successionRuleId === undefined ? {} : { successionRuleId: t.successionRuleId }) }));
  const sessions = (state.runtimeSessionIdsByAgent.get(agentId) ?? []).map((id) => state.runtimeSessions.get(id)).filter((s) => s !== undefined)
    .map((s) => Object.freeze({
      sessionId: s.id, controlEpoch: s.controlEpoch, credentialKeyId: s.credentialKeyId, ...(s.expiresAt === undefined ? {} : { expiresAt: s.expiresAt }),
      current: !agent.terminated && s.controlEpoch === agent.currentControlEpoch && (s.expiresAt === undefined || at < s.expiresAt),
    }));
  const openDuties = [
    ...[...state.obligations.values()].filter((o) => o.performanceAssigneeId === agentId && OPEN_STATUSES.has(o.status)).map((o) => Object.freeze({
      kind: "OBLIGATION" as const, id: o.record.obligationId, status: o.status, assignee: o.performanceAssigneeId, description: o.record.description,
      deadline: o.record.deadline, sourceIntentId: o.record.sourceIntentId, successionRuleId: o.record.successionRuleId,
    })),
    ...[...state.attemptDuties.values()].filter((d) => d.currentAssigneeId === agentId && OPEN_STATUSES.has(String(d.record.status))).map((d) => Object.freeze({
      kind: "ATTEMPT_DUTY" as const, id: d.record.dutyId, status: String(d.record.status), assignee: d.currentAssigneeId, description: String(d.record.description),
      deadline: Number(d.record.deadline), sourceIntentId: d.record.sourceIntentId,
    })),
  ];
  const liveGrants: HandoverReport["liveGrants"][number][] = [], delegationsIssued: HandoverReport["delegationsIssued"][number][] = [];
  for (const a of state.authorities.values()) {
    const g = a.grant;
    if (g.kind !== "PERMISSION" || a.revocationEventId !== undefined || !live(g.constraints.expiresAt, g.constraints.notBefore, at)) continue;
    const expiry = g.constraints.expiresAt === undefined ? {} : { expiresAt: g.constraints.expiresAt };
    if (g.granteeId === agentId) liveGrants.push(Object.freeze({
      authorityId: g.authorityId, grantorId: g.grantorId, rootAuthorityId: g.rootAuthorityId, delegated: g.parentAuthorityId !== undefined,
      actions: g.constraints.actions, resources: g.constraints.resources, ...expiry, followsSuccession: false as const,
    }));
    if (g.grantorId === agentId) delegationsIssued.push(Object.freeze({ authorityId: g.authorityId, granteeId: g.granteeId, actions: g.constraints.actions, resources: g.constraints.resources, ...expiry }));
  }
  return Object.freeze({
    agent: agentId, terminated: agent.terminated, asOf: at, head: state.head, tenures, sessions, openDuties, liveGrants, delegationsIssued,
    survives: survivesState(state, { targetAgentId: agentId, evaluationTime: at, disclosure: publicQueryDisclosure("SURVIVES", state.format) }),
  });
}
