/**
 * Human renderings of the core's results. Each one says what the result
 * establishes and what it does not; state words are spelled out and colour
 * only reinforces them. The JSON forms are the core's own result shapes.
 */
import type {
  AuthorityConstraints, AuthorizationResult, CapacityReport, HandoverReport, HistoryHead, OwnerVerification, PinnedHeadStatus, RemoteWitnessReport, RemoteWitnessStatus,
  ResponsibleQueryResult, SurvivesQueryResult, VerificationReport, WhyQueryResult, AnchorLogStatus, WitnessStatusReport,
} from "@ramex-labs/irontrellis";
import type { Action } from "@ramex-labs/irontrellis";
import { EQUIVOCATION_WARNING, NO_COMMITMENT_WARNING, SUPERSEDE_WARNING, type OwnerKeyStatus, type OwnerKeyWarning } from "@ramex-labs/irontrellis";
import { dim, formatTime, plural, rows, stateWord, type Lines, type Style } from "./output.ts";
import { identityCaveat, type IdentityView } from "./identity.ts";

export const READ_ONLY_NOTE = "This answer reads a captured history; it does not execute anything.";

export const headLine = (head: HistoryHead): string => `position ${head.position}, time ${formatTime(head.canonicalTime)}, hash ${head.hash.slice(0, 18)}…`;
const actionLine = (a: Action): string =>
  `${a.actor}: ${a.action} on ${a.resource}${a.amount === undefined ? "" : ` amount ${a.amount}`}${a.counterparty === undefined ? "" : ` with ${a.counterparty}`}`;
const listOrDash = (items: readonly string[]): string => (items.length === 0 ? "—" : items.join(", "));
const constraintsLine = (c: AuthorityConstraints): string => {
  const parts = [`actions ${listOrDash(c.actions)}`, `resources ${listOrDash(c.resources)}`];
  if (c.notBefore !== undefined) parts.push(`not before ${formatTime(c.notBefore)}`);
  if (c.expiresAt !== undefined) parts.push(`expires ${formatTime(c.expiresAt)}`);
  if (c.maxAmount !== undefined) parts.push(`max amount ${c.maxAmount}`);
  if (c.maxCumulativeAmount !== undefined) parts.push(`max cumulative ${c.maxCumulativeAmount}`);
  if (c.maxTransactions !== undefined) parts.push(`max transactions ${c.maxTransactions}`);
  if (c.maxDelegationDepth > 0) parts.push(`delegable ${c.maxDelegationDepth} deep`);
  if (c.requiredIntersectionIds.length > 0) parts.push(`requires ${c.requiredIntersectionIds.join(", ")}`);
  return parts.join(" · ");
};

// ---------------------------------------------------------------- decisions

/** The evidence of an authorization result, ALLOW paths or DENY/INDETERMINATE failures. */
function decisionEvidence(s: Style, out: Lines, result: AuthorizationResult): void {
  if (result.decision === "ALLOW") {
    const proof = result.proof;
    out.add(`  ${dim(s, "root")}       ${proof.recognizedRoot.rootAuthorityId} ${dim(s, `declared by ${proof.recognizedRoot.principalId}`)}`);
    out.add(`  ${dim(s, "path")}       ${proof.permissionPath.map((g) => `${g.authorityId} ${dim(s, `(${g.grantorId} → ${g.granteeId})`)}`).join(" › ")}`);
    out.add(`  ${dim(s, "effective")}  ${constraintsLine(proof.effectiveConstraints)}`);
    for (const partner of proof.intersections) {
      out.add(`  ${dim(s, "with")}       ${partner.requiredAuthorityId} ${dim(s, `required by ${partner.requiredByAuthorityIds.join(", ")}`)}: ${partner.path.map((g) => g.authorityId).join(" › ")}`);
    }
    if (proof.checkedProhibitionIds.length > 0) out.add(`  ${dim(s, "checked")}    ${plural(proof.checkedProhibitionIds.length, "prohibition")}: ${proof.checkedProhibitionIds.join(", ")}`);
    if (proof.consequential) out.add(`  ${dim(s, "session")}    ${proof.runtimeSessionId ?? "—"} epoch ${proof.controlEpoch ?? "—"} · role ${proof.roleId ?? "—"} tenure ${proof.roleTenureId ?? "—"}`);
    return;
  }
  out.add(`  ${dim(s, "code")}  ${result.code}`);
  for (const failure of result.failures) {
    const where = "authorityPathIds" in failure && failure.authorityPathIds.length > 0 ? ` ${dim(s, `path ${failure.authorityPathIds.join(" › ")}`)}` : "";
    const which = "failingAuthorityId" in failure && failure.failingAuthorityId !== undefined ? ` at ${failure.failingAuthorityId}` : "";
    const who = failure.subjectId === undefined ? "" : ` ${dim(s, `subject ${failure.subjectId}`)}`;
    out.add(`  ${dim(s, "·")}     ${failure.code}${which}${who}${where}`);
  }
}

export function renderAuthorize(s: Style, out: Lines, action: Action, result: AuthorizationResult, head: HistoryHead, at: number, refusal?: Readonly<Record<string, unknown>>): void {
  out.add(`${stateWord(s, result.decision)}  ${actionLine(action)}`);
  out.add(`  ${dim(s, "history")}    ${headLine(head)} · evaluated at ${formatTime(at)}`);
  decisionEvidence(s, out, result);
  if (refusal?.recorded === true) out.add(`  ${dim(s, "refusal")}    recorded as ${String(refusal.eventId)} · head ${headLine(refusal.head as HistoryHead)}`);
  else if (refusal !== undefined) out.add(`  ${dim(s, "refusal")}    not recorded: ${String(refusal.reason)}`);
  out.blank();
  out.add(dim(s, refusal?.recorded === true ? "The decision reads the captured history and executes nothing; the refusal was recorded in the history, signed by the actor's session." : READ_ONLY_NOTE));
}

const envelopeLines = (s: Style, out: Lines, result: WhyQueryResult | ResponsibleQueryResult | SurvivesQueryResult): void => {
  const scope = result.scope;
  const heads = scope.evaluationHead === undefined ? "—" : headLine(scope.evaluationHead);
  out.add(`  ${dim(s, "history")}    ${heads} · ${scope.headRelationship} · ${scope.freshness} · finality ${scope.finality}`);
};

export function renderWhy(s: Style, out: Lines, action: Action, result: WhyQueryResult, at: number): void {
  if (result.epistemicStatus !== "ESTABLISHED") {
    out.add(`${stateWord(s, "INDETERMINATE")}  ${actionLine(action)} ${dim(s, `(${result.epistemicStatus}: ${result.code})`)}`);
    envelopeLines(s, out, result);
    out.blank();
    out.add(dim(s, "WHY could not be established from this history at this time."));
    return;
  }
  const auth = result.answer.authorization;
  out.add(`${stateWord(s, auth.decision)}  ${actionLine(action)} ${dim(s, `at ${formatTime(at)}`)}`);
  envelopeLines(s, out, result);
  decisionEvidence(s, out, auth);
  if (result.answer.presentConsequentialUse) out.add(`  ${dim(s, "note")}       a consequential use of this authority is recorded in the history`);
  out.blank();
  out.add(dim(s, auth.decision === "ALLOW"
    ? "This shows the recorded grants that make the action allowed; it is not an execution capability."
    : "This shows why the recorded grants do not allow the action; a later grant may change the answer."));
}

const KIND_LABEL: Readonly<Record<string, string>> = {
  ACTOR: "actor", RUNTIME_SESSION: "runtime session", ROLE: "role", DECLARED_PRINCIPAL: "declared principal", MANDATOR: "mandator",
  AUTHORITY_SOURCE: "authority source", CONTROLLER: "controller", COUNTERPARTY: "counterparty", DURABLE_OBLIGOR: "durable obligor",
  BENEFICIARY: "beneficiary", PERFORMANCE_ASSIGNEE: "performance assignee",
};

export function renderResponsible(s: Style, out: Lines, action: Action, result: ResponsibleQueryResult, at: number): void {
  if (result.epistemicStatus !== "ESTABLISHED") {
    out.add(`${stateWord(s, "INDETERMINATE")}  ${actionLine(action)} ${dim(s, `(${result.epistemicStatus}: ${result.code})`)}`);
    envelopeLines(s, out, result);
    return;
  }
  const answer = result.answer;
  out.add(`${stateWord(s, answer.authorizationDecision)}  ${actionLine(action)} ${dim(s, `at ${formatTime(at)}`)}`);
  envelopeLines(s, out, result);
  if (answer.attributions.length === 0) {
    out.add(`  ${dim(s, "nobody is attributed: the action is not allowed, so no responsibility follows from it")}`);
  }
  const groups: readonly (readonly [string, string])[] = [["ACTION_PREFIX", "At the time of the action"], ["LATER_CAUSAL_STATE", "From what the history records afterwards"]];
  for (const [basis, title] of groups) {
    const items = answer.attributions.filter((a) => a.temporalBasis === basis);
    if (items.length === 0) continue;
    out.blank();
    out.add(`${title} ${dim(s, `(${plural(items.length, "attribution")})`)}`);
    out.add(...rows(s, items.map((a) => [KIND_LABEL[a.kind] ?? a.kind, `${a.subjectId} ${dim(s, `· ${plural(a.evidence.length, "evidence reference")}`)}`] as const)));
  }
  out.blank();
  out.add(dim(s, "Attribution is a statement about the supplied records, not a legal judgment."));
}

export function renderSurvives(s: Style, out: Lines, agent: string, result: SurvivesQueryResult, at: number): void {
  if (result.epistemicStatus !== "ESTABLISHED") {
    out.add(`${stateWord(s, "INDETERMINATE")}  survives ${agent} ${dim(s, `(${result.epistemicStatus}: ${result.code})`)}`);
    envelopeLines(s, out, result);
    return;
  }
  const a = result.answer;
  out.add(`${a.lifecycleStatus}  ${agent} ${dim(s, `at ${formatTime(at)}`)}`);
  envelopeLines(s, out, result);
  const section = (title: string, lines: readonly string[]): void => {
    out.blank();
    out.add(`${title} ${dim(s, `(${lines.length})`)}`);
    if (lines.length === 0) out.add(`  ${dim(s, "none")}`);
    else out.add(...lines.map((line) => `  ${line}`));
  };
  section("Current role tenures", a.currentRoleTenures.map((t) => `${t.roleId} ${dim(s, `tenure ${t.roleTenureId} #${t.tenureNumber}`)} ${t.status}`));
  section("Transferred role tenures", a.transferredRoleTenures.map((t) => `${t.roleId} ${dim(s, `tenure ${t.roleTenureId} #${t.tenureNumber} held by ${t.agentId}`)} ${t.status}`));
  section("Obligations that outlive the agent", a.obligations.map((o) => `${stateWord(s, o.status)} ${o.obligationId} ${dim(s, `role ${o.durableRoleId} · assignee ${o.performanceAssigneeId} · deadline ${formatTime(o.deadline)}`)}`));
  section("Current performance assignments", a.currentPerformanceAssignments.map((p) => `${p.obligationId} → ${p.assigneeId} ${dim(s, `under ${p.successionRuleId}`)}`));
  if (a.attemptDuties !== undefined && a.attemptDuties.length > 0) {
    // SPEC §13.6: a duty with an active policy carries its current view (`currentView.dutyDisposition`) in place of `status`.
    section("Attempt duties", a.attemptDuties.map((d) => `${stateWord(s, (d.currentView?.dutyDisposition as string | undefined) ?? d.status ?? "OPEN")} ${d.dutyId} ${dim(s, `assignee ${d.currentAssigneeId} · deadline ${formatTime(d.deadline)}`)}`));
  }
  section("Unresolved intents", a.unresolvedIntents.map((i) => `${i.intentId} ${dim(s, `${i.state} · actor ${i.actorId}`)}`));
  section("Invalidated authority dependencies", a.invalidatedAuthorityDependencies.map((d) => `${d.authorityId} ${d.state}`));
  out.blank();
  out.add(dim(s, "What survives is what the history records; it does not reassign anything."));
}

// ---------------------------------------------------------------- handover

export function renderHandover(s: Style, out: Lines, r: HandoverReport): void {
  const notCurrent = r.sessions.filter((x) => !x.current).length;
  const tenureText = r.tenures.length === 0 ? "" : ` (${r.tenures.map((t) => `${t.roleId} tenure ${t.tenureId}`).join(", ")})`;
  out.add(`Handover report for ${r.agent} ${dim(s, `· as of ${formatTime(r.asOf)} · history ${headLine(r.head)}`)}`);
  out.add(r.terminated
    ? `${r.agent} is terminated${tenureText}. ${r.agent} leaves ${plural(r.openDuties.length, "open duty", "open duties")}, ${plural(r.liveGrants.length, "live grant")} that will not follow a successor, and ${plural(r.sessions.length, "session")}${notCurrent > 0 ? ` (${notCurrent} no longer current)` : ""}.`
    : `${r.agent} is active${tenureText}. Leaving now would leave ${plural(r.openDuties.length, "open duty", "open duties")}, ${plural(r.liveGrants.length, "live grant")} that will not follow a successor, and ${plural(r.sessions.length, "session")}${notCurrent > 0 ? ` (${notCurrent} no longer current)` : ""}.`);
  out.blank();
  out.add(`Open duties ${dim(s, `(${r.openDuties.length})`)}`);
  if (r.openDuties.length === 0) out.add(`  ${dim(s, "none")}`);
  for (const d of r.openDuties) {
    out.add(`  ${stateWord(s, d.status)}  ${d.id} — ${d.description}`);
    out.add(`        ${dim(s, `assignee ${d.assignee} · deadline ${formatTime(d.deadline)} · from ${d.sourceIntentId}${d.successionRuleId === undefined ? "" : ` · succession ${d.successionRuleId}`}${d.kind === "ATTEMPT_DUTY" ? " · attempt duty" : ""}`)}`);
  }
  out.blank();
  out.add(`Live grants that do not follow ${r.agent} ${dim(s, `(${r.liveGrants.length})`)}`);
  if (r.liveGrants.length === 0) out.add(`  ${dim(s, "none")}`);
  for (const g of r.liveGrants) {
    out.add(`  ${g.authorityId} — ${g.actions.join(", ")} on ${g.resources.join(", ")} ${dim(s, `· from ${g.grantorId}${g.delegated ? ` (delegated under ${g.rootAuthorityId})` : ""}${g.expiresAt === undefined ? "" : ` · expires ${formatTime(g.expiresAt)}`} · a successor needs a fresh grant`)}`);
  }
  if (r.delegationsIssued.length > 0) {
    out.blank();
    out.add(`Delegations ${r.agent} issued ${dim(s, `(${r.delegationsIssued.length})`)}`);
    for (const d of r.delegationsIssued) out.add(`  ${d.authorityId} → ${d.granteeId} — ${d.actions.join(", ")} on ${d.resources.join(", ")} ${dim(s, "· evaluated against the delegator's own status")}`);
  }
  out.blank();
  out.add(`Sessions ${dim(s, `(${r.sessions.length})`)}`);
  if (r.sessions.length === 0) out.add(`  ${dim(s, "none")}`);
  for (const x of r.sessions) {
    out.add(`  ${x.sessionId} ${dim(s, `· epoch ${x.controlEpoch} · key ${x.credentialKeyId}${x.expiresAt === undefined ? "" : ` · expires ${formatTime(x.expiresAt)}`}`)} ${x.current ? "current" : "not current"}`);
  }
  out.blank();
  const sv = r.survives;
  if (sv.epistemicStatus === "ESTABLISHED") {
    const a = sv.answer;
    out.add(`Survives ${dim(s, "(ESTABLISHED)")}  ${a.lifecycleStatus} · ${plural(a.obligations.length, "obligation")} recorded against the agent's roles · ${plural(a.transferredRoleTenures.length, "transferred tenure")} · ${plural(a.unresolvedIntents.length, "unresolved intent")}`);
  } else {
    out.add(`Survives ${dim(s, `(${sv.epistemicStatus}: ${sv.code})`)}`);
  }
  out.add(dim(s, "This report reads a captured history; it transfers nothing. Duties follow the succession rule when a successor's session assigns them; grants never do."));
}

// ---------------------------------------------------------------- status, verify, capacity

/** What each pinned-head status means, in the report's own words (a malformed pin is not "events were removed"). */
const PIN_LABELS: Readonly<Record<PinnedHeadStatus, string>> = Object.freeze({
  MATCHES: "the pin is at the file's head",
  AHEAD: "the file extends past its pin",
  ROLLBACK: "the file does not contain its pinned head: events were removed or replaced",
  MISSING: "no pin file beside a history with events after genesis",
  MALFORMED: "the pin file cannot be parsed, so it vouches for nothing",
  UNPINNED: "no pin, and none is required",
});
const ATTESTATION_LABELS: Readonly<Record<string, string>> = Object.freeze({
  VERIFIED: "owner-attested",
  INVALID: "attestation INVALID",
  MISSING: "no owner attestation",
});
const ANCHOR_LOG_LABELS: Readonly<Record<AnchorLogStatus, string>> = Object.freeze({
  OK: "every anchored head is a prefix of the file",
  NONE: "no local anchor log holds a head for this history",
  ROLLBACK: "an anchor log holds a head the file no longer contains",
  INVALID: "an anchor log holds a head that is not owner-signed",
  UNREADABLE: "an anchor log cannot be read",
  MISSING: "the history records local anchors, but their anchor log was not found",
  NOT_APPLICABLE: "legacy histories cannot be anchored",
});

type PinView = Pick<VerificationReport, "pinnedHeadStatus" | "pinnedHead" | "pinnedAttestation" | "attestedHead">;
/** `MATCHES at position 12 · owner-attested` plus what the status means. */
export function pinLine(v: PinView): string {
  const at = v.pinnedHead === undefined ? "" : ` at position ${v.pinnedHead.position}`;
  const attestation = v.pinnedAttestation === undefined ? ""
    : ` · ${ATTESTATION_LABELS[v.pinnedAttestation] ?? v.pinnedAttestation}${v.pinnedAttestation === "VERIFIED" && v.attestedHead !== undefined && v.pinnedHead !== undefined && v.attestedHead.position < v.pinnedHead.position ? ` up to position ${v.attestedHead.position}` : ""}`;
  return `${v.pinnedHeadStatus}${at}${attestation} (${PIN_LABELS[v.pinnedHeadStatus] ?? v.pinnedHeadStatus})`;
}
const anchorLogLine = (v: Pick<VerificationReport, "anchorLogStatus" | "anchorLogHeads">): string => {
  const held = v.anchorLogHeads.length;
  const prefix = v.anchorLogHeads.filter((h) => h.status === "PREFIX_OK").length;
  return `${v.anchorLogStatus}${held === 0 ? "" : ` · ${plural(held, "anchored head")}, ${prefix} a prefix of the file`} (${ANCHOR_LOG_LABELS[v.anchorLogStatus] ?? v.anchorLogStatus})`;
};
const REMOTE_LABELS: Readonly<Record<RemoteWitnessStatus, string>> = Object.freeze({
  OK: "every remote witness's latest head is a prefix of the file",
  ROLLBACK: "a remote witness holds a head the file does not contain",
  SPLIT_VIEW: "a remote witness showed inconsistent logs",
  INVALID: "a remote witness gave an answer that does not verify",
  UNREACHABLE: "too few remote witnesses answered",
  NOT_CONSULTED: "configured, not asked by this check",
});
const remoteLine = (v: Pick<VerificationReport, "remoteWitnessStatus" | "remoteWitnesses">): string => {
  const status = v.remoteWitnessStatus ?? "NOT_CONSULTED";
  const answered = (v.remoteWitnesses ?? []).filter((w) => w.status !== "UNREACHABLE").length;
  return `${status}${v.remoteWitnesses === undefined ? "" : ` · ${answered} of ${v.remoteWitnesses.length} answered`} (${REMOTE_LABELS[status] ?? status})`;
};
/** One remote witness: status, what it holds, how far behind the file it is. */
export const remoteWitnessLine = (w: RemoteWitnessReport): string => {
  const latest = w.latest === undefined ? "" : w.latest === null ? " · holds no head yet" : ` · holds position ${w.latest.position}`;
  const tail = w.unwitnessedTail === undefined || w.unwitnessedTail === 0 ? "" : ` · ${plural(w.unwitnessedTail, "event")} not yet witnessed`;
  const conflicts = (w.equivocations === undefined || w.equivocations === 0 ? "" : ` · ${plural(w.equivocations, "equivocation")} recorded`) +
    (w.supersedes === undefined || w.supersedes === 0 ? "" : ` · ${plural(w.supersedes, "supersede")} recorded`) +
    (w.rotationPending === true ? " · holds the head of the interrupted rotation (the next owner command appends it)" : "") +
    ((w.pendingRotationPositions ?? []).length > 0 ? " · ROTATION INCOMPLETE" : "");
  const why = w.error === undefined ? "" : ` · ${w.error.code}: ${w.error.message}`;
  return `${w.status}  ${w.url}${w.bound ? " (bound in the history)" : ""}${latest}${tail}${conflicts}${why}`;
};
/**
 * A remote witness that recorded conflicting owner-signed heads for the history (docs/reference/witness-operations.md): not a verify
 * failure (the file is judged by the prefix check), but a warning about the owner key. `--json` carries these objects.
 */
export type WitnessWarning =
  | Readonly<{
    code: "REMOTE_WITNESS_EQUIVOCATION_RECORDED"; witness: string; origin?: string; equivocations: number;
    lastEquivocation?: Readonly<{ index: number; position: number; receivedAt: number }>; message: string;
  }>
  /** docs/reference/witness-operations.md §7.4: a pre-rotated rotation overrode heads an owner key signed after the last good head. */
  | Readonly<{
    code: "REMOTE_WITNESS_SUPERSEDED"; witness: string; origin?: string; supersedes: number;
    lastSupersede?: Readonly<{ index: number; from: number; heads: number; receivedAt: number }>; message: string;
  }>
  /** A bound witness has not recorded an owner key rotation of the history (it still accepts heads signed by the retired key). */
  | Readonly<{ code: "REMOTE_WITNESS_ROTATION_INCOMPLETE"; witness: string; origin?: string; positions: readonly number[]; message: string }>;
export const witnessWarnings = (reports: readonly RemoteWitnessReport[] | undefined): WitnessWarning[] => {
  const out: WitnessWarning[] = [];
  for (const w of reports ?? []) {
    const origin = w.origin === undefined ? {} : { origin: w.origin };
    if ((w.equivocations ?? 0) > 0) {
      out.push(Object.freeze({
        code: "REMOTE_WITNESS_EQUIVOCATION_RECORDED" as const, witness: w.url, ...origin, equivocations: w.equivocations!,
        ...(w.lastEquivocation === undefined ? {} : { lastEquivocation: w.lastEquivocation }), message: `${EQUIVOCATION_WARNING} (irontrellis owner rotate-key)`,
      }));
    }
    if ((w.supersedes ?? 0) > 0) {
      out.push(Object.freeze({
        code: "REMOTE_WITNESS_SUPERSEDED" as const, witness: w.url, ...origin, supersedes: w.supersedes!, ...(w.lastSupersede === undefined ? {} : { lastSupersede: w.lastSupersede }),
        message: SUPERSEDE_WARNING,
      }));
    }
    const missing = w.pendingRotationPositions ?? [];
    if (missing.length > 0 && (w.status === "OK" || w.status === "ROLLBACK")) {
      out.push(Object.freeze({
        code: "REMOTE_WITNESS_ROTATION_INCOMPLETE" as const, witness: w.url, ...origin, positions: Object.freeze(missing),
        message: "this witness has not recorded the owner key rotation; until it does it still accepts heads signed by the retired key (irontrellis witness sync; irontrellis owner export-key-events for an offline hand-off)",
      }));
    }
  }
  return out;
};
/** One WARNING block per witness finding about the owner keys (equivocations, supersedes, an incomplete rotation). */
export function renderWitnessWarnings(s: Style, out: Lines, warnings: readonly WitnessWarning[]): void {
  for (const w of warnings) {
    out.blank();
    if (w.code === "REMOTE_WITNESS_EQUIVOCATION_RECORDED") {
      const last = w.lastEquivocation === undefined ? "" : `, the latest at position ${w.lastEquivocation.position} on ${formatTime(w.lastEquivocation.receivedAt)}`;
      out.add(`${s.strong("WARNING")}  remote witness ${w.witness} recorded ${plural(w.equivocations, "conflicting owner-signed head statement")} for this history${last}.`);
      out.add(`  The owner key signed a conflicting head. If you did not restore or roll back this history, treat the owner key as compromised and rotate it: irontrellis owner rotate-key.`);
    } else if (w.code === "REMOTE_WITNESS_SUPERSEDED") {
      const last = w.lastSupersede === undefined ? "" : ` (the latest on ${formatTime(w.lastSupersede.receivedAt)}: ${plural(w.lastSupersede.heads, "head")} after position ${w.lastSupersede.from})`;
      out.add(`${s.strong("WARNING")}  remote witness ${w.witness} recorded REMOTE_WITNESS_SUPERSEDED ${w.supersedes}${last}.`);
      out.add(`  An owner key signed heads that a later pre-rotated rotation overrode; the old key was probably compromised. The superseded heads stay in the witness log as evidence.`);
    } else {
      out.add(`${s.strong("WARNING")}  remote witness ${w.witness} has not recorded the owner key rotation at position ${w.positions.join(", ")} (ROTATION INCOMPLETE).`);
      out.add(`  Until it does it still accepts heads signed by the retired key: irontrellis witness sync delivers it; irontrellis owner export-key-events writes a bundle for an offline hand-off.`);
    }
  }
}
/** The recommendation `verify` and `witness status` print while the owner keys in force have no next-key commitment. */
export function renderCommitmentAdvice(s: Style, out: Lines, notes: readonly string[]): void {
  if (!notes.some((note) => note.startsWith("NO_NEXT_KEY_COMMITMENT"))) return;
  out.blank();
  out.add(`${s.strong("WARNING")}  ${NO_COMMITMENT_WARNING.charAt(0).toUpperCase()}${NO_COMMITMENT_WARNING.slice(1)}.`);
}
/** DETECTED / accepted (when, and over which pin) / none. */
const rollbackLine = (v: Pick<VerificationReport, "rollbackAcceptedAt" | "previousPin"> & { rollback: boolean }): string => {
  if (v.rollback) return "DETECTED";
  if (v.rollbackAcceptedAt === undefined) return "none";
  return `accepted at ${formatTime(v.rollbackAcceptedAt)} · ${v.previousPin === undefined ? "there was no readable previous pin" : `the previous pin was at position ${v.previousPin.position}`}`;
};
const findingLines = (s: Style, out: Lines, title: string, lines: readonly string[], tone: "strong" | "secondary"): void => {
  if (lines.length === 0) return;
  out.blank();
  out.add(`${title} ${dim(s, `(${lines.length})`)}`);
  for (const line of lines) {
    const colon = line.indexOf(":");
    out.add(colon < 0 ? `  ${line}` : `  ${tone === "strong" ? s.strong(line.slice(0, colon)) : s.paint(line.slice(0, colon), "secondary")}${line.slice(colon)}`);
  }
};

export type Status = Readonly<{
  path: string; format: string; head: HistoryHead; eventCount: number; capacity: CapacityReport;
  verification: VerificationReport; anchors: readonly { position: number; anchor: string }[];
  owner: string; ownerKeys: readonly string[]; migratedFrom: { position: number } | undefined;
  counts: Readonly<Record<string, number>>;
  /** Format 2: the state root at the head, its record count, the projection head and the latest checkpoint (SPEC §7). */
  format2?: Readonly<Record<string, unknown>> | undefined;
  /** Why the file opens read only here (LEGACY, FORMAT_1, MIGRATED), when it does. */
  readOnly?: string | undefined;
}>;

export function renderStatus(s: Style, out: Lines, st: Status): void {
  const v = st.verification;
  const pairs: (readonly [string, string])[] = [
    ["history", st.path],
    ["format", st.format],
    ["owner", `${st.owner}${st.ownerKeys.length === 0 ? "" : ` · keys ${st.ownerKeys.join(", ")}`}`],
    ["head", headLine(st.head)],
    ["events", `${st.eventCount}${st.migratedFrom === undefined ? "" : ` (${st.migratedFrom.position + 1} re-recorded from a legacy history)`}`],
    ["capacity", `${st.capacity.mode} · ${st.capacity.eventCount} of ${st.capacity.maxEvents === null ? "unlimited" : st.capacity.maxEvents}${st.capacity.lifecycleReserved > 0 ? ` · ${st.capacity.lifecycleReserved} reserved for declared jobs` : ""}`],
    ["pinned head", pinLine(v)],
  ];
  const f2 = st.format2;
  if (f2 !== undefined) {
    const cp = f2.checkpoint as Readonly<Record<string, unknown>> | null;
    pairs.push(
      ["state root", `${String(f2.stateRoot)} · ${plural(f2.recordCount as number, "record")}`],
      ["projection", f2.projectionHead === null ? "off" : String(f2.projectionHead)],
      ["checkpoint", cp === null ? "none (irontrellis checkpoint create records one)" : `${String(cp.checkpointId)} at position ${String(cp.position)} · covers position ${String(cp.covers)} · ${plural(f2.checkpoints as number, "checkpoint")} in all`],
      ["format-2 records", `${plural(f2.budgets as number, "budget")} · ${plural(f2.counterparties as number, "counterparty", "counterparties")} · ${plural(f2.refusals as number, "refusal")} · ${plural(f2.effects as number, "effect")}`],
    );
  }
  if (st.readOnly !== undefined) pairs.push(["read only", st.readOnly === "MIGRATED" ? "yes: migrated to format 2 (a read-only archive)" : `yes: a ${st.readOnly === "LEGACY" ? "legacy" : "format-1"} history; this release reads it but writes only format 2 (irontrellis migrate)`]);
  if (v.rollbackAcceptedAt !== undefined) pairs.push(["rollback", rollbackLine({ ...v, rollback: false })]);
  pairs.push(
    ["anchor log", anchorLogLine(v)],
    ["anchors", st.anchors.length === 0 ? "none" : `${st.anchors.length} · latest position ${st.anchors[st.anchors.length - 1]!.position} via ${st.anchors[st.anchors.length - 1]!.anchor}`],
    ["integrity", v.ok ? "no failed check" : `${s.strong(`${plural(v.failures.length, "failed check")}`)}: ${v.failures.map((f) => f.split(":")[0]).join(", ")} — run irontrellis verify`],
  );
  out.add(...rows(s, pairs));
  out.blank();
  out.add("Recorded");
  out.add(...rows(s, Object.entries(st.counts).map(([key, value]) => [key, String(value)] as const)));
}

export type VerifyView = Readonly<{
  ok: boolean;
  path: string;
  failures: readonly string[];
  notes: readonly string[];
  report?: OwnerVerification;
  /** Why verification failed, in one line (a thrown code such as INVALID_HISTORY, or the failed checks). */
  error?: Readonly<{ code: string; message: string }>;
  /** Set with --accept-rollback: whether the owner key was there to attest the re-pin. */
  acceptRollback?: Readonly<{ signed: boolean }>;
  /** The history id and first owner keys the file states, and whether they match the values given (founder decision 4cb). */
  identity?: IdentityView;
}>;

/** The identity rows of verify and export verify: what the file states, and whether it matches what was given. */
export function identityRows(v: IdentityView): readonly (readonly [string, string])[] {
  const how = (given: unknown, mismatch: boolean): string => given === null ? "read from the file" : mismatch ? "MISMATCH" : "matches the value given";
  const idMismatch = v.mismatches.some((m) => m.code === "HISTORY_ID_MISMATCH"), keysMismatch = v.mismatches.some((m) => m.code === "OWNER_KEYS_MISMATCH");
  return [
    ["history id", v.historyId === null ? "unreadable" : `${v.historyId} (${how(v.expected.historyId, idMismatch)})`],
    ["first owner keys", v.ownerKeys === null ? "unreadable" : `${v.ownerKeys.length === 0 ? "none" : v.ownerKeys.join(", ")} (${how(v.expected.ownerKeys, keysMismatch)})`],
  ];
}

/**
 * Format 2 (SPEC §7.4): whether the pin's `/2` attestation names the state root the replay recomputed at its position.
 * A mismatch is already a failure of the report (ATTESTED_STATE_ROOT_MISMATCH); this line says what was compared.
 */
function pinRootLine(report: OwnerVerification): string {
  const attestation = report.pinnedHead?.attestation as Readonly<{ version?: string; stateRoot?: string; head?: { position?: number } }> | undefined;
  if (attestation === undefined || attestation.version !== "irontrellis-head-attestation/2") return "no format-2 pin attestation";
  const mismatch = report.failures.some((f) => f.startsWith("ATTESTED_STATE_ROOT_MISMATCH"));
  if (mismatch) return `MISMATCH: the pin attests ${String(attestation.stateRoot)} at position ${String(attestation.head?.position)}`;
  return `MATCHES at position ${String(attestation.head?.position)}${attestation.head?.position === report.head?.position ? "" : " (an earlier head; the replay recomputed the root there)"}`;
}

export function renderVerify(s: Style, out: Lines, v: VerifyView): void {
  out.add(`${v.ok ? "VERIFIED" : s.strong("FAILED")}  ${v.path}`);
  const report = v.report;
  const identity = v.identity === undefined ? [] : identityRows(v.identity);
  if (report === undefined && identity.length > 0) out.add(...rows(s, identity));
  if (report !== undefined) {
    out.add(...rows(s, [
      ...identity,
      ["chain", report.chain],
      ["events", String(report.eventCount)],
      ["head", report.head === undefined ? "—" : headLine(report.head)],
      ["pinned head", pinLine(report)],
      ["rollback", rollbackLine(report)],
      ["anchor log", anchorLogLine(report)],
      ...(report.remoteWitnessStatus === undefined ? [] : [["remote witnesses", remoteLine(report)] as const]),
      ["anchors", report.anchors.length === 0 ? "none" : report.anchors.map((a) => `position ${a.head.position} via ${a.anchor}: ${a.status}`).join("; ")],
      ["control signatures", report.controlSignatures],
      ...(report.stateRoot === undefined ? [] : [
        ["state root", `${report.stateRoot} (recomputed by a full replay)`] as const,
        ["pin state root", pinRootLine(report)] as const,
      ]),
    ]));
    for (const w of report.remoteWitnesses ?? []) out.add(`    ${dim(s, "·")} ${remoteWitnessLine(w)}`);
  }
  if (v.error !== undefined) out.add(`  ${s.strong(v.error.code)}  ${v.error.message}`);
  renderWitnessWarnings(s, out, witnessWarnings(report?.remoteWitnesses));
  renderCommitmentAdvice(s, out, v.notes);
  findingLines(s, out, "Failures", v.failures, "strong");
  findingLines(s, out, "Notes", v.notes, "secondary");
  if (v.acceptRollback !== undefined && !v.acceptRollback.signed && report?.format !== "continuity-event/0.2") {
    out.blank();
    out.add(dim(s, "No owner key file was found beside the history, so the new pin carries no owner attestation; readers refuse it until you run irontrellis repin --accept-rollback with the key in place."));
  }
  out.blank();
  out.add(dim(s, v.ok
    ? report?.remoteWitnessStatus === "OK"
      ? "Every record chains to the previous one, every signed check passed, and the remote witnesses' latest heads are prefixes of the file: no newer copy of this history was witnessed. Events after the witnessed head are established by this file alone."
      : report?.anchorLogStatus === "OK"
      ? "Every record chains to the previous one, every signed check passed and every head in the anchor logs is a prefix of the file. This establishes the integrity of the file; that it is the latest copy holds as far as the anchor logs saw."
      : "Every record chains to the previous one and every signed check passed. This establishes integrity of the file, not that it is the latest copy; bind a remote witness (or anchor the head) for that."
    : "The file did not pass verification; treat its contents as unestablished until each failing check is understood."));
  if (v.identity !== undefined) out.add(dim(s, identityCaveat(v.identity)));
}

/** `witness status`: the policy, what this process knows, and (unless --no-remote) what each witness says now. */
export function renderWitnessStatus(s: Style, out: Lines, st: WitnessStatusReport, remote: readonly RemoteWitnessReport[] | undefined, remoteStatus: RemoteWitnessStatus | undefined, notes: readonly string[] = []): void {
  const p = st.policy;
  const headline = st.alarm !== undefined ? s.strong(st.alarm.code) : st.rejected !== undefined ? s.strong("WITNESS_REJECTED") : "WITNESSED";
  out.add(`${headline}  ${st.statePath.replace(/\.witness\.json$/, "")}`);
  out.add(...rows(s, [
    ["policy", `quorum ${p.quorum} of ${p.witnesses.length === 0 ? st.witnesses.length : Math.max(p.witnesses.length, st.witnesses.length)} · ${p.mode} · at most ${p.maxUnwitnessedEvents} unwitnessed events${p.requireOnOpen ? " · checked before reads" : ""}`],
    ["head", st.head === undefined ? "—" : headLine(st.head)],
    ["witnessed", st.witnessedPosition === null ? "unknown" : `up to position ${st.witnessedPosition} by a quorum · ${plural(st.unwitnessedEvents, "event")} not yet witnessed`],
    ["queue", st.pending.length === 0 ? "empty" : st.pending.map((item) => (item.kind === "rotation" ? `rotation at ${item.rotationHead.position}` : `head ${item.head.position}${item.statements === undefined ? "" : " (signed by the old key)"}`)).join(", ")],
    ...(remoteStatus === undefined ? [] : [["remote check", `${remoteStatus} (${REMOTE_LABELS[remoteStatus] ?? remoteStatus})`] as const]),
    ...(rotationsOf(st) === 0 ? [] : [["rotations", `${rotationCountLine(st)} in the history, each recorded by every witness${st.rotationIncomplete ? ` · ${s.strong("ROTATION INCOMPLETE: a bound witness has not recorded one yet")}` : ""}`] as const]),
    ...(st.rotationPending === undefined ? [] : [["prepared rotation", s.strong(`position ${st.rotationPending.position} (${st.rotationPending.eventId}) is outstanding: writes wait until an owner command appends it (a witness holds its head) or discards it (no bound witness does)`)] as const]),
    ...(st.boundPolicy === undefined ? [] : [["signed minimum", `quorum ${st.boundPolicy.quorum} of the ${plural(st.bound.length, "bound witness", "bound witnesses")} · at most ${st.boundPolicy.maxUnwitnessedEvents} unwitnessed events${st.boundPolicy.requireOnOpen ? " · checked before reads" : ""} (owner-signed in the binding; no side file lowers it)`] as const]),
    ...(st.minimumPolicyFile === undefined ? [] : [["minimum policy", `${st.minimumPolicyFile} (IRONTRELLIS_WITNESS_POLICY)`] as const]),
  ]));
  if (st.alarm !== undefined) out.add(`  ${s.strong(st.alarm.code)}  ${st.alarm.message}`);
  if (st.rejected !== undefined) out.add(`  ${s.strong("WITNESS_REJECTED")}  ${st.rejected.url}: ${st.rejected.message}`);
  out.blank();
  out.add("Witnesses");
  for (const w of st.witnesses) {
    const now = remote?.find((r) => r.verifierKey === w.verifierKey);
    const known = w.latest === undefined ? "nothing known" : w.latest === null ? "holds no head" : `holds position ${w.latest.position}`;
    out.add(`  ${now === undefined ? w.source.toUpperCase() : now.status}  ${w.url}${w.bound ? dim(s, " · bound in the history") : ""}`);
    out.add(...rows(s, [
      ["key", w.verifierKey],
      ["origin", w.origin ?? "—"],
      ["latest", now === undefined ? `${known} (${w.source}${w.knownAt === undefined ? "" : `, ${formatTime(w.knownAt)}`})`
        : `${now.latest === undefined ? "not answered" : now.latest === null ? "holds no head yet" : `holds position ${now.latest.position}`}${now.unwitnessedTail === undefined || now.unwitnessedTail === 0 ? "" : ` · ${plural(now.unwitnessedTail, "event")} of the file not yet witnessed`}${now.error === undefined ? "" : ` · ${now.error.code}: ${now.error.message}`}`],
      ["receipt", now === undefined ? "not checked now" : now.receiptVerified ? "verified with the configured key" : s.strong("does not verify")],
      ["consistency", now === undefined ? (w.checkpointSize === undefined ? "no checkpoint remembered" : `checkpoint of ${w.checkpointSize} entries remembered`) : now.consistent ? `consistent with the remembered checkpoint${now.checkpointSize === undefined ? "" : ` (size ${now.checkpointSize})`}` : s.strong("SPLIT VIEW")],
      ...(now?.equivocations === undefined ? [] : [["equivocations", s.strong(`${now.equivocations} recorded (evidence that the owner key signed a conflicting head)`)] as const]),
      ...(now?.supersedes === undefined ? [] : [["supersedes", s.strong(`REMOTE_WITNESS_SUPERSEDED ${now.supersedes}: a pre-rotated rotation overrode heads an owner key signed after the last good head`)] as const]),
      ...(rotationsOf(st) === 0 ? [] : [["rotations", w.pendingRotations === null ? "unknown here (ask the witness: witness status without --no-remote)"
        : w.pendingRotations === 0 ? "recorded (every owner key rotation)" : s.strong(`PENDING: ${w.pendingRotations} of ${rotationsOf(st)} not recorded yet: until it records them this witness still accepts heads signed by the retired key (a leaked key can still fork it); run irontrellis witness sync. The retired key file(s) are still needed`)] as const]),
      ...(w.rejected === undefined ? [] : [["rejected", s.strong(`${w.rejected.code}: ${w.rejected.message}`)] as const]),
      ...(w.registrationDenied === undefined ? [] : [["registration", s.strong(`DENIED: ${w.registrationDenied.message}`)] as const]),
      ...(w.bindingWithoutReceipt !== true ? [] : [["binding", s.strong(`WITHOUT RECEIPT: bound while unreachable, so its "not registered" answers are unsigned and count as unreachable; run irontrellis witness add ${w.url} --verifier-key <key> again while it is reachable`)] as const]),
      ...(w.splitView === undefined ? [] : [["split view", s.strong(w.splitView)] as const]),
      ...(w.lastError === undefined ? [] : [["last error", `${w.lastError.code}: ${w.lastError.message}`] as const]),
    ], "    "));
  }
  renderWitnessWarnings(s, out, witnessWarnings(remote));
  renderCommitmentAdvice(s, out, notes);
  if (rotationsOf(st) > 0) {
    out.blank();
    out.add(dim(s, "A rotation is complete only when every witness bound to the history shows it recorded: until then that witness still accepts head statements signed by the retired key, so a leaked retired key can still fork it. Keep each retired owner key file (<history>.owner-key.<keyId>.retired.json) offline and backed up until then: a witness that has not recorded a rotation needs the statement for that rotation's head signed with the retired key, and so does a witness added later."));
  }
  out.blank();
  out.add(dim(s, "A remote witness shows which head of this history the owner last vouched for; it cannot show events it was never sent. This status reads the witnesses; it records nothing."));
}

export function renderCapacity(s: Style, out: Lines, c: CapacityReport): void {
  out.add(`${c.mode}  ${dim(s, c.profile)}`);
  out.add(...rows(s, [
    ["events", `${c.eventCount} of ${c.maxEvents === null ? "unlimited" : c.maxEvents}`],
    ["remaining", c.remainingPhysicalEvents === null ? "unlimited" : String(c.remainingPhysicalEvents)],
    ["reserved", `${c.lifecycleReserved} for ${plural(c.declaredJobs, "declared job")}`],
    ["can declare a job", c.canDeclareJob ? "yes" : "no"],
  ]));
  out.blank();
  out.add(dim(s, "Capacity is a point-in-time observation. Revocations, terminations and lifecycle records are always admitted; capacity never grants authority."));
}

// ---------------------------------------------------------------- owner keys (pre-rotation)

/** One WARNING line per owner-key finding (`owner status`, `init`, `owner rotate-key`, `owner commit-next-key`). */
export function renderOwnerKeyWarnings(s: Style, out: Lines, warnings: readonly OwnerKeyWarning[]): void {
  if (warnings.length === 0) return;
  out.blank();
  for (const w of warnings) out.add(`${s.strong("WARNING")}  ${w.message.charAt(0).toUpperCase()}${w.message.slice(1)}.`);
}

const NEXT_KEY_STATE: Readonly<Record<string, string>> = {
  COMMITTED: "the committed next key", IN_FORCE: "an owner key already in force (stale copy)", RETIRED: "a retired owner key",
  UNCOMMITTED: "a key the owner keys in force did not commit to", UNREADABLE: "unreadable",
};
/** Which event opened the epoch with its commitment. */
const COMMITMENT_SOURCE: Readonly<Record<string, string>> = { GENESIS: "in the genesis", ROTATION: "by the rotation", COMMITMENT: "by the commitment-only rotation (keys unchanged)" };
/** Every `OWNER_KEYS_ROTATED` of the history: key changes and commitment-only rotations. */
const rotationsOf = (st: Readonly<{ keyRotations: number; commitmentRotations: number }>): number => st.keyRotations + st.commitmentRotations;
const rotationCountLine = (st: Readonly<{ keyRotations: number; commitmentRotations: number }>): string =>
  `${plural(st.keyRotations, "key rotation")} · ${plural(st.commitmentRotations, "commitment-only rotation")}`;

export function renderOwnerStatus(s: Style, out: Lines, path: string, st: OwnerKeyStatus): void {
  if (st.format === "continuity-event/0.2") {
    out.add(`OWNER KEYS  ${path}`);
    out.add(dim(s, "A legacy (continuity-event/0.2) history has no owner keys; migrate it to format 2 (irontrellis migrate) to sign control events and rotate keys."));
    return;
  }
  const pairs: (readonly [string, string])[] = [
    ["history", path],
    ["keys in force", `${st.ownerKeys.map((k) => `${k.keyId} (${k.scheme})`).join(", ")} from position ${st.fromPosition}`],
    ["rotations", rotationCountLine(st)],
    ["next key", st.commitment === null ? s.strong("NONE") + dim(s, " — the current owner key alone can rotate this history")
      : `${s.strong("COMMITTED")} · ${plural(st.commitment.nextKeyDigests.length, "key")} · ${COMMITMENT_SOURCE[st.commitment.source] ?? "event"} ${st.commitment.eventId} at position ${st.commitment.position}`],
    ["owner key file", st.ownerKeyFile ?? "none (a caller's signer, or the file is missing)"],
    ["next-key file", st.nextKeyFile === null ? (st.commitment === null ? "none" : "not on this host") : `${st.nextKeyFile.path} · ${NEXT_KEY_STATE[st.nextKeyFile.state] ?? st.nextKeyFile.state}${st.nextKeyFile.keyId === undefined ? "" : ` (${st.nextKeyFile.keyId})`}`],
  ];
  if (st.ownerPolicy !== null) pairs.push(["approval policy", `${JSON.stringify(st.ownerPolicy)} · ${plural(st.policyRotations, "policy rotation")}`]);
  if (st.pending.length > 0) pairs.push(["pending", st.pending.join(", ")]);
  out.add(`OWNER KEYS  ${st.commitment === null ? "no next-key commitment" : st.nextKeyOnHost ? "next key on this host" : "pre-rotation in place"}`);
  out.add(...rows(s, pairs));
  renderCustody(s, out, st.custody);
  renderOwnerKeyWarnings(s, out, st.warnings);
}

const HOLDER: Readonly<Record<string, string>> = {
  file: "key file on this host", reference: "held by a signer", "public-key-only": "public key only here", elsewhere: "no key file here", none: "none", unreadable: "unreadable",
};
/** Where each key is held (docs/CUSTODY.md): one line per key, OK or WARN spelled out. */
export function renderCustody(s: Style, out: Lines, custody: OwnerKeyStatus["custody"]): void {
  if (custody.length === 0) return;
  out.blank();
  out.add(dim(s, "custody"));
  for (const c of custody) {
    const level = c.level === "OK" ? s.strong("OK  ") : s.strong("WARN");
    out.add(`  ${c.role.padEnd(7)}  ${(c.keyId ?? "—").padEnd(10)}  ${level}  ${HOLDER[c.holder] ?? c.holder}${c.description === undefined || c.holder === "file" ? "" : ` · ${c.description}`}`);
    out.add(dim(s, `           ${c.code}: ${c.message}`));
  }
}
