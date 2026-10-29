/**
 * Informational `verify` / `inspect` findings the G2 addenda ask for (never failures: none of them is a replay rule).
 *
 * - A-32.3: every credential that appears under more than one role or `keyId` ("credential reuse"), and every Ed25519
 *   session key of a legacy or format-1 history that fails the A-32.2 declaration test (reported, never refused there,
 *   A-28).
 * - A-36.2 / A-36 (G2): a CONNECTOR refusal whose `request.actorId` is not an agent of the history; the agents that signed
 *   CONNECTOR refusals or CONNECTOR-measured effects; effects whose metric differs from their intent's. "CONNECTOR means:
 *   the named agent says so. Replay does not know which agents are connectors."
 * - A-40.2: the provenance of a migrated prefix whose `sourceAttestation` is `null`.
 * - A-71.7: the observation listings (`observationNotes`).
 * - A-180.1 (A-22.5): the two time listings (`timeListings`): "session time advance" and "owner event at head time".
 */
import { ed25519KeyCheck } from "./crypto/ed25519-point.ts";
import { TRELLIS2_FORMAT } from "./events.ts";
import { CONTROL_EVENT_TYPES, type CanonicalEvent, type EventType, type ReplayState, type U53 } from "./types.ts";

type Rec = Readonly<Record<string, unknown>>;
const credentialKey = (scheme: string, credential: string): string => `${scheme}:${credential.toLowerCase()}`;

export function verificationNotes(state: ReplayState): readonly string[] {
  const notes: string[] = [];
  // A-32.3: one key, one role.
  const roles = new Map<string, Set<string>>();
  const use = (scheme: string, credential: string, role: string): void => {
    const key = credentialKey(scheme, credential);
    const set = roles.get(key) ?? new Set<string>();
    set.add(role);
    roles.set(key, set);
  };
  for (const epoch of state.ownerKeyEpochs ?? []) for (const k of epoch.keys) use(k.scheme, k.credential, `owner key ${k.keyId}`);
  for (const s of state.runtimeSessions.values()) use(s.credentialScheme, s.credentialAddressKey, `session ${s.id} (key ${s.credentialKeyId})`);
  for (const c of state.counterparties.values()) {
    for (const k of ((c.keys as readonly Rec[] | undefined) ?? [])) use(k.scheme as string, k.credential as string, `counterparty ${String(c.counterpartyId)} key ${String(k.keyId)}`);
  }
  for (const [key, set] of roles) if (set.size > 1) notes.push(`CREDENTIAL_REUSE: ${key} is used as ${[...set].join(", ")} (A-32.3: one key, one role)`);
  if (state.format !== TRELLIS2_FORMAT) {
    for (const s of state.runtimeSessions.values()) {
      if (s.credentialScheme !== "ed25519") continue;
      const check = ed25519KeyCheck(new Uint8Array(Buffer.from(s.credentialAddressKey.replace(/^0x/, ""), "hex")));
      if (check !== "OK") notes.push(`KEY_CHECK: session ${s.id}'s Ed25519 key is ${check} (A-32.2; reported, not refused, in a ${state.format} history)`);
    }
    return Object.freeze(notes);
  }
  // A-36.2: CONNECTOR attribution is stated, not enforced.
  const connectorSigners = new Set<string>();
  for (const event of state.events) {
    const d = event.data as Rec;
    if (event.type === "REQUEST_REFUSED" && d.refusalSource === "CONNECTOR") {
      const agent = state.runtimeSessions.get(d.runtimeSessionId as string)?.agentId;
      if (agent !== undefined) connectorSigners.add(agent);
      const actor = (d.request as Rec).actorId as string;
      if (!state.agents.has(actor)) notes.push(`CONNECTOR_ACTOR_UNKNOWN: refusal ${String(d.refusalId)} names ${actor}, which is not an agent of this history (CONNECTOR means: the named agent says so)`);
    } else if (event.type === "EFFECT_RECORDED" && (d.measurer as Rec).kind === "CONNECTOR") {
      const agent = state.runtimeSessions.get(d.runtimeSessionId as string)?.agentId;
      if (agent !== undefined) connectorSigners.add(agent);
    }
  }
  if (connectorSigners.size > 0) notes.push(`CONNECTOR_SIGNERS: ${[...connectorSigners].sort().join(", ")} signed CONNECTOR refusals or effects; replay does not know which agents are connectors`);
  for (const effect of state.effects.values()) {
    const intentMetric = (state.intentDeclarations.get(effect.intentId as string)?.data as Rec | undefined)?.metric ?? "amount";
    if (effect.metric !== intentMetric) notes.push(`EFFECT_METRIC: effect ${String(effect.effectId)} reports ${String(effect.metric)}, its intent ${String(effect.intentId)} is measured in ${String(intentMetric)}`);
  }
  notes.push(...observationNotes(state));
  // A-180.1: the two time listings (file-only; they read no clock and change no vector or root).
  const listings = timeListings(state);
  for (const a of listings.sessionTimeAdvances) notes.push(`SESSION_TIME_ADVANCE: position ${a.position} (${a.type}) by session ${a.sessionId ?? "unknown"} advanced history time by ${a.advanceMs} ms (more than ${TIME_LISTING_SKEW_MS} ms; A-180.1)`);
  for (const o of listings.ownerEventsAtHeadTime) notes.push(`OWNER_EVENT_AT_HEAD_TIME: position ${o.position} (${o.type}) is dated at its non-control predecessor's time (A-180.1)`);
  // A-40.2: what a null sourceAttestation means.
  const migrated = state.genesis.migratedFrom as (Rec & { sourceAttestation?: unknown; format?: string }) | undefined;
  if (migrated !== undefined && migrated.sourceAttestation === null) {
    notes.push(migrated.format === "irontrellis-event/1"
      ? "MIGRATED_PREFIX: format-1 prefix: source unpinned (acceptUnpinnedSource, or no pin attestation of the migrated head)"
      : "MIGRATED_PREFIX: legacy prefix: control events attested by the migrating key only");
  }
  return Object.freeze(notes);
}

/**
 * A-71.7 (report level): equivocations grouped by `(streamId, eventRef)`; MATCHED observations whose supplied `call.action`,
 * `call.resource` or `call.amount` differ from the cited decision's request; self-observations (`reconcilerAgentId = call.actorId`).
 * An observation is one admitted session's signed claim about one provider event: it proves neither that the provider
 * supplied every event nor that any external effect occurred, and an equivocation shows that a story changed, not which
 * version is true.
 */
export function observationNotes(state: ReplayState): readonly string[] {
  const notes: string[] = [];
  const equivocated = new Map<string, number[]>();
  for (const o of state.reconciliationObservations.values()) {
    const source = o.source as Rec, call = o.call as Rec, match = o.match as Rec;
    if (o.equivocates !== null) {
      const key = `${String(source.streamId)}/${String(source.eventRef)}`;
      equivocated.set(key, [...(equivocated.get(key) ?? [o.equivocates as number]), o.position as number]);
    }
    if (match.result === "MATCHED") {
      const cited = state.events[match.position as number]!.data as Rec;
      const request = (cited.authorizationProof === undefined ? cited.request : (cited.authorizationProof as Rec).request) as Rec;
      const differing = ["action", "resource", "amount"].filter((field) => call[field] !== undefined && call[field] !== request[field]);
      if (differing.length > 0) notes.push(`OBSERVATION_MISMATCH: observation ${String(o.observationId)} (position ${String(o.position)}) reports a ${differing.join(", ")} that differs from the decision it cites at position ${String(match.position)}`);
    }
    if (o.reconcilerAgentId === call.actorId) notes.push(`OBSERVATION_SELF: observation ${String(o.observationId)} (position ${String(o.position)}) is reported by ${String(o.reconcilerAgentId)} about its own call`);
  }
  for (const [key, positions] of equivocated) {
    notes.push(`OBSERVATION_EQUIVOCATION: ${key} was observed with different digests at positions ${positions.join(", ")}; the story changed, which version is true is not shown`);
  }
  return Object.freeze(notes);
}

/** A-180.1: a fixed constant of the format, not reader configuration (`maxClockSkewMs` stays for CLOCK_AHEAD_OF_READER only). */
export const TIME_LISTING_SKEW_MS = 300_000;
export type SessionTimeAdvance = Readonly<{ position: U53; type: EventType; sessionId: string | null; advanceMs: U53 }>;
export type OwnerEventAtHeadTime = Readonly<{ position: U53; type: EventType }>;
type Rec2 = Readonly<Record<string, unknown>> | undefined;
/** The session that signed a ◇ event, or the outer session of a ▲ event (its binding, wherever the type carries it). */
const signingSessionOf = (event: CanonicalEvent): string | null => {
  const d = event.data as Rec;
  const candidates = [((d.administrativeAuthorization as Rec2)?.challenge as Rec2)?.runtimeSessionId, (d.authorizationProof as Rec2)?.runtimeSessionId,
    (d.recordAuthorization as Rec2)?.runtimeSessionId, (d.declarationAuthorization as Rec2)?.runtimeSessionId, d.runtimeSessionId];
  const found = candidates.find((c) => typeof c === "string");
  return typeof found === "string" ? found : null;
};
/**
 * A-180.1 (A-22.5), report level, file-only: every ◇ or ▲ event at `p` outside a migrated prefix that advanced history time by
 * more than `TIME_LISTING_SKEW_MS` over the event before it ("session time advance": `{position, type, sessionId, advanceMs}`),
 * and every ◆ event dated exactly at its predecessor's time when that predecessor is a non-control event ("owner event at head
 * time": `{position, type}`). Rendered by `verify`; A-196: the engine's inspection surface may return the same listings.
 */
export function timeListings(state: ReplayState): Readonly<{ sessionTimeAdvances: readonly SessionTimeAdvance[]; ownerEventsAtHeadTime: readonly OwnerEventAtHeadTime[] }> {
  const advances: SessionTimeAdvance[] = [], atHead: OwnerEventAtHeadTime[] = [];
  const events = state.events, prefixEnd = state.genesis.migratedFrom?.position ?? 0;
  for (let p = 1; p < events.length; p += 1) {
    const e = events[p]!, previous = events[p - 1]!, control = CONTROL_EVENT_TYPES.has(e.type);
    if (!control && p > prefixEnd && e.timestamp - previous.timestamp > TIME_LISTING_SKEW_MS) {
      advances.push(Object.freeze({ position: p, type: e.type, sessionId: signingSessionOf(e), advanceMs: e.timestamp - previous.timestamp }));
    }
    if (control && e.timestamp === previous.timestamp && p > 1 && !CONTROL_EVENT_TYPES.has(previous.type)) atHead.push(Object.freeze({ position: p, type: e.type }));
  }
  return Object.freeze({ sessionTimeAdvances: Object.freeze(advances), ownerEventsAtHeadTime: Object.freeze(atHead) });
}
