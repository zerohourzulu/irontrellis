/**
 * Rebuild of the replay state from a §7.2 record set (SPEC-IRONTRELLIS-CORE-v2 §7.1, the normative invariant; §7.5 step 4).
 *
 * `rebuildReplayState(records, events)` reconstructs every field of the replay state at the position the `event`
 * records cover from (the record set, the events the records reference by position) without re-validating the
 * prefix: no signature is checked and no transition runs. The derivation table in `state-records.ts` is this module's
 * inverse direction; every format-1 record and index is rebuilt in event order (each record's `position`), so the rebuilt
 * state answers every operation as a full replay does (builder test T2).
 *
 * What the records do not carry and is read from the events (allowed by §7.1: "a record may refer to an event by
 * `position` and the referenced event's data is then read from the history file"): the grant in event order, the
 * declaration's `adapterProfile`/fields, the admission proof's runtime fields and domain, consumption and outcome
 * payloads, observation acknowledgments, duty assignment/review payloads, receipt payloads, the appointment's
 * `successionRuleId`, the termination's lock, witness binding payloads (url, name, registration) and, for a migrated
 * history, the prefix events (inverted to the source's form to recompute the `shadow` hashes). Per-position roots and
 * projection heads before the rebuilt position are not kept (`stateRoots[q]`, `projectionHeads[q]` for q < p are
 * unfilled): nothing reads them through the state — checkpoints verify `rootAt(p−1)` of the live position only,
 * attestations and the export view compute an earlier root by a prefix replay when it is missing; the `event` records
 * carry every per-position hash. The projection head at `p` is either given (a resume takes it from the owner-signed
 * attestation or checkpoint that vouched for the root) or recomputed over the event records' `eventHash`es (T2).
 * The capacity ledger is rebuilt from the intent, duty and obligation records; `canonicalBytes` is Σ of the canonical
 * store lines of the events unless the caller knows it (a store resuming from its own canonical file passes the end
 * offset of line `p`, which is that sum).
 */
import { canonicalEncode, captureValue, compareProtocolStrings, parseAmountString } from "./canonical.ts";
import { deriveAdapterIdentityForAcceptedAdmission } from "./authority.ts";
import { formatTwoLineBytes, DUTY_CONTEST_QUOTA, DUTY_DISPOSITION_QUOTA } from "./capacity.ts";
import { EngineError } from "./errors.ts";
import { controlEffect, hashAlgorithmOf, MAX_EVENT_DATA_BYTES, sessionCredential, TRELLIS2_FORMAT } from "./events.ts";
import { hexToBytes, RecordChain } from "./hash.ts";
import { checkpointIdKey, createReplayState, indexObservation, recordCounterpartyEnvelope, reopenShadow, type MutableReplayState } from "./state.ts";
import { envelopeDigest } from "./session-auth.ts";
import { leafOf, projectionHeadAfter, projectionRow, reconciliationCursorKey, recordKey, STATE_RECORD_KINDS, type StateRecordKind } from "./state-records.ts";
import { RecordTree, rootOfLeaves } from "./state-roots.ts";
import { CONTROL_EVENT_TYPES } from "./types.ts";
import { invertTranscription } from "./transcription.ts";
import type {
  AuthorityGrant, AuthorityRecord, BoundWitness, CanonicalEvent, ContentHash, EventType, HistoryHead, IntentOutcomeState, NonceReservation, OutcomeRecord, OwnerPolicy,
  RoleRecord, RoleTenureRecord, TransactionIntent, U53,
} from "./types.ts";

type Rec = Readonly<Record<string, unknown>>;
export type RecordInput = Readonly<{ kind: string; key: string; record: Rec }>;
export type RebuildOptions = Readonly<{
  /** `projectionHead(p)` when known from an owner-signed source (SPEC §7.5 step 3); recomputed over the event records otherwise. */
  projectionHead?: ContentHash | null;
  /** The bytes of the canonical store lines 0…p when the caller knows them (a store's own file); computed otherwise. */
  canonicalBytes?: number;
  /** The §7.1 leaves the caller already computed for these records (`recomputeRoot`), keyed `kind\u0000key`; computed otherwise. */
  leaves?: ReadonlyMap<string, Uint8Array>;
  /**
   * The aligned-subtree cache `recomputeRootTree` built over exactly these leaves (A-67): adopted as the state's head
   * cache when its leaves are the very ones the rebuild uses, in the same order, so the root is not hashed twice and the
   * tail replay updates it incrementally; a fresh tree otherwise.
   */
  tree?: RecordTree;
}>;

const invalid = (reason: string): EngineError => new EngineError("INVALID_INPUT", `rebuildReplayState: ${reason}`);
const num = (value: unknown, what: string): number => { if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw invalid(`${what} must be a U53`); return value; };
const str = (value: unknown, what: string): string => { if (typeof value !== "string") throw invalid(`${what} must be a string`); return value; };
const amountField = (value: unknown, what: string): bigint => { const parsed = parseAmountString(value); if (parsed === undefined) throw invalid(`${what} must be an Amount string`); return parsed; };
const byPosition = <T extends Rec>(entries: Iterable<T>, field = "position"): T[] => [...entries].sort((a, b) => (a[field] as number) - (b[field] as number));
const LIFECYCLE_OF_INTENT = 11; // the lifecycle record types a declared job reserves (capacity.ts LIFECYCLE)
const KINDS: ReadonlySet<string> = new Set(STATE_RECORD_KINDS);

/**
 * SPEC §7.1: the full replay state at the position the `event` records cover, from the records and the events they
 * reference. Throws `INVALID_INPUT` when the records are not a consistent format-2 record set or an event they
 * reference is missing or differs from its `event` record (id, type, timestamp).
 */
export function rebuildReplayState(records: Iterable<RecordInput>, events: ArrayLike<CanonicalEvent>, options: RebuildOptions = {}): MutableReplayState {
  // ---- index the records by kind
  const byKind = new Map<StateRecordKind, Map<string, Rec>>();
  for (const kind of STATE_RECORD_KINDS) byKind.set(kind, new Map());
  let count = 0;
  for (const entry of records) {
    if (entry === null || typeof entry !== "object" || !KINDS.has(entry.kind) || typeof entry.key !== "string" || entry.record === null || typeof entry.record !== "object") throw invalid("every record must be {kind, key, record} with a §7.2 kind");
    const map = byKind.get(entry.kind as StateRecordKind)!;
    if (map.has(entry.key)) throw invalid(`duplicate record (${entry.kind}, ${entry.key})`);
    map.set(entry.key, entry.record);
    count += 1;
  }
  const of = (kind: StateRecordKind): Map<string, Rec> => byKind.get(kind)!;
  // ---- events: positions 0…p, contiguous, each matching its record
  const eventRecords = [...of("event").values()].sort((a, b) => (a.position as number) - (b.position as number));
  if (eventRecords.length === 0) throw invalid("no event records");
  const p = eventRecords.length - 1;
  if (events.length < p + 1) throw invalid(`the records reference positions through ${p} but only ${events.length} events were given`);
  const eventHashes: ContentHash[] = [], recordHashes: ContentHash[] = [];
  for (let q = 0; q <= p; q += 1) {
    const r = eventRecords[q]!;
    if (r.position !== q) throw invalid(`event records are not contiguous at ${q}`);
    eventHashes.push(str(r.eventHash, "event.eventHash") as ContentHash);
    recordHashes.push(str(r.recordHash, "event.recordHash") as ContentHash);
  }
  // Events are read only where a record references them (a resuming store hands a lazily verified array: touching an
  // element parses and verifies that line, SPEC §7.5 step 2); each one read must match its `event` record.
  const captured = new Map<number, CanonicalEvent>();
  const eventAt = (position: number, what: string): CanonicalEvent => {
    const known = captured.get(position);
    if (known !== undefined) return known;
    const event = position <= p ? events[position] : undefined;
    const r = eventRecords[position];
    if (event === undefined || r === undefined) throw invalid(`${what} references position ${position} beyond the records`);
    if (event.id !== r.eventId || event.type !== r.type || event.timestamp !== r.timestamp) throw invalid(`event ${position} does not match its record`);
    // As replay holds it: a frozen canonical copy (keys in canonical order), so the records and answers built from it are byte-equal to a replay's.
    let data: unknown;
    try { data = captureValue(event.data, { maxTotalBytes: MAX_EVENT_DATA_BYTES, maxDepth: 29 }); } catch { throw invalid(`event ${position} is not canonical`); }
    const copy: CanonicalEvent = Object.freeze({ id: event.id, type: event.type, timestamp: event.timestamp, data: data as CanonicalEvent["data"] });
    captured.set(position, copy);
    return copy;
  };
  const genesisEvent = eventAt(0, "genesis");
  if (genesisEvent.type !== "DEPLOYMENT_INITIALIZED" || (genesisEvent.data.versions as Rec | undefined)?.eventSchemaVersion !== TRELLIS2_FORMAT) throw invalid("the genesis is not a format-2 genesis");

  const s = createReplayState(TRELLIS2_FORMAT);
  s.genesis = genesisEvent.data as unknown as MutableReplayState["genesis"];
  s.signatureScheme = s.genesis.versions.signatureScheme as MutableReplayState["signatureScheme"];
  s.events = events.length === p + 1 ? (events as CanonicalEvent[]) : Array.prototype.slice.call(events, 0, p + 1) as CanonicalEvent[];
  s.eventHistoryHashes = recordHashes;
  for (let q = 0; q <= p; q += 1) s.eventPositionsById.set(eventRecords[q]!.eventId as string, q);
  const timestampAt = (q: number): number => eventRecords[q]!.timestamp as number;
  s.lastTimestamp = timestampAt(p);
  // A-179.2: the ownerTime index, from the `event` records (type, timestamp), as replay derives it.
  s.ownerTime = timestampAt(0);
  for (let q = 1; q <= p; q += 1) if (CONTROL_EVENT_TYPES.has(eventRecords[q]!.type as EventType) && timestampAt(q) > timestampAt(q - 1)) s.ownerTime = timestampAt(q);
  s.head = Object.freeze({ hash: recordHashes[p]!, position: p, canonicalTime: timestampAt(p) });
  s.hasher = RecordChain.resume(recordHashes[p]!, p + 1, eventHashes[p]!);

  // ---- owner key epochs
  const epochs = [...of("ownerKeyEpoch").entries()].map(([key, r]) => ({ epoch: Number(key), r })).sort((a, b) => a.epoch - b.epoch);
  epochs.forEach(({ epoch, r }, index) => {
    if (epoch !== index) throw invalid("owner key epochs are not contiguous");
    const next = r.nextKeyDigests;
    if (r.policy !== undefined && (r.policy === null || typeof r.policy !== "object" || Array.isArray(r.policy))) throw invalid("ownerKeyEpoch.policy is not a record (A-91.3)");
    s.ownerKeyEpochs.push(Object.freeze({
      fromPosition: num(r.fromPosition, "ownerKeyEpoch.fromPosition"), keys: Object.freeze((r.keys as readonly Rec[]).map((k) => Object.freeze({ keyId: k.keyId as string, scheme: k.scheme as never, credential: k.credential as string }))),
      ...(next === null || next === undefined ? {} : { nextKeyDigests: Object.freeze((next as readonly ContentHash[]).slice()) }),
      ...(r.policy === undefined ? {} : { policy: r.policy as unknown as OwnerPolicy }),
    }));
  });
  if (s.ownerKeyEpochs.length === 0) throw invalid("ownerKeyEpoch 0 is missing");

  // ---- migrated prefix: the shadow context from the inverted prefix events (SPEC §16.2 step 3)
  const migrated = s.genesis.migratedFrom;
  const inPrefix = (position: number): boolean => migrated !== undefined && position <= migrated.position;
  if (migrated !== undefined) {
    const inverted: CanonicalEvent[] = [genesisEvent];
    for (let q = 1; q <= Math.min(p, migrated.position); q += 1) inverted.push(invertTranscription(eventAt(q, "migrated prefix"), migrated.format));
    try { reopenShadow(s, migrated, inverted, p); } catch (error) { throw invalid(error instanceof Error ? error.message : "shadow"); }
    const shadowRecord = of("shadow").get("0");
    const hashes = s.shadowHashes ?? [];
    if (shadowRecord === undefined || shadowRecord.count !== hashes.length || shadowRecord.root !== rootOfLeaves(hashes.map(hexToBytes))) throw invalid("the shadow record does not match the recomputed source hashes");
  } else if (of("shadow").size > 0) throw invalid("a shadow record without migratedFrom");
  /** The head including `position` as the runtime-signed records of that position bound it (the source's head inside a migrated prefix). */
  const headAt = (position: number): HistoryHead => Object.freeze({
    hash: inPrefix(position) ? s.shadowHashes![position]! : recordHashes[position]!, position, canonicalTime: timestampAt(position),
  });
  const algorithmAt = (position: number) => (inPrefix(position) && migrated !== undefined ? hashAlgorithmOf(migrated.format) : s.hashAlgorithm);
  const digestFree = (data: Rec, ...keys: string[]): Rec => { const copy: Record<string, unknown> = { ...data }; for (const key of keys) delete copy[key]; return copy; };
  const engineAmount = (value: unknown): bigint | undefined => (typeof value === "string" ? parseAmountString(value) : typeof value === "bigint" ? value : undefined);

  // ---- principals, agents, roles, succession rules, tenures (in event order)
  for (const r of byPosition(of("principal").values())) {
    s.principals.set(r.principalId as string, Object.freeze({ id: r.principalId as string, creationEventId: r.eventId as string, creationEventPosition: num(r.position, "principal.position") }));
  }
  for (const r of byPosition(of("agent").values())) {
    const id = r.agentId as string;
    s.agents.set(id, Object.freeze({ id, principalId: r.principalId as string, controllerId: r.controllerId as string, currentControlEpoch: num(r.controlEpoch, "agent.controlEpoch"), terminated: r.status === "TERMINATED" }));
    s.recordRefs.set(recordKey("agent", id), Object.freeze({ eventId: r.eventId, position: r.position, ...(r.terminatedEventId === null ? {} : { terminatedEventId: r.terminatedEventId, terminatedPosition: r.terminatedPosition }) }));
  }
  const tenureRecords = byPosition(of("tenure").values());
  const latestTenureNumber = new Map<string, number>();
  for (const t of tenureRecords) latestTenureNumber.set(t.roleId as string, Math.max(latestTenureNumber.get(t.roleId as string) ?? 0, num(t.tenureNumber, "tenure.tenureNumber")));
  for (const r of byPosition(of("role").values())) {
    const id = r.roleId as string;
    const role: RoleRecord = Object.freeze({ id, principalId: r.principalId as string, ...(r.currentTenureId === null ? {} : { currentTenureId: r.currentTenureId as string }), latestTenureNumber: latestTenureNumber.get(id) ?? 0 });
    s.roles.set(id, role);
    s.recordRefs.set(recordKey("role", id), Object.freeze({ eventId: r.eventId, position: r.position }));
  }
  for (const r of byPosition(of("succession").values())) {
    const rule = r.rule as Rec & { ruleId: string; successorAgentId: string };
    s.successionRules.set(rule.ruleId, Object.freeze({ data: rule as never }));
    s.recordRefs.set(recordKey("succession", rule.ruleId), Object.freeze({ eventId: r.eventId, position: r.position }));
    const reserved = s.reservedAgentIds.get(rule.successorAgentId) ?? new Set<string>();
    reserved.add(rule.ruleId);
    s.reservedAgentIds.set(rule.successorAgentId, reserved);
  }
  for (const t of tenureRecords) {
    const id = t.roleTenureId as string, roleId = t.roleId as string, agentId = t.agentId as string, position = num(t.position, "tenure.position");
    const role = s.roles.get(roleId);
    if (role === undefined) throw invalid(`tenure ${id} names an unknown role`);
    const opening = eventAt(position, `tenure ${id}`);
    const successionRuleId = opening.type === "AGENT_APPOINTED" ? opening.data.successionRuleId as string | undefined : undefined;
    const closed = t.status === "ENDED";
    // The lock (AGENT_TERMINATED, A-189.4): the AGENT_TERMINATED event at agent.terminatedPosition names this tenure. As in the
    // live engine, it persists after the tenure ends (CURRENT or ENDED).
    let lock: RoleTenureRecord["successionLock"];
    const agentRefs = s.recordRefs.get(recordKey("agent", agentId));
    if (agentRefs?.terminatedPosition !== undefined) {
      const termination = eventAt(agentRefs.terminatedPosition as number, `agent ${agentId} termination`).data as { agentId: string; principalId: string; successionRuleId: string; roleId: string; roleTenureId: string };
      if (termination.roleTenureId === id) lock = Object.freeze({ agentId: termination.agentId, principalId: termination.principalId, successionRuleId: termination.successionRuleId, roleId: termination.roleId, roleTenureId: termination.roleTenureId });
    }
    const tenure: RoleTenureRecord = Object.freeze({
      id, roleId, agentId, principalId: role.principalId, tenureNumber: num(t.tenureNumber, "tenure.tenureNumber"), ...(successionRuleId === undefined ? {} : { successionRuleId }), closed, ...(lock === undefined ? {} : { successionLock: lock }),
    });
    s.tenures.set(id, tenure);
    s.recordRefs.set(recordKey("tenure", id), Object.freeze({ eventId: t.eventId, position, ...(t.endedEventId === null ? {} : { endedEventId: t.endedEventId, endedPosition: t.endedPosition }) }));
    if (!closed) {
      const current = s.currentTenureIdsByAgent.get(agentId) ?? new Set<string>();
      current.add(id);
      s.currentTenureIdsByAgent.set(agentId, current);
    }
  }

  // ---- sessions
  for (const r of byPosition(of("session").values())) {
    const id = r.sessionId as string, agentId = r.agentId as string, position = num(r.position, "session.position");
    const credential = sessionCredential(eventAt(position, `session ${id}`).data, inPrefix(position) && migrated !== undefined ? migrated.format : s.format);
    s.runtimeSessions.set(id, Object.freeze({
      id, agentId, controllerId: r.controllerId as string, controlEpoch: num(r.controlEpoch, "session.controlEpoch"), credentialKeyId: r.credentialKeyId as string,
      credentialAddressKey: credential.key, credentialScheme: credential.scheme, admissionEventId: r.eventId as string, admissionEventPosition: position,
      ...(r.expiresAt === null ? {} : { expiresAt: num(r.expiresAt, "session.expiresAt") }),
    }));
    s.credentialKeyIds.add(r.credentialKeyId as string);
    const keys = s.credentialAddressKeysByAgent.get(agentId) ?? new Set<string>();
    keys.add(credential.key);
    s.credentialAddressKeysByAgent.set(agentId, keys);
    const ids = s.runtimeSessionIdsByAgent.get(agentId) ?? [];
    ids.push(id);
    s.runtimeSessionIdsByAgent.set(agentId, ids);
  }

  // ---- authorities, recognized roots, capped usage (grant order)
  for (const r of byPosition(of("authority").values())) {
    const position = num(r.position, "authority.position");
    const written = eventAt(position, "authority").data.grant as AuthorityGrant & { constraints: Rec };
    const constraints: Record<string, unknown> = { ...written.constraints };
    for (const key of ["maxAmount", "maxCumulativeAmount"] as const) if (typeof constraints[key] === "string") constraints[key] = parseAmountString(constraints[key] as string);
    const grant = Object.freeze({ ...written, constraints: Object.freeze(constraints) }) as AuthorityGrant;
    const record: AuthorityRecord = Object.freeze({
      grant, grantEventId: r.eventId as string, grantEventPosition: position,
      ...(r.revoked === true ? { revocationEventId: r.revocationEventId as string, revocationEventPosition: num(r.revocationPosition, "authority.revocationPosition"), revokerId: r.revokerId as string } : {}),
    });
    s.authorities.set(grant.authorityId, record);
    if (grant.kind === "PERMISSION") {
      if (grant.parentAuthorityId === undefined && grant.authorityId === grant.rootAuthorityId) {
        const principal = s.principals.get(grant.grantorId);
        if (principal !== undefined) s.recognizedRoots.set(grant.rootAuthorityId, Object.freeze({ rootAuthorityId: grant.rootAuthorityId, principalId: principal.id, principalRecognitionEventId: principal.creationEventId, rootGrantEventId: record.grantEventId }));
      }
      if (grant.constraints.maxTransactions !== undefined || grant.constraints.maxCumulativeAmount !== undefined) {
        s.authorityUsage.set(grant.authorityId, Object.freeze({ authorityId: grant.authorityId, admittedTransactionCount: 0, admittedCumulativeAmount: 0n }));
      }
    }
  }
  for (const [key, r] of of("usage")) {
    s.usageCounters.set(key, Object.freeze({ authorityId: r.authorityId as string, admittedTransactionCount: num(r.admittedTransactionCount, "usage.admittedTransactionCount"), admittedCumulativeAmount: amountField(r.admittedCumulativeAmount, "usage.admittedCumulativeAmount") }));
  }
  for (const [key, r] of of("nonce")) s.nonceRecords.set(key, Object.freeze({ actorId: r.actorId as string, nonce: r.nonce as string, intentId: r.intentId as string, position: num(r.position, "nonce.position") }));

  // ---- intents: declarations, admissions, consumptions, outcomes, observations (each in its own event order)
  const intents = byPosition(of("intent").values(), "declarationPosition");
  for (const r of intents) {
    const id = r.intentId as string, position = num(r.declarationPosition, "intent.declarationPosition");
    const event = eventAt(position, `intent ${id}`);
    const fields = digestFree(event.data, "declarationAuthorization") as Rec & { amount?: unknown };
    const amount = engineAmount(fields.amount);
    const data = Object.freeze({ ...fields, ...(amount === undefined ? {} : { amount }) }) as unknown as TransactionIntent;
    s.intentDeclarations.set(id, Object.freeze({ data, declarationDigest: (r.declarationDigest as ContentHash | null) ?? null }));
    s.declarationPositions.set(id, position);
  }
  const admitted = intents.filter((r) => r.admissionPosition !== null).sort((a, b) => (a.admissionPosition as number) - (b.admissionPosition as number));
  for (const r of admitted) {
    const id = r.intentId as string, position = num(r.admissionPosition, "intent.admissionPosition");
    const event = eventAt(position, `admission of ${id}`);
    const proof = event.data.authorizationProof as Rec & { request: Rec & { actorId: string; amount?: unknown }; controllingAuthorityIds: readonly string[] };
    const head = headAt(position);
    const declaration = s.intentDeclarations.get(id);
    if (declaration === undefined) throw invalid(`admitted intent ${id} has no declaration`);
    const admission = Object.freeze({
      intentId: id, actorId: proof.request.actorId, nonce: proof.nonce as string, admissionEventId: event.id, admissionEventPosition: position, admissionHead: head,
      runtimeSessionId: proof.runtimeSessionId as string, credentialKeyId: proof.credentialKeyId as string, controlEpoch: proof.controlEpoch as U53, roleId: proof.roleId as string, roleTenureId: proof.roleTenureId as string,
      // Inside a migrated prefix the identity was derived over the source-form event (the view's), SPEC §16.2 step 3.
      adapterIdentity: deriveAdapterIdentityForAcceptedAdmission(inPrefix(position) && migrated !== undefined ? invertTranscription(event, migrated.format) : event, head, declaration.data.adapterProfile, algorithmAt(position)),
    });
    s.intentAdmissions.set(id, admission);
    const reservations = s.nonceReservationsByActor.get(admission.actorId) ?? new Map<string, NonceReservation>();
    reservations.set(admission.nonce, Object.freeze({ intentId: id, admissionEventId: event.id, admissionEventPosition: position, admissionHead: head }));
    s.nonceReservationsByActor.set(admission.actorId, reservations);
    // The format-1 capped usage: per controlling authority, only the dimension it caps (authority.ts validateIntentAdmissionTransition).
    const amount = engineAmount(proof.request.amount);
    for (const authorityId of proof.controllingAuthorityIds) {
      const current = s.authorityUsage.get(authorityId), constraints = s.authorities.get(authorityId)?.grant.constraints;
      if (current === undefined || constraints === undefined) continue;
      s.authorityUsage.set(authorityId, Object.freeze({
        authorityId, admittedTransactionCount: current.admittedTransactionCount + (constraints.maxTransactions === undefined ? 0 : 1),
        admittedCumulativeAmount: current.admittedCumulativeAmount + (constraints.maxCumulativeAmount === undefined || amount === undefined ? 0n : amount),
      }));
    }
  }
  for (const r of intents.filter((r) => r.consumptionPosition !== null).sort((a, b) => (a.consumptionPosition as number) - (b.consumptionPosition as number))) {
    const id = r.intentId as string, position = num(r.consumptionPosition, "intent.consumptionPosition");
    const event = eventAt(position, `consumption of ${id}`);
    const d = event.data as { adapterId: string; idempotencyKey: ContentHash; submissionFingerprint: ContentHash; transactionReference: string; acknowledgment: Rec; evidenceReference: Rec };
    s.intentConsumptions.set(id, Object.freeze({
      intentId: id, eventId: event.id, eventPosition: position, head: headAt(position), adapterId: d.adapterId, idempotencyKey: d.idempotencyKey, submissionFingerprint: d.submissionFingerprint,
      transactionReference: d.transactionReference, acknowledgment: d.acknowledgment, evidenceReference: d.evidenceReference,
    }));
  }
  const outcomeLists = intents.map((r) => ({ id: r.intentId as string, outcomes: (r.outcomes as readonly Rec[]) })).filter((x) => x.outcomes.length > 0).sort((a, b) => (a.outcomes[0]!.position as number) - (b.outcomes[0]!.position as number));
  for (const { id, outcomes } of outcomeLists) {
    const list: OutcomeRecord[] = [];
    let terminal: OutcomeRecord | undefined;
    for (const o of outcomes) {
      const position = num(o.position, "intent.outcomes[].position");
      const event = eventAt(position, `outcome of ${id}`);
      const d = event.data as { status: string; attesterId: string; evidenceReference: Rec; noEffect?: Rec };
      const record: OutcomeRecord = Object.freeze({ intentId: id, eventId: event.id, eventPosition: position, head: headAt(position), status: d.status, attesterId: d.attesterId, evidenceReference: d.evidenceReference as never, ...(d.noEffect === undefined ? {} : { noEffect: d.noEffect }) });
      list.push(record);
      terminal ??= d.status === "CONFIRMED" || d.status === "FAILED" ? record : undefined;
    }
    const state: IntentOutcomeState = Object.freeze({ latest: list.at(-1)!, ...(terminal === undefined ? {} : { terminal }) });
    s.intentOutcomeStates.set(id, state);
    s.recordRefs.set(recordKey("intentOutcomes", id), Object.freeze({ outcomes: Object.freeze(list) }));
  }
  const observationLists = intents.map((r) => ({ id: r.intentId as string, observations: (r.observations as readonly Rec[]) })).filter((x) => x.observations.length > 0).sort((a, b) => (a.observations[0]!.position as number) - (b.observations[0]!.position as number));
  for (const { id, observations } of observationLists) {
    s.outcomeObservations.set(id, Object.freeze(observations.map((o) => {
      const position = num(o.position, "intent.observations[].position");
      const event = eventAt(position, `observation of ${id}`);
      const d = event.data as { sourceAdmissionEventId: string; acknowledgment: Rec; actorId: string };
      return Object.freeze({ intentId: id, sourceAdmissionEventId: d.sourceAdmissionEventId, acknowledgment: d.acknowledgment, actorId: d.actorId, eventId: event.id, eventPosition: position, observedAt: event.timestamp });
    })));
  }

  // ---- receipts, obligations, duties
  for (const r of byPosition(of("receipt").values())) {
    const position = num(r.position, "receipt.position");
    const event = eventAt(position, "receipt");
    // A-51: the commitment keeps the receipt data without the format-2 `recordAuthorization` (as replay's `applyLifecycle2` hands it on).
    const { recordAuthorization: _signed, ...receiptData } = event.data as Rec;
    s.receiptCommitments.set(r.receiptContentHash as string, Object.freeze({ ...receiptData, eventId: event.id, eventPosition: position, head: headAt(position) }) as never);
    // A-51.5: the per-intent receipt count (state.ts `receiptCountOf`).
    const countKey = recordKey("intentReceipts", r.intentId as string);
    s.recordRefs.set(countKey, Object.freeze({ count: (((s.recordRefs.get(countKey) as Rec | undefined)?.count as number | undefined) ?? 0) + 1 }));
  }
  // A-46.3: the accepted checkpoint ids, from the type-35 bodies.
  for (const r of eventRecords) {
    if (r.type !== "STATE_CHECKPOINT") continue;
    const id = (eventAt(r.position as number, "checkpoint").data as { checkpointId: string }).checkpointId;
    s.recordRefs.set(checkpointIdKey(id), Object.freeze({ position: r.position }));
  }
  // A-36.1: the counterparty envelope index (bookkeeping, no state record), from the accepted type-40 bodies in order.
  for (const r of eventRecords) {
    if (r.type !== "COUNTERPARTY_RECEIPT_RECORDED") continue;
    const d = eventAt(r.position as number, "counterparty receipt").data as { intentId: string; envelope: Rec & { counterpartyId: string; amount: string } };
    recordCounterpartyEnvelope(s, d.intentId, d.envelope.counterpartyId, envelopeDigest(d.envelope), d.envelope.amount);
  }
  for (const r of byPosition(of("obligation").values())) {
    const position = num(r.position, "obligation.position");
    const record = r.record as Rec & { obligationId: string; sourceIntentId: string };
    s.obligations.set(record.obligationId, Object.freeze({ record: record as never, status: r.status as string, performanceAssigneeId: r.performanceAssigneeId as string, creationEventId: r.eventId as string, creationEventPosition: position, creationHead: headAt(position) }));
    s.obligationIdsBySourceIntent.set(record.sourceIntentId, record.obligationId);
    // A-189.2: like the live engine, an entry only once an assignment (type 18) or a status (type 19) exists.
    if (r.assignmentEventId !== null || r.statusEventId !== null) s.recordRefs.set(recordKey("obligation", record.obligationId), Object.freeze({
      ...(r.assignmentEventId === null ? {} : { assignmentEventId: r.assignmentEventId, assignmentPosition: r.assignmentPosition }),
      ...(r.statusEventId === null ? {} : { statusEventId: r.statusEventId, statusPosition: r.statusPosition }),
    }));
  }
  const dutyRecords = byPosition(of("duty").values());
  for (const r of dutyRecords) {
    const position = num(r.position, "duty.position");
    const record = r.record as Rec & { dutyId: string; sourceIntentId: string };
    const assignments = (r.assignments as readonly Rec[]).map((a) => {
      const at = num(a.position, "duty.assignments[].position");
      const event = eventAt(at, `assignment of ${record.dutyId}`);
      const d = event.data as { fromAgentId: string; toAgentId: string; actorId: string };
      return Object.freeze({ fromAgentId: d.fromAgentId, toAgentId: d.toAgentId, actorId: d.actorId, eventId: event.id, eventPosition: at, assignedAt: event.timestamp });
    });
    s.attemptDuties.set(record.dutyId, Object.freeze({ record: record as never, creationEventId: r.eventId as string, creationEventPosition: position, creationActorId: r.creationActorId as string, currentAssigneeId: r.currentAssigneeId as string, assignments: Object.freeze(assignments) }));
    s.attemptDutyIdsBySourceIntent.set(record.sourceIntentId, record.dutyId);
    const reviews = (r.reviews as readonly Rec[]);
    if (reviews.length > 0) {
      s.attemptDutyReviews.set(record.dutyId, Object.freeze(reviews.map((v) => {
        const at = num(v.position, "duty.reviews[].position");
        const event = eventAt(at, `review of ${record.dutyId}`);
        const d = event.data as { actorId: string; observationEventIds: readonly string[]; summaryDigest: ContentHash };
        return Object.freeze({ dutyId: record.dutyId, actorId: d.actorId, observationEventIds: d.observationEventIds, summaryDigest: d.summaryDigest, eventId: event.id, eventPosition: at, reviewedAt: event.timestamp });
      })));
    }
    // SPEC §13 (E4 open item 1, closed at the merge): the activation record from `duty.policy` — `eventPosition = position`,
    // the full `priorHead` = the short record head + the timestamp of the event at its position (the head the activation
    // challenge bound, `state.ts applyDutyPolicyActivated`: `priorHead: s.head`), the descriptor as written by the event.
    const policy = r.policy as Rec | null | undefined;
    if (policy !== null && policy !== undefined) {
      const at = num(policy.position, "duty.policy.position");
      const prior = policy.priorHead as Rec;
      const priorPosition = num(prior?.position, "duty.policy.priorHead.position");
      if (priorPosition !== at - 1) throw invalid(`duty.policy.priorHead of ${record.dutyId} is not the head before the activation`);
      const event = eventAt(at, `activation of ${record.dutyId}`);
      if (event.type !== "ATTEMPT_DUTY_POLICY_ACTIVATED" || event.id !== policy.eventId) throw invalid(`duty.policy of ${record.dutyId} does not reference its activation event`);
      s.attemptDutyPolicies.set(record.dutyId, Object.freeze({
        descriptor: (event.data as Rec).descriptor as never, descriptorHash: str(policy.descriptorHash, "duty.policy.descriptorHash") as ContentHash,
        activationAuthorityId: str(policy.activationAuthorityId, "duty.policy.activationAuthorityId"), actorId: str(policy.actorId, "duty.policy.actorId"),
        eventId: event.id, eventPosition: at, activatedAt: num(policy.activatedAt, "duty.policy.activatedAt"),
        priorHead: Object.freeze({ hash: str(prior.hash, "duty.policy.priorHead.hash") as ContentHash, position: priorPosition, canonicalTime: timestampAt(priorPosition) }),
        dispositionCount: num(policy.dispositionCount, "duty.policy.dispositionCount"), contestCount: num(policy.contestCount, "duty.policy.contestCount"),
      }));
    }
    const dispositions = r.dispositions as readonly Rec[] | null | undefined;
    if (dispositions !== null && dispositions !== undefined && dispositions.length > 0) {
      s.attemptDutyDispositions.set(record.dutyId, Object.freeze(byPosition(dispositions).map((d) => Object.freeze({
        eventId: str(d.eventId, "duty.dispositions[].eventId"), position: num(d.position, "duty.dispositions[].position"),
        type: str(d.type, "duty.dispositions[].type") as "ATTEMPT_DUTY_DISPOSITION_RECORDED" | "ATTEMPT_DUTY_CONTEST_RECORDED",
        findingHash: str(d.findingHash, "duty.dispositions[].findingHash") as ContentHash,
      }))));
    }
  }

  // ---- anchors, witnesses
  for (const r of byPosition(of("anchor").values())) {
    const head = r.head as HistoryHead;
    s.anchors.push(Object.freeze({ head: Object.freeze({ hash: head.hash, position: head.position, canonicalTime: head.canonicalTime }), anchor: r.anchor as string, eventId: r.eventId as string, eventPosition: num(r.position, "anchor.position") }));
  }
  const bound: BoundWitness[] = [];
  for (const r of byPosition(of("witnessBinding").values(), "boundAtPosition")) {
    const position = num(r.boundAtPosition, "witnessBinding.boundAtPosition");
    const event = eventAt(position, "witness binding");
    const named = (controlEffect(event.data).witnesses as readonly Rec[]).find((w) => w.verifierKey === r.verifierKey);
    if (named === undefined) throw invalid(`witness binding ${r.verifierKey as string} is not in the event at ${position}`);
    const registration = named.registration as (Rec & { index: number }) | undefined;
    bound.push(Object.freeze({
      url: named.url as string, verifierKey: r.verifierKey as string, ...(named.name === undefined ? {} : { name: named.name as string }), ...(named.allowInsecureHttp === true ? { allowInsecureHttp: true as const } : {}),
      ...(registration === undefined ? {} : { registration: Object.freeze({ receipt: registration as never, index: registration.index }) }), eventId: event.id, eventPosition: position,
    }));
  }
  s.boundWitnesses = Object.freeze(bound);
  const policy = of("witnessPolicy").get("0");
  if (policy !== undefined) {
    const value = policy.policy as Rec;
    s.boundPolicy = Object.freeze({ quorum: value.quorum as number, requireOnOpen: value.requireOnOpen as boolean, maxUnwitnessedEvents: value.maxUnwitnessedEvents as number });
    s.boundPolicyPosition = num(policy.position, "witnessPolicy.position");
  }

  // ---- format-2 maps kept as their §7.2 records
  for (const r of byPosition(of("budget").values(), "declaredAtPosition")) s.budgets.set(r.budgetId as string, r);
  for (const key of [...of("budgetUsage").keys()].sort(compareProtocolStrings)) s.budgetUsage.set(key, of("budgetUsage").get(key)!);
  for (const r of byPosition(of("counterparty").values())) s.counterparties.set(r.counterpartyId as string, r);
  for (const r of byPosition(of("refusal").values())) s.refusals.set(r.refusalId as string, r);
  for (const r of byPosition(of("effect").values())) s.effects.set(r.effectId as string, r);
  // A-71.4: observations and cursors as their records (each cursor where replay creates it: at its pair's first observation);
  // the (streamId, eventRef) index from the observations in position order.
  const cursors = of("reconciliation-cursor");
  for (const r of byPosition(of("observation").values())) {
    s.reconciliationObservations.set(r.observationId as string, r);
    const source = r.source as Readonly<{ streamId: string; eventRef: string; eventDigest: string }>;
    indexObservation(s, source.streamId, source.eventRef, source.eventDigest, num(r.position, "observation.position"));
    const key = reconciliationCursorKey(str(r.reconcilerAgentId, "observation.reconcilerAgentId"), source.streamId);
    const cursor = cursors.get(key);
    if (cursor === undefined) throw invalid(`an observation without its reconciliation-cursor ${key}`);
    if (!s.reconciliationCursors.has(key)) s.reconciliationCursors.set(key, cursor);
  }
  if (s.reconciliationCursors.size !== cursors.size) throw invalid("a reconciliation-cursor without an observation");

  // ---- capacity ledger (capacity.ts): declared jobs and the lifecycle record types they produced, duties and obligations by job, duty quotas
  const produced = new Map<string, Set<EventType>>();
  for (const r of intents) produced.set(r.intentId as string, new Set());
  const mark = (intentId: string | undefined, type: EventType): void => { if (intentId !== undefined) produced.get(intentId)?.add(type); };
  for (const r of intents) {
    const id = r.intentId as string;
    if (r.admissionPosition !== null) mark(id, "TRANSACTION_INTENT_ADMITTED");
    if (r.consumptionPosition !== null) mark(id, "TRANSACTION_INTENT_CONSUMED");
    if ((r.outcomes as readonly unknown[]).length > 0) mark(id, "TRANSACTION_OUTCOME_RECORDED");
    if ((r.observations as readonly unknown[]).length > 0) mark(id, "OUTCOME_OBSERVATION_RECORDED");
  }
  for (const r of of("receipt").values()) mark(r.intentId as string, "RECEIPT_RECORDED");
  for (const r of dutyRecords) {
    const record = r.record as { dutyId: string; sourceIntentId: string };
    s.capacityDuties.set(record.dutyId, record.sourceIntentId);
    mark(record.sourceIntentId, "ATTEMPT_DUTY_CREATED");
    if ((r.assignments as readonly unknown[]).length > 0) mark(record.sourceIntentId, "ATTEMPT_DUTY_ASSIGNED");
    if ((r.reviews as readonly unknown[]).length > 0) mark(record.sourceIntentId, "ATTEMPT_DUTY_REVIEW_CLOSED");
    const dutyPolicy = r.policy as Rec | null;
    if (dutyPolicy !== null && dutyPolicy !== undefined) {
      const dispositions = Math.min(num(dutyPolicy.dispositionCount, "duty.policy.dispositionCount"), DUTY_DISPOSITION_QUOTA), contests = Math.min(num(dutyPolicy.contestCount, "duty.policy.contestCount"), DUTY_CONTEST_QUOTA);
      s.capacityDutyQuota.set(record.dutyId, Object.freeze({ dispositions, contests }));
      s.dutyReserved += DUTY_DISPOSITION_QUOTA + DUTY_CONTEST_QUOTA - dispositions - contests;
    }
  }
  for (const r of of("obligation").values()) {
    const record = r.record as { obligationId: string; sourceIntentId: string };
    s.capacityObligations.set(record.obligationId, record.sourceIntentId);
    mark(record.sourceIntentId, "OBLIGATION_CREATED");
    if (r.assignmentEventId !== null) mark(record.sourceIntentId, "OBLIGATION_PERFORMANCE_ASSIGNED");
    if (r.statusEventId !== null) mark(record.sourceIntentId, "OBLIGATION_STATUS_RECORDED");
  }
  for (const [id, types] of produced) { s.capacityIntents.set(id, types); s.lifecycleReserved += LIFECYCLE_OF_INTENT - types.size; }
  s.canonicalBytes = options.canonicalBytes ?? (() => { let bytes = 0; for (let q = 0; q <= p; q += 1) bytes += formatTwoLineBytes(q, Buffer.byteLength(canonicalEncode(eventAt(q, "canonical bytes")))); return bytes; })();

  // ---- the leaf map, the root at p and the projection head at p
  const keys: string[] = [];
  for (const [kind, map] of byKind) for (const [key, record] of map) { const k = recordKey(kind, key); keys.push(k); s.stateRecords.set(k, Object.freeze({ kind, key, record, leaf: options.leaves?.get(k) ?? leafOf(kind, key, record) })); }
  keys.sort(compareProtocolStrings);
  s.sortedRecordKeys = keys;
  if (keys.length !== count) throw invalid("record count mismatch");
  const leaves = keys.map((k) => s.stateRecords.get(k)!.leaf);
  const given = options.tree;
  const tree = given !== undefined && given.leaves.length === leaves.length && given.leaves.every((leaf, index) => leaf === leaves[index]) ? given : new RecordTree(leaves);
  s.rootLog.tree = tree;
  s.stateRoots[p] = tree.root();
  if (s.genesis.projection !== null) {
    if (options.projectionHead !== undefined && options.projectionHead !== null) s.projectionHeads[p] = options.projectionHead;
    else {
      let previous: ContentHash | null = null;
      for (let q = 0; q <= p; q += 1) previous = projectionHeadAfter(previous, projectionRow(eventAt(q, "projection"), q, eventHashes[q]!));
      s.projectionHeads[p] = previous!;
    }
  }
  return s;
}

/** The §7.1 root and leaf count of a record set (SPEC §7.5 step 3: always recomputed, never read from a stored field); `leaves` lets a rebuild reuse the work. */
export function recomputeRoot(records: Iterable<RecordInput>): Readonly<{ root: ContentHash; count: number; leaves: ReadonlyMap<string, Uint8Array> }> {
  const { root, count, leaves } = recomputeRootTree(records);
  return Object.freeze({ root, count, leaves });
}
/** `recomputeRoot` plus the aligned-subtree cache it hashed (the resume hands it to `rebuildReplayState`, `tree`). */
export function recomputeRootTree(records: Iterable<RecordInput>): Readonly<{ root: ContentHash; count: number; leaves: ReadonlyMap<string, Uint8Array>; tree: RecordTree }> {
  const entries = [...records].map((entry) => ({ k: recordKey(entry.kind, entry.key), leaf: leafOf(entry.kind, entry.key, entry.record) }));
  entries.sort((a, b) => compareProtocolStrings(a.k, b.k));
  const tree = new RecordTree(entries.map((entry) => entry.leaf));
  return Object.freeze({ root: tree.root(), count: entries.length, leaves: new Map(entries.map((entry) => [entry.k, entry.leaf])), tree });
}
