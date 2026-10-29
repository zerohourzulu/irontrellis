/**
 * IronTrellis core — shared vocabulary.
 *
 * Every module imports its types from here so that the replay state, the
 * authority engine, the queries and the store agree on one data model. The
 * shapes are the ones the legacy engine (Continuity Core 0.2.2) exposes, so a
 * history written by either implementation reads the same way. Format-specific
 * differences are confined to the genesis record and to signature credentials.
 */
import type { WitnessReceipt } from "./transparency/receipt.ts";
import { readonlyMap, readonlySet } from "./readonly-collections.ts";

// ---------------------------------------------------------------- scalars

/** `0x` + 64 lowercase hex characters (keccak-256 for format 0.2, sha256 for format 1). */
export type ContentHash = `0x${string}`;
/** `0x` + 130 hex (r ‖ s ‖ v, secp256k1) or `0x` + 128 hex (Ed25519). */
export type HexSignature = `0x${string}`;
/** Non-negative safe integer. */
export type U53 = number;
/** Unsigned 256-bit quantity (engine-internal; format 2 spells it on the wire as an `AmountString`). */
export type Amount = bigint;
/**
 * The wire form of an Amount in format 2 (SPEC §3.3): a decimal string `^(0|[1-9][0-9]*)$`, at most 78
 * characters, at most 2^256−1. Every format-2 structure that is hashed, signed or stored carries this form;
 * the engine converts it to `Amount` at the schema boundary and back when it emits a structure.
 */
export type AmountString = string;

export type HistoryFormat = "continuity-event/0.2" | "irontrellis-event/1" | "irontrellis-event/2";
export type HashAlgorithm = "keccak256" | "sha256";
export type SignatureScheme = "eip191-personal-sign-keccak256" | "ed25519";

export type HistoryHead = Readonly<{ hash: ContentHash; position: U53; canonicalTime: U53 }>;

/** Legacy domain (format 0.2). `verifyingContract` compares case-insensitively. */
export type LegacyDomain = Readonly<{
  protocol: "continuity";
  version: "0.2";
  deploymentId: string;
  chainId: string;
  verifyingContract: string;
}>;
/** Format-1 (`version: "1"`) and format-2 (`version: "2"`) domain. */
export type TrellisDomain = Readonly<{ protocol: "irontrellis"; version: "1" | "2"; deploymentId: string }>;
export type AuthorizationDomain = LegacyDomain | TrellisDomain;

// ---------------------------------------------------------------- events

/** Frozen at runtime as well as in its type (KNOWN-ISSUES r2.2 59): the list cannot be changed by a caller. */
export const EVENT_TYPES = Object.freeze([
  "DEPLOYMENT_INITIALIZED",
  "PRINCIPAL_CREATED",
  "AGENT_CREATED",
  "ROLE_CREATED",
  "SUCCESSION_RULE_DECLARED",
  "AGENT_APPOINTED",
  "AGENT_UNAPPOINTED",
  "ROLE_TRANSFERRED",
  "RUNTIME_SESSION_ADMITTED",
  "CONTROL_EPOCH_ADVANCED",
  "AUTHORITY_GRANTED",
  "AUTHORITY_REVOKED",
  "TRANSACTION_INTENT_DECLARED",
  "TRANSACTION_INTENT_ADMITTED",
  "TRANSACTION_INTENT_CONSUMED",
  "TRANSACTION_OUTCOME_RECORDED",
  "RECEIPT_RECORDED",
  "OBLIGATION_CREATED",
  "OBLIGATION_PERFORMANCE_ASSIGNED",
  "OBLIGATION_STATUS_RECORDED",
  "AGENT_TERMINATED",
  "OUTCOME_OBSERVATION_RECORDED",
  "ATTEMPT_DUTY_CREATED",
  "ATTEMPT_DUTY_ASSIGNED",
  "ATTEMPT_DUTY_REVIEW_CLOSED",
  /** Format 1 only. */
  "ANCHOR_RECORDED",
  /** Format 1 only: opens a new owner key epoch (a new key set, or the same set with a next-key commitment). */
  "OWNER_KEYS_ROTATED",
  /** Format 1 only: binds remote witnesses to the history, with the policy minimum they are checked under. */
  "WITNESSES_BOUND",
  /** Format 1 only: unbinds remote witnesses (optionally recording an accepted loss), with the policy minimum after it. */
  "WITNESSES_UNBOUND",
  // Format 2 only (SPEC §5; the index is the projection type code of §12). 29–31 are ported from Continuity preview.10.2 (§13).
  "ATTEMPT_DUTY_POLICY_ACTIVATED",
  "ATTEMPT_DUTY_DISPOSITION_RECORDED",
  "ATTEMPT_DUTY_CONTEST_RECORDED",
  "BUDGET_DECLARED",
  "BUDGET_UPDATED",
  "BUDGET_CLOSED",
  "STATE_CHECKPOINT",
  "COUNTERPARTY_REGISTERED",
  "COUNTERPARTY_RETIRED",
  "REQUEST_REFUSED",
  "EFFECT_RECORDED",
  "COUNTERPARTY_RECEIPT_RECORDED",
  // A-71 (post-E5): projection type code 42; code 41 is unassigned (`EVENT_TYPE_CODES`).
  "RECONCILIATION_OBSERVED",
] as const);
export type EventType = (typeof EVENT_TYPES)[number];
/** SPEC §5 / §12.1: the projection type code of every type — its index in `EVENT_TYPES`, except that code 41 is unassigned and `RECONCILIATION_OBSERVED` is 42 (A-71.0). */
export const EVENT_TYPE_CODES: ReadonlyMap<EventType, number> = readonlyMap<EventType, number>(EVENT_TYPES.map((type, index) => [type, index < 41 ? index : index + 1]));

/** Control events: in format 1 they must carry `data.controlAuthorization` signed by an owner key. */
export const CONTROL_EVENT_TYPES: ReadonlySet<EventType> = readonlySet<EventType>([
  "PRINCIPAL_CREATED",
  "AGENT_CREATED",
  "ROLE_CREATED",
  "SUCCESSION_RULE_DECLARED",
  "AGENT_APPOINTED",
  "AGENT_UNAPPOINTED",
  "ROLE_TRANSFERRED",
  "RUNTIME_SESSION_ADMITTED",
  "CONTROL_EPOCH_ADVANCED",
  "AUTHORITY_GRANTED",
  "AUTHORITY_REVOKED",
  "AGENT_TERMINATED",
  "ANCHOR_RECORDED",
  "OWNER_KEYS_ROTATED",
  "WITNESSES_BOUND",
  "WITNESSES_UNBOUND",
  // Format 2 (SPEC §5): budgets, checkpoints and counterparty registrations are owner-signed too.
  "BUDGET_DECLARED",
  "BUDGET_UPDATED",
  "BUDGET_CLOSED",
  "STATE_CHECKPOINT",
  "COUNTERPARTY_REGISTERED",
  "COUNTERPARTY_RETIRED",
]);
/**
 * The power-reducing types of the G1 header (A-22.3, A-24.1): written at `max(now, head.canonicalTime)` by the owner API
 * (reported as CLOCK_BEHIND_HEAD), and never refused by MAX_UNWITNESSED.
 */
export const POWER_REDUCING_TYPES: ReadonlySet<EventType> = readonlySet<EventType>([
  "AUTHORITY_REVOKED", "CONTROL_EPOCH_ADVANCED", "AGENT_TERMINATED", "AGENT_UNAPPOINTED", "BUDGET_UPDATED", "BUDGET_CLOSED", "COUNTERPARTY_RETIRED", "WITNESSES_UNBOUND",
]);
/**
 * A-24.1 as amended by A-176.2: the witness option `MAX_UNWITNESSED` never refuses a power-reducing control event or a
 * `STATE_CHECKPOINT` (the L12 route of A-119.2 stays open under lapse). `POWER_REDUCING_TYPES` stays the A-22.3 set.
 */
export const MAX_UNWITNESSED_EXEMPT_TYPES: ReadonlySet<EventType> = readonlySet<EventType>([...POWER_REDUCING_TYPES, "STATE_CHECKPOINT"]);

/** Session-signed event types (SPEC §6.2, ◇): `TRANSACTION_INTENT_DECLARED` only in format 2 (format 1 declarations are unsigned). */
export const SESSION_SIGNED_EVENT_TYPES: ReadonlySet<EventType> = readonlySet<EventType>([
  "TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED", "REQUEST_REFUSED", "EFFECT_RECORDED", "COUNTERPARTY_RECEIPT_RECORDED",
  // A-51 / A-51.6: format-2 types 14–16 are ◇ session-signed; their projection rows set flag bit 1 per type (native and migrated histories alike).
  "TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED", "RECEIPT_RECORDED",
  // A-71.5: type 42 is ◇ (flag bit 1).
  "RECONCILIATION_OBSERVED",
]);

/** Event types a legacy (`continuity-event/0.2`) history may not carry (`UNSUPPORTED_EVENT_TYPE`). */
export const TRELLIS_ONLY_EVENT_TYPES: ReadonlySet<EventType> = readonlySet<EventType>(["ANCHOR_RECORDED", "OWNER_KEYS_ROTATED", "WITNESSES_BOUND", "WITNESSES_UNBOUND"]);
/** Event types only a format-2 history may carry (SPEC §5: types 29–40 and 42; `UNSUPPORTED_EVENT_TYPE` in legacy and format-1 histories). */
export const FORMAT2_ONLY_EVENT_TYPES: ReadonlySet<EventType> = readonlySet<EventType>(EVENT_TYPES.slice(29));

/** Events that the capacity policy always admits, even when a history is full. */
export const ALWAYS_ADMITTED_EVENT_TYPES: ReadonlySet<EventType> = readonlySet<EventType>([
  "AUTHORITY_REVOKED",
  "AGENT_TERMINATED",
  "AGENT_UNAPPOINTED",
  "CONTROL_EPOCH_ADVANCED",
  "ROLE_TRANSFERRED",
  "OBLIGATION_STATUS_RECORDED",
  "OBLIGATION_PERFORMANCE_ASSIGNED",
  "TRANSACTION_INTENT_CONSUMED",
  "TRANSACTION_OUTCOME_RECORDED",
  "RECEIPT_RECORDED",
  "OUTCOME_OBSERVATION_RECORDED",
  "ATTEMPT_DUTY_REVIEW_CLOSED",
  "ANCHOR_RECORDED",
  /** A key compromise response (or the commitment that makes one possible) must never be blocked by a full history. */
  "OWNER_KEYS_ROTATED",
  /** Nor a change of the remote witnesses that guard the history. */
  "WITNESSES_BOUND",
  "WITNESSES_UNBOUND",
  /** Format 2 (SPEC §5.2): control events are never refused by a declared capacity. */
  "BUDGET_DECLARED",
  "BUDGET_UPDATED",
  "BUDGET_CLOSED",
  "STATE_CHECKPOINT",
  "COUNTERPARTY_REGISTERED",
  "COUNTERPARTY_RETIRED",
]);

/** An event as stored: exactly these four keys. `data` is a plain record (bigints allowed). */
export type CanonicalEvent = Readonly<{
  id: string;
  type: EventType;
  timestamp: U53;
  data: Readonly<Record<string, unknown>>;
}>;

export type GenesisVersions = Readonly<Record<string, string>>;

export type GenesisRecord = Readonly<{
  domain: AuthorizationDomain;
  adapterPolicyHash: ContentHash;
  canonicalLineageId: string;
  versions: GenesisVersions;
  policyVersion: string;
  rootRecognitionPolicy: "declared-principal-root/0.2";
  globalPolicySourceId: string;
  timeSource: "EVENT_TIMESTAMP";
  finality: "LOCAL_ONLY";
  /** Format 1 only. */
  ownerKeys?: readonly OwnerKey[];
  /** Format 1 only (pre-rotation): the genesis owner keys' commitment to the digests (`ownerKeyDigest`) of their next keys. */
  nextKeyDigests?: readonly ContentHash[];
  capacity?: Readonly<{ maxEvents: number | null; /** Format 2 (SPEC §5.1): the declared cap on §7.2 state records. */ maxStateRecords?: number | null }>;
  migratedFrom?: MigratedFrom;
  /** Format 2 (SPEC §5.1): automatic checkpoints every that many accepted events (`null` = manual). */
  checkpointPolicy?: Readonly<{ everyEvents: number | null }>;
  /** Format 2 (SPEC §5.1): `"irontrellis-projection/2"` (rows computed; the default when absent) or `null` (projection off). */
  projection?: "irontrellis-projection/2" | null;
  /** Format 2 (A-179.1): the session time horizon of rule T3 in ms (U53 ≥ 1), or `null` (the default: no horizon). */
  sessionTimeHorizonMs?: U53 | null;
  /** Format 2 (A-91): epoch 0's owner approval policy, copied into `ownerKeyEpoch[0].policy`; forbidden with `migratedFrom`. */
  ownerPolicy?: OwnerPolicy;
}>;

/** A-92.1 / A-99: the class of an owner key under a policy, a function of its credential (declared, not evidence). */
export type OwnerKeyClass = "HUMAN" | "AGENT";
/**
 * Format 2 (A-91.1): the owner approval policy of an owner key epoch. `threshold` (1..64) is the number of distinct owner
 * keys that must sign a control (◆) event; `byType` raises or lowers it per ◆ type (`OWNER_KEYS_ROTATED` never below
 * `threshold`); `keyClasses` marks keys `AGENT` (an agent co-signs but never alone, and never counts on a rotation);
 * `labels` and `acknowledged` are annotations replay checks but does not act on.
 */
export type OwnerPolicy = Readonly<{
  threshold: number;
  byType?: Readonly<Partial<Record<EventType, number>>>;
  keyClasses?: Readonly<Record<string, OwnerKeyClass>>;
  labels?: Readonly<Record<string, string>>;
  acknowledged?: "SINGLE_SIGNER";
  /** A-93.1: `ATTESTED` counts a key as human only while an attester's statement about it is valid (absent: `DECLARED` semantics). */
  humanFloor?: "DECLARED" | "ATTESTED";
  /** A-93.1: the attester keys this epoch trusts (1..16; never owner keys, committed keys or foreign credentials). */
  attesters?: readonly OwnerKey[];
  /** A-93.1 / A-107.4: the human-attestation statements this epoch embeds (1..64, at most one per subject credential). */
  attestations?: readonly HumanAttestation[];
  /** A-97.1: a committed next key may sign the rotation that reveals it. */
  recovery?: "COMMITTED_NEXT_KEYS";
}>;
/**
 * A-93.1 / A-107.4: an attester's statement that `subject` was associated with a human under `profile` for
 * `[notBefore, expiresAt)` (milliseconds), signed (`irontrellis-human-attestation/1`) over the object without `signature`.
 * `historyId` (`recordHash(0)`) binds a statement set after the genesis to one history.
 */
export type HumanAttestation = Readonly<{
  version: "irontrellis-human-attestation/1";
  audience: AuthorizationDomain;
  subject: OwnerKey;
  profile: string;
  attesterKeyId: string;
  evidenceDigest: ContentHash;
  notBefore: U53;
  expiresAt: U53;
  historyId?: ContentHash;
  signature: string;
}>;

/**
 * Format 1 only: the legacy source a migrated history re-records at positions
 * 1..`position`. `genesis` is the source genesis data verbatim so replay can
 * rebuild the legacy prefix hashes ("shadow" heads) that the re-recorded
 * runtime-signed events bind.
 */
export type MigratedFrom = Readonly<{
  format: HistoryFormat;
  historyHash: ContentHash;
  position: U53;
  recordHash: ContentHash;
  genesis: GenesisRecord;
  genesisEventId: string;
  genesisTimestamp: U53;
  /** Format 2 (SPEC §16.2 step 4): the source `versions` block as written. */
  versions?: GenesisVersions;
  /** Format 2 (A-40.2): the source pin's `/1` attestation of the migrated head, verified on replay; `null` for a legacy or unpinned source. */
  sourceAttestation?: Readonly<Record<string, unknown>> | null;
  /** Format 2 (A-40.3): 32 random bytes drawn at plan time, so two migrations of copies of one source never share a historyId. */
  migrationId?: ContentHash;
}>;

export type OwnerKey = Readonly<{ keyId: string; scheme: SignatureScheme; credential: string }>;
/**
 * One owner key set and the first position it governs (format 1). The genesis
 * set has `fromPosition: 0`; an `OWNER_KEYS_ROTATED` event at position `r`
 * opens a new epoch with `fromPosition: r + 1` (the rotation itself is signed
 * under the set in force before it). See `ownerKeysAt`.
 *
 * `nextKeyDigests` (pre-rotation): the epoch's commitment to the digests
 * (`ownerKeyDigest`) of the keys that must replace it. It is fixed by the event
 * that opens the epoch (the genesis or the rotation) and never changes; a
 * rotation that leaves a committed epoch must reveal committed keys and prove
 * it holds them. An uncommitted epoch gets a commitment by a rotation that keeps
 * every key and carries `nextKeyDigests` (a commitment-only rotation).
 */
export type OwnerKeyEpoch = Readonly<{
  fromPosition: U53; keys: readonly OwnerKey[]; nextKeyDigests?: readonly ContentHash[];
  /** Format 2 (A-91.3): the epoch's owner approval policy, present iff the event that opened it carried `ownerPolicy`, as written. */
  policy?: OwnerPolicy;
}>;

export type ControlAuthorization = Readonly<{ keyId: string; signature: HexSignature }>;

/**
 * The owner-signed policy minimum a binding event records (docs/reference/witness-policy.md §5.3): `quorum` (1..16, at most the number of
 * witnesses bound after the event, or 1) applies to the bound witnesses, `requireOnOpen` and `maxUnwitnessedEvents`
 * (>= 1) to every reader and writer. The newest binding event's policy is in force.
 */
export type BoundPolicy = Readonly<{ quorum: number; requireOnOpen: boolean; maxUnwitnessedEvents: number }>;
/**
 * A remote witness bound by a `WITNESSES_BOUND` event, as replay applied it. `registration` is the witness's own signed
 * receipt of this history's REGISTERED leaf (verified at replay with `verifierKey`, naming exactly this genesis), when the
 * binding carried one; `index` is its leaf index.
 */
export type BoundWitness = Readonly<{
  url: string;
  verifierKey: string;
  name?: string;
  allowInsecureHttp?: true;
  registration?: Readonly<{ receipt: WitnessReceipt; index: U53 }>;
  eventId: string;
  eventPosition: U53;
}>;

// ---------------------------------------------------------------- authority

export type AuthorityConstraints = Readonly<{
  actions: readonly string[];
  resources: readonly string[];
  quantitative: boolean;
  notBefore?: U53;
  expiresAt?: U53;
  maxAmount?: Amount;
  maxCumulativeAmount?: Amount;
  maxTransactions?: U53;
  maxDelegationDepth: U53;
  requiredIntersectionIds: readonly string[];
}>;

export type PermissionGrant = Readonly<{
  kind: "PERMISSION";
  authorityId: string;
  grantorId: string;
  granteeId: string;
  rootAuthorityId: string;
  parentAuthorityId?: string;
  independent: boolean;
  constraints: AuthorityConstraints;
}>;
export type RootProhibitionGrant = Readonly<{
  kind: "PROHIBITION";
  scope: "ROOT";
  authorityId: string;
  grantorId: string;
  subjectActorId?: string;
  rootAuthorityId: string;
  parentAuthorityId?: string;
  constraints: AuthorityConstraints;
}>;
export type GlobalProhibitionGrant = Readonly<{
  kind: "PROHIBITION";
  scope: "GLOBAL";
  authorityId: string;
  grantorId: string;
  subjectActorId?: string;
  constraints: AuthorityConstraints;
}>;
export type ProhibitionGrant = RootProhibitionGrant | GlobalProhibitionGrant;
export type AuthorityGrant = PermissionGrant | ProhibitionGrant;

export type RecognizedRoot = Readonly<{
  rootAuthorityId: string;
  principalId: string;
  principalRecognitionEventId: string;
  rootGrantEventId: string;
}>;
export type AuthorityUsage = Readonly<{ authorityId: string; admittedTransactionCount: U53; admittedCumulativeAmount: Amount }>;
export type AuthorityEvidence = Readonly<{ authorityId: string; grantEventId: string; grantEventPosition: U53 }>;
export type AuthorityRecord = Readonly<{
  grant: AuthorityGrant;
  grantEventId: string;
  grantEventPosition: U53;
  revocationEventId?: string;
  revocationEventPosition?: U53;
  revokerId?: string;
}>;

// ---------------------------------------------------------------- replay state records

export type PrincipalRecord = Readonly<{ id: string; creationEventId: string; creationEventPosition: U53 }>;
export type AgentRecord = Readonly<{
  id: string;
  principalId: string;
  controllerId: string;
  currentControlEpoch: U53;
  terminated: boolean;
}>;
export type RoleRecord = Readonly<{ id: string; principalId: string; currentTenureId?: string; latestTenureNumber: U53 }>;
export type RoleTenureRecord = Readonly<{
  id: string;
  roleId: string;
  agentId: string;
  principalId: string;
  tenureNumber: U53;
  successionRuleId?: string;
  closed: boolean;
  /** Set by AGENT_TERMINATED; the tenure stays current until a SUCCESSION transfer matching the lock. */
  successionLock?: SuccessionLock;
}>;
export type SuccessionLock = Readonly<{ agentId: string; principalId: string; successionRuleId: string; roleId: string; roleTenureId: string }>;
export type SuccessionRuleData = Readonly<{
  ruleId: string;
  principalId: string;
  predecessorAgentId: string;
  successorAgentId: string;
  roleId: string;
  trigger: "AGENT_TERMINATED";
  permittedEventTypes: readonly string[];
}>;
export type RuntimeSessionRecord = Readonly<{
  id: string;
  agentId: string;
  controllerId: string;
  controlEpoch: U53;
  credentialKeyId: string;
  /** Lowercased address (legacy) or the public-key credential (format 1). */
  credentialAddressKey: string;
  credentialScheme: SignatureScheme;
  admissionEventId: string;
  admissionEventPosition: U53;
  expiresAt?: U53;
}>;

export type AdapterProfile = Readonly<{ profileId: string; profileVersion: string; descriptorHash: ContentHash }>;
export type TransactionIntent = Readonly<{
  adapterProfile: AdapterProfile;
  intentId: string;
  nonce: string;
  actorId: string;
  action: string;
  resource: string;
  roleId: string;
  roleTenureId: string;
  amount?: Amount;
  counterpartyId?: string;
  termsCommitment?: ContentHash;
  /** Format 2 (SPEC §8.6): the metric the intent is measured in (absent ≡ `"amount"`). */
  metric?: string;
}>;
/**
 * `data`: the intent fields with engine amounts (bigint). Format 2 adds `declarationDigest` (the
 * `declarationAuthorization.hash`, `null` in a migrated prefix) for the §7.2 `intent` record.
 */
export type IntentDeclarationRecord = Readonly<{ data: TransactionIntent; declarationDigest?: ContentHash | null }>;
export type AdapterIdentity = Readonly<Record<string, unknown>>;
export type IntentAdmissionRecord = Readonly<{
  intentId: string;
  actorId: string;
  nonce: string;
  admissionEventId: string;
  admissionEventPosition: U53;
  admissionHead: HistoryHead;
  runtimeSessionId: string;
  credentialKeyId: string;
  controlEpoch: U53;
  roleId: string;
  roleTenureId: string;
  adapterIdentity: AdapterIdentity;
}>;
export type NonceReservation = Readonly<{ intentId: string; admissionEventId: string; admissionEventPosition: U53; admissionHead: HistoryHead }>;
/** Format 2 (SPEC §7.2 `nonce`): created by the declaration; keyed `hashCanonical([actorId, nonce])`. */
export type NonceRecord = Readonly<{ actorId: string; nonce: string; intentId: string; position: U53 }>;
/** Format 2 (SPEC §7.2 `usage`): a counter per authority that controlled at least one admission (distinct from `authorityUsage`). */
export type UsageCounter = Readonly<{ authorityId: string; admittedTransactionCount: U53; admittedCumulativeAmount: Amount }>;
export type IntentConsumptionRecord = Readonly<{
  intentId: string;
  eventId: string;
  eventPosition: U53;
  head: HistoryHead;
  adapterId: string;
  idempotencyKey: string;
  submissionFingerprint: ContentHash;
  transactionReference: string;
  acknowledgment: Readonly<Record<string, unknown>>;
  evidenceReference: Readonly<Record<string, unknown>>;
}>;
export type OutcomeRecord = Readonly<{
  intentId: string;
  eventId: string;
  eventPosition: U53;
  head: HistoryHead;
  status: string;
  attesterId: string;
  evidenceReference: Readonly<Record<string, unknown>>;
  noEffect?: Readonly<Record<string, unknown>>;
}>;
export type IntentOutcomeState = Readonly<{ latest: OutcomeRecord; terminal?: OutcomeRecord }>;
export type OutcomeObservationRecord = Readonly<{
  intentId: string;
  sourceAdmissionEventId: string;
  acknowledgment: Readonly<Record<string, unknown>>;
  actorId: string;
  eventId: string;
  eventPosition: U53;
  observedAt: U53;
}>;
export type AttemptDutyRecord = Readonly<Record<string, unknown>> & Readonly<{ dutyId: string; sourceIntentId: string }>;
export type AttemptDutyState = Readonly<{
  record: AttemptDutyRecord;
  creationEventId: string;
  creationEventPosition: U53;
  creationActorId: string;
  currentAssigneeId: string;
  assignments: readonly Readonly<Record<string, unknown>>[];
}>;
/** SPEC §13.1 (E4): the in-memory activation record (the frozen `PortableDutyPolicyActivation` shape: full `priorHead`, `eventPosition`); the §7.2 `duty.policy` record is derived from it. */
export type DutyPolicyActivationRecord = Readonly<{
  descriptor: Readonly<Record<string, unknown>> & Readonly<{ dutyId: string; sourceAdmissionEventId: string; acceptedAttesterRoleId: string; principalId: string; durableRoleId: string }>;
  descriptorHash: ContentHash; activationAuthorityId: string; actorId: string;
  eventId: string; eventPosition: U53; activatedAt: U53; priorHead: HistoryHead; dispositionCount: U53; contestCount: U53;
}>;
/** SPEC §13.2 (E4): one accepted disposition or contest of a duty (the §7.2 `duty.dispositions` row). */
export type DutyDispositionRefRecord = Readonly<{ eventId: string; position: U53; type: "ATTEMPT_DUTY_DISPOSITION_RECORDED" | "ATTEMPT_DUTY_CONTEST_RECORDED"; findingHash: ContentHash }>;
export type AttemptDutyReview = Readonly<{
  dutyId: string;
  actorId: string;
  observationEventIds: readonly string[];
  summaryDigest: ContentHash;
  eventId: string;
  eventPosition: U53;
  reviewedAt: U53;
}>;
export type ReceiptCommitmentRecord = Readonly<Record<string, unknown>> &
  Readonly<{ intentId: string; receiptContentHash: ContentHash; eventId: string; eventPosition: U53; head: HistoryHead }>;
export type ObligationStatus = "OPEN" | "OUTCOME_UNKNOWN" | "PERFORMED" | "FAILED" | "CANCELLED" | "WAIVED";
export type ObligationTransitionPolicy = Readonly<{
  fromStatus: string;
  toStatus: string;
  action: string;
  acceptedAttesterIds: readonly string[];
  requiredAuthorityIds: readonly string[];
}>;
export type ObligationRecord = Readonly<{
  obligationId: string;
  sourceIntentId: string;
  causalReceiptContentHash: ContentHash;
  durableRoleId: string;
  creationRoleTenureId: string;
  description: string;
  trigger: string;
  deadline: U53;
  status: string;
  beneficiaryId: string;
  termsCommitment: ContentHash;
  performanceAssigneeId: string;
  successionRuleId: string;
  counterpartyId?: string;
  transitionPolicies: readonly ObligationTransitionPolicy[];
}>;
export type ObligationState = Readonly<{
  record: ObligationRecord;
  status: string;
  performanceAssigneeId: string;
  creationEventId: string;
  creationEventPosition: U53;
  creationHead: HistoryHead;
}>;

/**
 * The replay state. The iteration order of its Maps and Sets is unspecified in the public API (A-188.2): identity is the
 * record set (SPEC §7.1), and a comparator that needs an order sorts by key. Where the engine itself relies on an order,
 * it is the order of each record's position. The engine mutates a `MutableReplayState` during replay/append; everything
 * outside receives it as `ReplayState`.
 */
export interface ReplayState {
  readonly format: HistoryFormat;
  readonly hashAlgorithm: HashAlgorithm;
  readonly signatureScheme: SignatureScheme;
  readonly events: readonly CanonicalEvent[];
  readonly eventHistoryHashes: readonly ContentHash[];
  readonly eventPositionsById: ReadonlyMap<string, U53>;
  readonly head: HistoryHead;
  readonly genesis: GenesisRecord;
  readonly principals: ReadonlyMap<string, PrincipalRecord>;
  readonly agents: ReadonlyMap<string, AgentRecord>;
  readonly reservedAgentIds: ReadonlyMap<string, ReadonlySet<string>>;
  readonly roles: ReadonlyMap<string, RoleRecord>;
  readonly successionRules: ReadonlyMap<string, Readonly<{ data: SuccessionRuleData }>>;
  readonly tenures: ReadonlyMap<string, RoleTenureRecord>;
  readonly currentTenureIdsByAgent: ReadonlyMap<string, ReadonlySet<string>>;
  readonly runtimeSessions: ReadonlyMap<string, RuntimeSessionRecord>;
  readonly runtimeSessionIdsByAgent: ReadonlyMap<string, readonly string[]>;
  readonly credentialKeyIds: ReadonlySet<string>;
  readonly credentialAddressKeysByAgent: ReadonlyMap<string, ReadonlySet<string>>;
  readonly intentDeclarations: ReadonlyMap<string, IntentDeclarationRecord>;
  readonly intentAdmissions: ReadonlyMap<string, IntentAdmissionRecord>;
  readonly intentConsumptions: ReadonlyMap<string, IntentConsumptionRecord>;
  readonly intentOutcomeStates: ReadonlyMap<string, IntentOutcomeState>;
  readonly outcomeObservations: ReadonlyMap<string, readonly OutcomeObservationRecord[]>;
  readonly attemptDuties: ReadonlyMap<string, AttemptDutyState>;
  readonly attemptDutyReviews: ReadonlyMap<string, readonly AttemptDutyReview[]>;
  readonly attemptDutyIdsBySourceIntent: ReadonlyMap<string, string>;
  /** SPEC §13 (E4): the active duty policies by dutyId (`duty-policy.ts DutyPolicyActivation`) and, per duty, its accepted dispositions and contests in position order. */
  readonly attemptDutyPolicies: ReadonlyMap<string, DutyPolicyActivationRecord>;
  readonly attemptDutyDispositions: ReadonlyMap<string, readonly DutyDispositionRefRecord[]>;
  readonly receiptCommitments: ReadonlyMap<string, ReceiptCommitmentRecord>;
  readonly obligations: ReadonlyMap<string, ObligationState>;
  readonly obligationIdsBySourceIntent: ReadonlyMap<string, string>;
  readonly nonceReservationsByActor: ReadonlyMap<string, ReadonlyMap<string, NonceReservation>>;
  readonly authorities: ReadonlyMap<string, AuthorityRecord>;
  readonly recognizedRoots: ReadonlyMap<string, RecognizedRoot>;
  readonly authorityUsage: ReadonlyMap<string, AuthorityUsage>;
  /**
   * Format 1: the owner key sets in force, oldest first (`fromPosition` strictly
   * increasing; the first is the genesis set at 0). Legacy histories hold one
   * epoch with no keys. Read it through `ownerKeysAt(state, position)`.
   */
  readonly ownerKeyEpochs: readonly OwnerKeyEpoch[];
  /** Format 1: anchored heads in event order. */
  readonly anchors: readonly Readonly<{ head: HistoryHead; anchor: string; eventId: string; eventPosition: U53 }>[];
  /**
   * Format 1: the remote witnesses the history binds, in binding order: every `WITNESSES_BOUND` /
   * `WITNESSES_UNBOUND` event applied in turn (a re-binding replaces the record in place). Nothing else binds.
   */
  readonly boundWitnesses: readonly BoundWitness[];
  /** Format 1: the owner-signed witness policy minimum of the newest binding event (`undefined`: none yet). */
  readonly boundPolicy: BoundPolicy | undefined;
  /** Migrated histories only: the legacy prefix hashes for positions 0..migratedFrom.position (the heads the re-recorded events bind). */
  readonly shadowHashes?: readonly ContentHash[];
  // ---- format 2 (SPEC §7, §12); empty / undefined for legacy and format-1 states
  /**
   * Format 2: event references the §7.2 records need that the format-1 records (byte-identical to the reference kernel) do
   * not carry, keyed `kind\u0000id`: `agent` (creation, termination), `role` and `succession` (creation), `tenure` (opening,
   * ending), `obligation` (latest assignment and status events) and `intentOutcomes` (every outcome, in order). Iteration
   * order unspecified (A-188.2): sort by key where an order is needed; an entry equal to the empty record may be absent.
   */
  readonly recordRefs: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
  /** Format 2: the §7.2 nonce records created at declaration, keyed `hashCanonical([actorId, nonce])`. */
  readonly nonceRecords: ReadonlyMap<string, NonceRecord>;
  /** Format 2: the §7.2 `usage` counters (every controlling authority of every admission). */
  readonly usageCounters: ReadonlyMap<string, UsageCounter>;
  /** Format 2: the §7.1 state records, keyed `kind\u0000key`, each with its leaf hash. */
  readonly stateRecords: ReadonlyMap<string, StateRecordEntry>;
  /** Format 2: `rootAt(p)` for every position `p` (SPEC §7.1), kept so checkpoints and attestations verify without a replay. */
  readonly stateRoots: readonly ContentHash[];
  /** Format 2: `projectionHead(p)` for every position (SPEC §12.3); empty when the genesis turned the projection off. */
  readonly projectionHeads: readonly ContentHash[];
  /** Format 2 (E2, SPEC §9–§11): the budget, budget-usage, counterparty, refusal and effect records, as the §7.2 records. */
  readonly budgets: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
  readonly budgetUsage: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
  readonly counterparties: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
  readonly refusals: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
  readonly effects: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
  /** A-71.4: the `observation` records by observationId and the `reconciliation-cursor` records by their key. */
  readonly reconciliationObservations: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
  readonly reconciliationCursors: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
  /**
   * Format 2 (SPEC §5.2, `capacity.ts`): the bytes of the canonical store lines of every accepted event (what the
   * store writes for them) and the reservation ledger (declared jobs → lifecycle record types produced, duty and
   * obligation ids → job, duty-policy quotas, the two reserved sums). All zero/empty for legacy and format 1.
   */
  readonly canonicalBytes: number;
  readonly capacityIntents: ReadonlyMap<string, ReadonlySet<EventType>>;
  readonly capacityDuties: ReadonlyMap<string, string>;
  readonly capacityObligations: ReadonlyMap<string, string>;
  readonly capacityDutyQuota: ReadonlyMap<string, Readonly<{ dispositions: number; contests: number }>>;
  readonly lifecycleReserved: number;
  readonly dutyReserved: number;
}

/** One §7.2 state record with its §7.1 leaf hash (32 bytes). */
export type StateRecordEntry = Readonly<{ kind: string; key: string; record: Readonly<Record<string, unknown>>; leaf: Uint8Array }>;

export type ReplayCode =
  | "INVALID_INPUT"
  | "UNSUPPORTED_VERSION"
  | "UNSUPPORTED_EVENT_SCHEMA"
  | "UNSUPPORTED_EVENT_TYPE"
  | "GENESIS_REQUIRED"
  | "GENESIS_DUPLICATE"
  | "EVENT_ID_DUPLICATE"
  | "EVENT_TIME_REGRESSION"
  | "EVENT_DATA_INVALID"
  | "TRANSITION_INVALID"
  | "CONTROL_AUTHORIZATION_INVALID"
  // Format 2 (SPEC §18)
  | "CAPACITY_CONTROL_ONLY"
  | "CAPACITY_EXCEEDED"
  /** The control-event reserve below a hard limit (BUILD-INSTRUCTIONS addendum): only ◆ control events are admitted. */
  | "CAPACITY_RESERVED"
  | "DECLARATION_AUTHORIZATION_INVALID"
  | "REFUSAL_AUTHORIZATION_INVALID"
  | "REFUSAL_NOT_REPRODUCED"
  | "EFFECT_AUTHORIZATION_INVALID"
  | "EFFECT_LIMIT"
  | "COUNTERPARTY_SIGNATURE_INVALID"
  | "RECORD_AUTHORIZATION_INVALID"
  | "STATE_ROOT_MISMATCH"
  | "PROJECTION_HEAD_MISMATCH"
  /** A-29 / A-58.5 (format 2): the signing session (any ◇ type, admissions and 14–16 included, and the outer ▲ session) belongs to an earlier control epoch of its agent. */
  | "SESSION_FENCED"
  /** A-71.3 / A-89.3: a well-formed type-42 authorization that fails §6.2 (other than the fence), its hash or its signature. */
  | "OBSERVATION_AUTHORIZATION_INVALID"
  /** A-71.3 / A-86.1: an observation with this `(streamId, eventRef, eventDigest)` is already accepted (recorded: advance the checkpoint). */
  | "OBSERVATION_DUPLICATE";

export type ReplayResult =
  | Readonly<{
    status: "ACCEPTED"; state: ReplayState; head: HistoryHead; eventCount: U53;
    /** Format 2 only (SPEC §17): `rootAt(head.position)` and `projectionHead(head.position)` (`null` with the projection off). */
    stateRoot?: ContentHash; projectionHead?: ContentHash | null;
  }>
  | Readonly<{ status: "REJECTED"; code: ReplayCode; position?: U53; reason?: string }>;

// ---------------------------------------------------------------- authorization

export type ActionRequest = Readonly<{
  actorId: string;
  action: string;
  resource: string;
  claimedAt: U53;
  amount?: Amount;
  counterpartyId?: string;
  termsCommitment?: ContentHash;
  /** Format 2 (SPEC §8.2): the metric the amount is measured in (absent ≡ `"amount"`); refused in legacy and format-1 requests. */
  metric?: string;
}>;

export type ConsequentialBinding = Readonly<{
  runtimeSessionId: string;
  credentialKeyId?: string;
  controlEpoch: U53;
  roleId: string;
  roleTenureId: string;
  intentId?: string;
  nonce?: string;
  runtimeSignature?: HexSignature;
}>;

export type AuthorizeInput = Readonly<{
  operationVersion: "continuity-authorization/0.2";
  events: readonly CanonicalEvent[];
  expectedHistoryHead: HistoryHead;
  domain: AuthorizationDomain;
  policyVersion: string;
  rootRecognitionPolicy: string;
  request: ActionRequest;
  evaluationTime: U53;
  authoritative: true;
  consequential: boolean;
  binding?: ConsequentialBinding;
}>;

export type EvidenceReference = Readonly<{
  kind: "EVENT";
  eventId: string;
  eventType: string;
  position: U53;
  historyHash: ContentHash;
}>;

export type DenialCode =
  | "DOMAIN_MISMATCH"
  | "POLICY_MISMATCH"
  | "INVALID_REQUEST"
  | "INVALID_AMOUNT"
  | "INVALID_DELEGATION"
  | "AGENT_INACTIVE"
  | "SESSION_NOT_FOUND"
  | "SESSION_EXPIRED"
  | "SESSION_CREDENTIAL_REQUIRED"
  | "SESSION_CREDENTIAL_INVALID"
  | "SESSION_FENCED"
  | "STALE_EPOCH"
  | "ROLE_TENURE_NOT_CURRENT"
  | "INTENT_REQUIRED"
  | "INTENT_NOT_DECLARED"
  | "INTENT_MISMATCH"
  | "INTENT_REPLAY"
  | "NONCE_ALREADY_ADMITTED"
  | "PROHIBITED"
  | "REVOKED"
  | "NOT_YET_VALID"
  | "EXPIRED"
  | "MISSING_INTERSECTION"
  | "ACTION_NOT_ALLOWED"
  | "RESOURCE_NOT_ALLOWED"
  | "AMOUNT_REQUIRED"
  | "AMOUNT_EXCEEDED"
  | "CUMULATIVE_AMOUNT_EXCEEDED"
  | "TRANSACTION_COUNT_EXCEEDED"
  | "NO_AUTHORITY"
  // Format 2 (SPEC §18): the budget procedure (§9.4) and the §3.3 closure rule
  | "BUDGET_PER_OPERATION_EXCEEDED"
  | "BUDGET_COUNT_EXCEEDED"
  | "BUDGET_AMOUNT_EXCEEDED"
  | "BUDGET_PERIOD_UNDEFINED"
  | "BUDGET_SET_TOO_LARGE"
  | "AMOUNT_OVERFLOW";

export type IndeterminateCode =
  | "INVALID_INPUT"
  | "UNSUPPORTED_VERSION"
  | "STATE_NOT_AUTHORITATIVE"
  | "HISTORY_RELATION_UNVERIFIED"
  | "CAUSAL_TIME_INVALID"
  | "OUTPUT_LIMIT"
  /** The code the legacy engine actually emits for output-budget overruns (spec 02 §6.2/§6.3). */
  | "OUTPUT_LIMIT_EXCEEDED"
  | "EVIDENCE_UNAVAILABLE"
  | "EVIDENCE_DISPUTED";

export type DenialEvidence = Readonly<{
  code: DenialCode;
  subjectId?: string;
  rootAuthorityId?: string;
  terminalAuthorityId?: string;
  failingAuthorityId?: string;
  authorityPathIds: readonly string[];
  evidence: readonly EvidenceReference[];
}>;
export type IndeterminateEvidence = Readonly<{ code: IndeterminateCode; subjectId?: string; evidence: readonly EvidenceReference[] }>;

/** One selected intersection partner inside an ALLOW proof (spec 02 §6.3). */
export type IntersectionProof = Readonly<{
  requiredAuthorityId: string;
  requiredByAuthorityIds: readonly string[];
  recognizedRoot: RecognizedRoot;
  path: readonly PermissionGrant[];
  effectiveConstraints: AuthorityConstraints;
}>;
/**
 * The ALLOW proof, exactly as the legacy engine emits it (spec 02 §6.3). Runtime fields only when consequential.
 * In format 2 (SPEC §8.3) every Amount field of an emitted proof (`request.amount`, the `maxAmount`/`maxCumulativeAmount`
 * of every constraints record, `usageSnapshot[].admittedCumulativeAmount`) is an `AmountString`; the type keeps `Amount`
 * because the engine builds the proof with bigints and converts once at the wire boundary (`wireAmounts`).
 */
export type AuthorizationProof = Readonly<{
  proofVersion: string;
  domain: AuthorizationDomain;
  policyVersion: string;
  rootRecognitionPolicy: string;
  historyHead: HistoryHead;
  evaluationTime: U53;
  request: ActionRequest;
  recognizedRoot: RecognizedRoot;
  permissionPath: readonly PermissionGrant[];
  intersections: readonly IntersectionProof[];
  effectiveConstraints: AuthorityConstraints;
  controllingAuthorityIds: readonly string[];
  usageSnapshot: readonly AuthorityUsage[];
  authorityEvidence: readonly AuthorityEvidence[];
  checkedProhibitionIds: readonly string[];
  consequential: boolean;
  runtimeSessionId?: string;
  credentialKeyId?: string;
  controlEpoch?: U53;
  roleId?: string;
  roleTenureId?: string;
  intentId?: string;
  nonce?: string;
}>;

/** What replay derives from the pre-event state for a signed administrative event (spec 03 §I.2). */
export type AdministrativeRequirements = Readonly<{
  request: ActionRequest;
  requiredPrincipalId: string;
  requiredAuthorityIds: readonly string[];
  roleId: string;
  roleTenureId: string;
}>;

/** The structure a runtime signs for a consequential authorization (spec 02 §5.1). */
export type RuntimeAuthorizationChallenge = Readonly<{
  version: string;
  domain: AuthorizationDomain;
  request: ActionRequest;
  authoritative: true;
  consequential: true;
  evaluationTime: U53;
  policyVersion: string;
  rootRecognitionPolicy: string;
  eventHistoryHash: ContentHash;
  eventHistoryPosition: U53;
  runtimeSessionId: string;
  credentialKeyId: string;
  controlEpoch: U53;
  roleId: string;
  roleTenureId: string;
  intentId: string;
  nonce: string;
}>;

export type ScopeAssurance = "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";

export type AuthorizationResult =
  | Readonly<{ operationVersion: string; decision: "ALLOW"; scopeAssurance: ScopeAssurance; consequential: boolean; proof: AuthorizationProof }>
  | Readonly<{
    operationVersion: string; decision: "DENY"; scopeAssurance: ScopeAssurance; consequential: false; code: DenialCode; failures: readonly DenialEvidence[];
    /** Format 2 (SPEC §8.1): the budget that decided a `BUDGET_*` / `AMOUNT_OVERFLOW` denial; absent (`null` on the wire) otherwise. */
    budgetId?: string | null;
  }>
  | Readonly<{ operationVersion: string; decision: "INDETERMINATE"; scopeAssurance: ScopeAssurance; consequential: false; code: IndeterminateCode; failures: readonly IndeterminateEvidence[] }>;

export type Decision = AuthorizationResult["decision"];
