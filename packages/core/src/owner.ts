/**
 * The local owner API (port of Core 0.3 `local-owner.ts` + `local-store.ts`
 * onto the incremental store), with the docs/API.md §1 additions: delegations,
 * prohibitions, terminations, unappointments, `verify`, `handover`, and
 * format 1 (signed control events, owner key file). Every write is async
 * because format-1 control signing may go through a KMS; queries stay sync.
 *
 * The exported `configuration` / `openStore` / `currentState` / `appendEvent`
 * helpers are shared with execution.ts, runtime.ts and attempts.ts; they are
 * privileged host plumbing, not an agent-facing surface.
 */
import { randomUUID } from "node:crypto";
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { canonicalEncode, isContentHash, wireAmounts } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { headroom as headroomState } from "./budgets.ts";
import { inspectDutyPolicyOf, type DutyPolicyView } from "./duty-policy.ts";
import { exportViewState, type ExportView, type ExportViewInput } from "./export-view.ts";
import { STATE_DERIVATION_VERSION } from "./events.ts";
import { projectionHeadAt, rootAt, stateRecordsOf, stateRootOfRecords } from "./state-records.ts";
import { ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH, ADAPTER_POLICY_HASH } from "./adapter-editions.ts";
import { ADDITIONAL_CONTROL_AUTHORIZATIONS, controlAuthorizationChallenge, controlAuthorizationHash, controlEffect, controlEffectHash, FORMAT2_VERSIONS, isFormat2, isTrellis, LEGACY_FORMAT, LEGACY_VERSIONS, PROJECTION_VERSION, ROOT_RECOGNITION_POLICY, TRELLIS2_FORMAT, TRELLIS_FORMAT, TRELLIS_VERSIONS, validateEvent, validateGenesis } from "./events.ts";
import { applyEvent, createReplayState, forkReplayState, replayFrom, withProspectiveEvent } from "./replay.ts";
import {
  createNextOwnerKeyFile, createOwnerKeyFile, keyIdFileFragment, loadNextOwnerKeyFile, loadOwnerKeyFile, nextOwnerKeyPathFor, ownerKeyPathFor, pendingNextOwnerKeyPathFor,
  pendingOwnerKeyPathFor, promoteNextOwnerKeyFile, retiredOwnerKeyFilesFor, retiredOwnerKeyPathFor, signControlEvent, writeKeyReferenceFile, type Signer,
} from "./signer.ts";
import type { SignerClass } from "./owner-policy.ts";
import { controlQuorum, controlQuorumFailure, controlRuleAt, controlSignatureFailure, eligibleSigners, keepsEveryOwnerKey, ownerKeyDigest, ownerKeyInForce, ownerKeyRotationCounts, ownerKeysAt, ownerPolicyAt, singleSignerTimeFailure, type ControlSigner } from "./owner-keys.ts";
import { controlThreshold, effectiveThreshold, isDefaultOwnerPolicy, ownerKeyClass, ownerPolicyFailure, sameOwnerPolicy } from "./owner-policy.ts";
import type { SignContext } from "./custody/registry.ts";
import {
  OWNER_KEY_REF_VERSION, OWNER_NEXT_KEY_REF_VERSION, parseKeyReference, parsePublicKey, publicKeySigner, withReferenceVersion, type KeyReferenceVersion, type OwnerKeyReference,
} from "./custody/reference.ts";
import {
  judgePendingRotation, pendingRotationPathFor, pendingRotationSealHash, PENDING_ROTATION_VERSION, readPendingRotation, removePendingRotation, writePendingRotation, type PendingRotationRecord,
} from "./rotation-pending.ts";
import { KEY_EVENT_BUNDLE_VERSION, keyEventBundlePathFor, type KeyEventBundle } from "./transparency/bundle.ts";
import { HEAD_STATEMENT_VERSION, signHeadStatement, type SignedHeadStatement } from "./transparency/statement.ts";
import { counterpartyStateOf, type CounterpartyState } from "./session-writes.ts";
import { createHistoryStore, markerTargetPath, openHistoryStore, readMigratedMarker, witnessSessionOf, type HistoryStore, type PinnedHead, type RemoteVerifyOptions } from "./store.ts";
import type { AnchorTarget, VerificationReport } from "./anchor.ts";
import { normalizeWitnessConfig, normalizeWitnessPolicy, normalizeWitnessUrl, remoteWitness, type RemoteWitnessConfig, type WitnessMode, type WitnessPolicy } from "./witness-client.ts";
import {
  bindingPolicyOf, boundPolicyOf, boundRegistrationOf, boundWitnessesOf, witnessBindingEvent, type AcceptedLossRecord, type BindingWitness, type BoundPolicy, type WitnessBindingAction,
  type WitnessStatusReport, type WitnessView,
} from "./witness-session.ts";
import { minimumWitnessPolicy, storedPolicyOf, type StoredWitnessConfig } from "./witness-state.ts";
import type { WitnessReceipt } from "./transparency/receipt.ts";
import { assertCapacityTransition, capacityOf, RESERVE_THRESHOLD_BYTES, RESERVE_THRESHOLD_RECORDS, type CapacityReport } from "./capacity.ts";
import { sameHead } from "./admission.ts";
import { hasFormat1TestTooling } from "./format1-tooling.ts";
import { sessionExpiredAt } from "./session-auth.ts";
import { sessionTimeHorizonOf } from "./session-time.ts";
import { assertSessionWriteTime } from "./session-write-checks.ts";
import { IronTrellisError, type IronTrellisErrorCode, amount, captureData, contentHash, identifier, identifiers, optional, record, requireCondition, time } from "./input.ts";
import { observeState, type Action, type Observation, type ObservationOptions } from "./observation.ts";
import { publicQueryDisclosure, survivesState, type SurvivesQueryResult } from "./queries.ts";
import { replaceFileSync, syncDirectorySync } from "./platform.ts";
import {
  CONTROL_EVENT_TYPES, POWER_REDUCING_TYPES, type AuthorityConstraints, type AuthorizationDomain, type CanonicalEvent, type ContentHash, type EventType, type HistoryFormat,
  type HexSignature, type HistoryHead, type LegacyDomain, type OwnerKey, type OwnerKeyEpoch, type OwnerPolicy, type ReplayState, type SignatureScheme, type TrellisDomain, type U53,
} from "./types.ts";

// ---------------------------------------------------------------- configuration

/** Genesis `policyVersion` per format. The legacy literal is the one Core 0.3 wrote, so its SDK can reopen our legacy files. */
export const POLICY_VERSIONS = Object.freeze({ [LEGACY_FORMAT]: "continuity-local-owner/0.3-preview.1", [TRELLIS_FORMAT]: "irontrellis-local-owner/1", [TRELLIS2_FORMAT]: "irontrellis-local-owner/2" });
/** @deprecated Core 0.3 name for the legacy policy literal. */
export const POLICY = POLICY_VERSIONS[LEGACY_FORMAT];

export type LocalOwnerOptions = Readonly<{
  historyFile: string;
  domain: AuthorizationDomain;
  owner: string;
  controller: string;
  /** Trusted host clock: Unix milliseconds as a u53 (format 2 reads every timestamp as milliseconds). */
  now: () => number;
  /**
   * History format for `createLocalOwner`; open autodetects. Default format 2 (`irontrellis-event/2`, SPEC §19).
   * Naming format 1 or legacy explicitly asks for the format-1-era writer of that format (kept for compatibility: a history a
   * handle created that way stays writable through a handle that names the same format); without it, a legacy or
   * format-1 file opens read only and every write is `FORMAT_READ_ONLY {reason}` (SPEC §16.1) — migrate it to format 2.
   */
  format?: HistoryFormat;
  /** Owner key for control events, formats 1 and 2 (KMS/HSM path). Default: the `<historyFile>.owner-key.json` key file. */
  signer?: Signer;
  /** Formats 1 and 2: capacity budget stored in the genesis (`null`/absent = unlimited). */
  maxEvents?: number | null;
  /** Format 1 only: runtime signature scheme declared by the genesis (default `ed25519`). */
  signatureScheme?: SignatureScheme;
  /** Format 2 (SPEC §5.1): the declared cap on §7.2 state records (`null`/absent = none; the hard limit always applies). */
  maxStateRecords?: number | null;
  /** Format 2 (SPEC §7.3): automatic `STATE_CHECKPOINT`s every that many accepted events (`{everyEvents: null}`/absent = manual, plus after a handover). */
  checkpointPolicy?: Readonly<{ everyEvents: number | null }>;
  /** Format 2 (SPEC §5.1, §12): `"irontrellis-projection/2"` (default: rows computed) or `null` (projection off, `projectionHead` null everywhere). */
  projection?: "irontrellis-projection/2" | null;
  /**
   * Format 2 (A-179.1): the genesis session time horizon in ms (≥ 1): a session-signed or administrative event may carry
   * history time at most this far past the latest time-advancing owner event (rule T3). Absent or `null`: no horizon.
   */
  sessionTimeHorizonMs?: number | null;
  /**
   * Format 2 (docs/API.md §2): whether a runtime handle records a `REQUEST_REFUSED` for every DENY/INDETERMINATE it
   * decides before executing (`"record"`, the default) or not (`"off"`). Owner handles ignore it.
   */
  refusals?: "record" | "off";
  /**
   * A-23 / A-38: refusal recording limits — `coalesceMs` (default 60,000: an identical refusal of the same actor younger
   * than this is not recorded, `COALESCED`), `maxPerMinute` (default 6 per actor: `RATE_LIMITED`), `recordBudgetMs`
   * (default 250: hooks and the gateway spool a refusal they cannot record in time, `SPOOLED`).
   */
  refusalPolicy?: Readonly<{ coalesceMs?: number; maxPerMinute?: number; recordBudgetMs?: number }>;
  /**
   * Format 2 (SPEC §7.5): how the history is read on open — `CHECKPOINT_RESUME` (the default for the local API: resume
   * from the engine-private snapshot, after rollback detection and with the state root recomputed and matched against an
   * owner-signed root) or `FULL_REPLAY` (replay every event, as `verifyHistory` and `migrateHistory` always do).
   */
  trust?: "FULL_REPLAY" | "CHECKPOINT_RESUME";
  /** Addendum A-19.4: the expected history identity (`recordHash(0)`); a file whose genesis line differs is refused with `HISTORY_IDENTITY_MISMATCH`. */
  historyId?: ContentHash;
  /** Identifier generator for event, lineage and policy ids (default `randomUUID`); injectable for reproducible histories. */
  ids?: () => string;
  /**
   * Proceed when the file does not contain its pinned head, the pin is
   * malformed, or a format-1 or format-2 history has lost its pin: the file is re-pinned as
   * it is (attested with the owner key when available) and the pin records
   * `rollbackAcceptedAt` and the previous pin.
   */
  acceptRollback?: boolean;
  /** Read a format-1 or format-2 history whose pin is missing or unattested (writes still refuse a missing pin). */
  allowUnpinned?: boolean;
  /**
   * A-41.2: lets an enforcement caller (`run()`, `authorize`, the execution handles, hooks, the gateway) act on a
   * legacy or format-1 history that was never migrated (no `.migrated` marker), with a warning on every open. There is
   * no opt-in for a fenced history. Without it such a history is `FORMAT_READ_ONLY {reason: LEGACY | FORMAT_1}` for
   * enforcement (verify, inspect, queries, the export view and migrate keep reading it).
   */
  enforceFromReadOnlyHistory?: boolean;
  /**
   * `createLocalOwner`: adopt an owner key file already at `<historyFile>.owner-key.json` instead of refusing with `KEY_EXISTS`
   * (and, likewise, a next-key file already at `<historyFile>.owner-next-key.json`).
   */
  reuseExistingKey?: boolean;
  /**
   * `createLocalOwner`, format 1 (pre-rotation): the genesis commits the owner keys to a next owner key
   * (`nextKeyDigests`, part of the history id), so a leaked current key alone can never rotate them. Default true: a new
   * Ed25519 next key is written to `<historyFile>.owner-next-key.json` (mode 0600; move it off the agent host) unless
   * `nextSigner`, `nextPublicKey` or `nextKeyReference` names the key. `false` creates the history without a commitment
   * (`LocalOwner#commitNextKey` adds one later, as a rotation that keeps the owner keys). Ignored by the open.
   */
  nextKey?: boolean;
  /** `createLocalOwner`: commit to this key (e.g. an offline HSM or KMS key) instead of generating a next-key file. */
  nextSigner?: Signer;
  /**
   * `createLocalOwner`, format 2 (A-91): more owner keys for the genesis, beside the handle's own key (public keys only: each
   * is held by another person or device that signs out of band, see `prepareControlEvent`). 1..63 keys with distinct key
   * ids and credentials. Without `ownerPolicy` any one key signs alone, as today.
   */
  coOwnerKeys?: readonly OwnerKey[];
  /**
   * `createLocalOwner`, format 2 (A-91): the owner approval policy of epoch 0 (how many owner keys sign each control event).
   * The handle writes the principal (and a witness binding) alone at creation, so those types must need one signature;
   * a stricter policy is set after creation with `rotateOwnerPolicy` (or `prepareOwnerPolicyRotation`).
   */
  ownerPolicy?: OwnerPolicy;
  /**
   * `createLocalOwner`, format 1 (docs/CUSTODY.md): the owner key is held by a signer (ssh-agent, command, …) named by
   * this key reference, which is written to `<historyFile>.owner-key.json` (mode 0600, exclusive: KEY_EXISTS when a file
   * is there unless `reuseExistingKey`) instead of generating key material. Every signature is asked of that signer and
   * verified against the reference's public key. Excludes `signer`.
   */
  ownerKeyReference?: OwnerKeyReference;
  /**
   * `createLocalOwner`: commit to the key this reference names (the next key held by a signer); the reference is written
   * to `<historyFile>.owner-next-key.json` (it holds no secret). Excludes `nextSigner`, `nextPublicKey` and `nextKey: false`.
   */
  nextKeyReference?: OwnerKeyReference;
  /**
   * `createLocalOwner`: commit to this Ed25519 public key (`0x` + 64 hex, or an OpenSSH `ssh-ed25519 AAAA…` line); its
   * private half never touches this host and nothing is written for it. Excludes `nextSigner`, `nextKeyReference` and `nextKey: false`.
   */
  nextPublicKey?: string;
  /**
   * Remote witnesses (formats 1 and 2; docs/WITNESS.md §5). Default: the policy in
   * `<historyFile>.witness.json` plus the witnesses the history binds, plus the
   * out-of-band minimum named by `IRONTRELLIS_WITNESS_POLICY`.
   * `createLocalOwner` registers the genesis with each witness before the file
   * exists (a witness that refuses the registration fails the creation with
   * WITNESS_REJECTED and nothing is written; one that cannot be reached is
   * registered later), writes the policy to the side file and binds the
   * witnesses in the history's first event after the genesis and the principal,
   * written together with them (an owner-signed `WITNESSES_BOUND` event
   * carrying each witness's signed REGISTERED receipt), so no copy of the
   * history exists without them. `false` turns remote witnesses off for this
   * handle (the out-of-band minimum included).
   */
  witness?: WitnessPolicy | false;
  /**
   * Open even when a remote witness shows that this copy lacks a head it holds
   * (or a split view): every read and write of the handle still refuses, but
   * `removeWitness(…, { acceptRemoteLoss })` can record the owner's decision to
   * continue without that witness (docs/reference/witness-operations.md §6.2). Default false: such a
   * finding fails the open.
   */
  witnessRecovery?: boolean;
}>;
/** `addWitness` policy changes, applied with the new witness. */
export type WitnessPolicyUpdate = Readonly<{ quorum?: number; mode?: WitnessMode; maxUnwitnessedEvents?: number; requireOnOpen?: boolean; cacheMs?: number }>;
/** `addWitness` options. */
export type AddWitnessOptions = Readonly<{
  /**
   * When the witness cannot be reached (network, 5xx, 408, 429): bind it anyway
   * and let the queue register the genesis and submit later. Default false:
   * fail with WITNESS_UNAVAILABLE and write nothing. A witness that answers
   * with a refusal or with another key is never bound.
   */
  allowOffline?: boolean;
}>;
/** `removeWitness` options. */
export type RemoveWitnessOptions = Readonly<{
  /**
   * The witness holds a head that no surviving copy of the history contains
   * (this copy lacks it: ROLLBACK_DETECTED, WITNESS_AHEAD or WITNESS_FORK, from
   * the witness's own verified answer). Record, with the owner key, that the
   * history continues on this copy without that witness: an owner-signed
   * unbinding whose data carries `reason` and the heads the witness holds. Any
   * other witness still applies.
   */
  acceptRemoteLoss?: boolean;
  /** Required with `acceptRemoteLoss`: 1..256 UTF-8 bytes, no control characters; recorded in the event. */
  reason?: string;
}>;
export type WitnessChange = Readonly<{
  witness: StoredWitnessConfig; bound: boolean; eventId?: string; status: WitnessStatusReport | undefined; submitted: boolean; error?: Readonly<{ code: string; message: string }>;
  /** `addWitness`: the binding carries the witness's signed REGISTERED receipt (false after `allowOffline`). */
  registered?: boolean;
  /** `removeWitness`: every witness removed (several can be removed at once). */
  removed?: readonly StoredWitnessConfig[];
  /** `removeWitness` with `acceptRemoteLoss`: what the unbinding recorded. */
  acceptedLoss?: AcceptedLossRecord;
}>;
/**
 * A-197.1 (SHOULD): written whenever a policy carrying `recovery` is written or in force. Replay honours a recovery rotation
 * (an owner key rotation authorized under `recovery` without a current owner key), but this release ships no writer for one.
 */
export const OWNER_POLICY_RECOVERY_NO_WRITER = "OWNER_POLICY_RECOVERY_NO_WRITER: this policy sets recovery; replay honours a recovery rotation, but this release ships no writer for one (known issue 24, A-197)";
/** `{warning}` when `event` writes an owner approval policy that carries `recovery` (A-197.1; independent review JOB75-08). */
const recoveryWarningOf = (event: Pick<CanonicalEvent, "type" | "data"> | undefined): Readonly<{ warning?: string }> =>
  event?.type === "OWNER_KEYS_ROTATED" && (event.data as { ownerPolicy?: { recovery?: unknown } }).ownerPolicy?.recovery !== undefined ? { warning: OWNER_POLICY_RECOVERY_NO_WRITER } : {};
export type WriteResult = Readonly<{
  eventId: string; head: HistoryHead; clock?: Readonly<{ code: "CLOCK_BEHIND_HEAD"; skewMs: number }>;
  /** A-46.2 / A-66.2: the automatic checkpoint after this (committed) write was not written, and why. */
  checkpoint?: CheckpointSuppression;
}>;
/** A-66.2: `RESERVE` (once per open), `NO_SIGNER`, `SIGNER_FAILED`, `STORE_FAILED` (every occurrence). */
export type CheckpointSuppression = Readonly<{ code: "CHECKPOINT_SUPPRESSED"; reason: "RESERVE" | "NO_SIGNER" | "SIGNER_FAILED" | "STORE_FAILED"; message?: string }>;
/** The power-reducing types (A-22.3, A-24.1); defined in `types.ts` beside `MAX_UNWITNESSED_EXEMPT_TYPES` (A-176.2). */
export { POWER_REDUCING_TYPES };
/** `checkpoint()`: the recorded `STATE_CHECKPOINT` and what it committed to (SPEC §7.3). */
export type CheckpointResult = WriteResult & Readonly<{ stateRoot: ContentHash; recordCount: U53; projectionHead: ContentHash | null }>;
/** `stateRoot()`: `rootAt(head.position)` and its leaf count (SPEC §7.1); `projectionHead` is `null` with the projection off. */
export type StateRootReport = Readonly<{ stateRoot: ContentHash; recordCount: U53; projectionHead: ContentHash | null }>;
/** SPEC §9.1 `BUDGET_DECLARED.data` without `controlAuthorization`; Amounts as decimal strings or bigints (normalized to strings). */
export type BudgetDeclaration = Readonly<{
  budgetId: string; subjects: Readonly<{ actorIds: readonly string[] | null; roleIds: readonly string[] | null; actions: readonly string[] | null; resources: readonly string[] | null }>;
  /** A-26.1: `null` matches every metric. */
  metric: string | null; period: Readonly<{ kind: "NONE" }> | Readonly<{ kind: "FIXED_WINDOW"; lengthMs: number; originMs: number; carryUnused: boolean; carryCap: string | bigint | null }>;
  amountCap: string | bigint | null; countCap: number | null; perOperationCap: string | bigint | null; notBefore: number | null; expiresAt: number | null;
}>;
/** SPEC §9.1 `BUDGET_UPDATED.data`: all six keys required, subjects restated in full. */
export type BudgetUpdate = Readonly<{ budgetId: string; subjects: BudgetDeclaration["subjects"]; amountCap: string | bigint | null; countCap: number | null; perOperationCap: string | bigint | null; expiresAt: number | null }>;
/** SPEC §11.1: a counterparty's Ed25519 keys (1..16, distinct `keyId`s; EIP-191 is not allowed for counterparties). */
export type CounterpartyKey = Readonly<{ keyId: string; scheme: "ed25519"; credential: string }>;
/** SPEC §9.7: the headroom view of a budget at a time (`at` defaults to the handle's clock). */
export type HeadroomInput = Readonly<{ budgetId: string; at?: number }>;
export type Headroom = Readonly<{ budgetId: string; active: boolean; periodIndex: U53 | null; usedAmount: string; usedCount: U53; carryIn: string; remainingAmount: string | null; remainingCount: U53 | null }>;
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
  /** maxDelegationDepth (default 0: not delegable). */
  delegable?: number;
  /** requiredIntersectionIds (default none). */
  requires?: readonly string[];
  /** Default true; `false` makes the grant an intersection partner only. */
  independent?: boolean;
  /** parentAuthorityId of a delegation. */
  parent?: string;
  /** grantorId (default the owner); required together with `parent` for a delegation. */
  from?: string;
}>;
export type Delegation = Grant & Readonly<{ parent: string; from: string }>;
export type Prohibition = Readonly<{
  id: string;
  actions: readonly string[];
  resources: readonly string[];
  subject?: string;
  /** rootAuthorityId of a ROOT-scoped prohibition (required unless `global`). */
  root?: string;
  /** parentAuthorityId of a ROOT-scoped prohibition issued by an agent (its own permission on that root). */
  anchor?: string;
  /** grantorId of a ROOT-scoped prohibition (default the owner; an agent needs `anchor`). */
  from?: string;
  /** GLOBAL scope: issued by the genesis policy source. */
  global?: boolean;
  expiresAt?: number;
  notBefore?: number;
  maxAmount?: bigint;
}>;
export type Appointment = Readonly<{ agent: string; role: string; tenure: string; number: number; succession?: string }>;
export type Unappointment = Readonly<{ agent: string; role: string; tenure: string }>;
export type Termination = Readonly<{ agent: string; succession: string; role: string; tenure: string }>;
export type RuntimeAdmission = Readonly<{
  session: string;
  agent: string;
  epoch: number;
  key: string;
  /** Legacy credential: an Ethereum address (still accepted in format 1). */
  address?: string;
  /** Format 1 credential: `0x` public key (ed25519) or address (eip191). */
  credential?: string;
  scheme?: SignatureScheme;
  expiresAt: number;
}>;
export type Succession = Readonly<{
  id: string; rule: string; fromAgent: string; fromTenure: string; toAgent: string; toTenure: string; role: string; number: number;
}>;
/** `LocalOwner.runtimeSession`: the session's admission facts and its agent's control state at the head. */
export type RuntimeSessionView = Readonly<{
  sessionId: string; agentId: string; controlEpoch: U53; expiresAt?: U53; credentialKeyId: string;
  /** The agent's current control epoch (its creation epoch, then every CONTROL_EPOCH_ADVANCED). */
  agentControlEpoch: U53;
  agentTerminated: boolean;
}>;
export type HandoverReport = Readonly<{
  agent: string;
  terminated: boolean;
  asOf: number;
  head: HistoryHead;
  tenures: readonly Readonly<{ roleId: string; tenureId: string; tenureNumber: U53; successionRuleId?: string }>[];
  sessions: readonly Readonly<{ sessionId: string; controlEpoch: U53; credentialKeyId: string; expiresAt?: U53; current: boolean }>[];
  openDuties: readonly Readonly<{
    kind: "OBLIGATION" | "ATTEMPT_DUTY"; id: string; status: string; assignee: string; description: string; deadline: U53; sourceIntentId: string; successionRuleId?: string;
  }>[];
  /** Live permissions held by the agent. None of them follows a succession: the successor needs fresh grants. */
  liveGrants: readonly Readonly<{ authorityId: string; grantorId: string; rootAuthorityId: string; delegated: boolean; actions: readonly string[]; resources: readonly string[]; expiresAt?: U53; followsSuccession: false }>[];
  /** Live delegations the agent issued to others (they stay recorded but are evaluated against the agent's own status). */
  delegationsIssued: readonly Readonly<{ authorityId: string; granteeId: string; actions: readonly string[]; resources: readonly string[]; expiresAt?: U53 }>[];
  survives: SurvivesQueryResult;
}>;
/** `rotateOwnerKey` / `prepareOwnerKeyRotation` input (format 1). */
export type OwnerKeyRotation = Readonly<{
  /**
   * The new owner key (e.g. a KMS signer) when the owner keys in force have no next-key commitment. Default: a new Ed25519
   * key file that replaces `<history>.owner-key.json`. Refused when there is a commitment: the new key must then be the
   * committed one (`nextKeyFile` or `nextSigner`).
   */
  newSigner?: Signer;
  /**
   * Pre-rotation: the next-key file holding the key the owner keys in force committed to (default
   * `<history>.owner-next-key.json` when it is there). It becomes the new owner key file. Needed, with `nextSigner` as the
   * alternative, whenever there is a commitment: without it the rotation refuses with KEY_UNAVAILABLE.
   */
  nextKeyFile?: string;
  /** Pre-rotation: the committed next key as a signer (an offline HSM or KMS key); it becomes the handle's owner signer. */
  nextSigner?: Signer;
  /**
   * The key the new owner key set commits to next (its `nextKeyDigests`). Default: a fresh Ed25519 next-key file, staged as
   * `<history>.owner-next-key.pending.json` and moved to `<history>.owner-next-key.json` once the rotation is recorded.
   */
  newNextSigner?: Signer;
  /** The new owner key set commits to this Ed25519 public key (`0x` + 64 hex or `ssh-ed25519 AAAA…`), held off this host; nothing is written. */
  newNextPublicKey?: string;
  /** The new owner key set commits to the key this reference names; it is staged and moved to `<history>.owner-next-key.json` like a generated next key. */
  newNextKeyReference?: OwnerKeyReference;
  /**
   * `false`: record no commitment for the new owner key set. Allowed only when the owner keys in force have none (a
   * rotation out of a committed set must commit again). Default true.
   */
  nextKey?: boolean;
  /**
   * Key id of the new owner key (default: the next free `owner:N`, or the id a next-key file proposes when it is free);
   * with `newSigner` / `nextSigner` it must equal that signer's `keyId` when given.
   */
  keyId?: string;
  /** Recorded in the event: 1..256 UTF-8 bytes, no control characters. */
  reason?: string;
  /**
   * Format 2 (A-91): the owner approval policy of the new owner key set. Without it the new set has the default policy
   * (`{threshold: 1}`); when the policy in force is not the default that is refused (`INVALID_INPUT {reason: POLICY_RESET}`,
   * A-96.4) unless `resetPolicy: true`.
   */
  ownerPolicy?: OwnerPolicy;
  /** A-96.4: let this rotation return a non-default policy to the default `{threshold: 1}`. */
  resetPolicy?: boolean;
  /**
   * Which keys of the current set leave it: `"all"` (default: the new set is
   * the new key alone) or a list of current key ids (the new set keeps the
   * others). The key held in `<history>.owner-key.json` must be retired when a
   * generated key file replaces it.
   */
  retire?: "all" | readonly string[];
  /**
   * Rotate locally first and deliver to the remote witnesses afterwards (through the queue and the key-event bundle), the
   * behaviour before the two-phase rotation (docs/reference/witness-operations.md §7.1). Without it, a history that binds remote witnesses
   * rotates in two phases: every bound witness must be at the current head, the prepared rotation goes to them first, and
   * the rotation is recorded only when at least one of them accepted it (WITNESS_UNAVAILABLE otherwise, nothing written).
   * Use it when a bound witness is down and the key must be replaced now (a leak): the window it leaves is closed by the
   * supersede of a pre-rotated rotation (docs/reference/witness-operations.md §7.4).
   */
  emergency?: boolean;
}>;
export type OwnerKeyRotationResult = Readonly<{
  eventId: string;
  /** The head that ends with the rotation (position r); still attested under the previous key set. */
  head: HistoryHead;
  keyId: string;
  /** The owner key set in force from `fromPosition` (= head.position + 1) on. */
  ownerKeys: readonly OwnerKey[];
  retired: readonly string[];
  fromPosition: U53;
  /** Where the new private key is (generated keys only): `<history>.owner-key.json`, or the pending path if moving it there failed (the next open completes it). */
  keyFile?: string;
  /** Where the retired key file was archived, when one was. */
  retiredKeyFile?: string;
  /** The rotation satisfied the next-key commitment of the owner keys it replaced (pre-rotation). */
  preRotated: boolean;
  /** The commitment of the new owner key set, when the rotation recorded one. */
  nextKeyDigests?: readonly ContentHash[];
  /** Where the new next key is (a generated one): `<history>.owner-next-key.json`, or the pending path if moving it failed (the next open completes it). */
  nextKeyFile?: string;
  /** The key id the new next key proposes for the rotation that will reveal it (when the rotation recorded a commitment). */
  nextKeyId?: string;
  /** The rotation kept every owner key and only recorded a next-key commitment (`commitNextKey`). */
  commitmentOnly?: boolean;
  /**
   * Two-phase rotation (docs/reference/witness-operations.md §7.1): the bound witnesses that recorded the rotation before it was appended,
   * those that refused it and those whose answer is unknown (the queue delivers to them; `rotationIncomplete` until then).
   */
  witnesses?: Readonly<{ accepted: readonly string[]; refused: readonly Readonly<{ url: string; code: string; message: string }>[]; unknown: readonly Readonly<{ url: string; message: string }>[] }>;
  /** A bound witness has not confirmed the rotation yet (it lacks it or was not reached; it accepts heads signed by the retired key until it records it). */
  rotationIncomplete?: boolean;
  /** Rotated with `emergency`: recorded locally first, delivered afterwards (a history without bound witnesses always rotates local-first, with `emergency: false`). */
  emergency?: boolean;
  /** The key-event bundle written for the rotation (`<history>.key-event-<r>.bundle.json`), for an offline hand-off. */
  bundle?: string;
}>;
/** One key-event bundle `exportKeyEvents` wrote (an `OWNER_KEYS_ROTATED`, commitment-only ones included), or why it could not. */
export type KeyEventExport = Readonly<{ position: U53; kind: "ROTATED"; eventId: string; path?: string; chain?: Readonly<{ hash: ContentHash; position: U53 }>; error?: string }>;
/**
 * A rotation built and signed in memory, not yet recorded (`prepareOwnerKeyRotation`). `head` is the head the history
 * will have once `event` is appended at `previousHead`, computed with the store's history hasher;
 * `commitOwnerKeyRotation` appends exactly `event` and checks that the recorded head equals `head`. Any key files it
 * needs are staged as pending files (`files`): a prepared rotation that is never committed leaves only pending files,
 * which the next open or rotation removes (no epoch declares their keys).
 */
export type PreparedOwnerKeyRotation = Readonly<{
  event: CanonicalEvent;
  previousHead: HistoryHead;
  head: HistoryHead;
  /** The new owner key set, in force from `fromPosition` (= head.position + 1). */
  ownerKeys: readonly OwnerKey[];
  keyId: string;
  retired: readonly string[];
  fromPosition: U53;
  preRotated: boolean;
  nextKeyDigests?: readonly ContentHash[];
  /** The owner key in force that signed `event` (it also signs the statement for `head` for remote witnesses). */
  signedBy: string;
  files: Readonly<{ pendingKeyFile?: string; pendingNextKeyFile?: string; nextKeySource?: string }>;
  /**
   * Format 2 (A-92): the owner signatures the rotation needs (`M_rot` of the policy in force). With 2 or more, `head` is
   * the head without co-signatures: the other owner keys sign `challengeHash` out of band and the signatures are passed to
   * `commitOwnerKeyRotation(prepared, {additionalAuthorizations})`.
   */
  required: number;
  /** The §6.1 `/2` control challenge every co-signer signs (`challengeHash` is its hash). */
  challenge: Readonly<Record<string, unknown>>;
  challengeHash: ContentHash;
}>;
/** One owner signature over a control challenge (`controlAuthorization` or one of `additionalControlAuthorizations`). */
export type ControlAuthorizationEntry = Readonly<{ keyId: string; signature: HexSignature }>;
/**
 * A control (◆) event prepared for several owner signatures (A-92.4, format 2): `event` is fixed (id, timestamp, data
 * without signatures) at `previousHead`; every signer signs `challengeHash` (the hash of `challenge`, the SPEC §6.1 `/2`
 * challenge) by any means; `submitControlEvent` appends it once `required` counting signatures are collected. `signers`
 * lists the keys that may sign it (`adm(e)`), their class under the policy at the event's timestamp (A-107.1) and whether
 * they count for this event (A-107.2).
 */
export type PreparedControlEvent = Readonly<{
  event: CanonicalEvent;
  previousHead: HistoryHead;
  challenge: Readonly<Record<string, unknown>>;
  challengeHash: ContentHash;
  required: number;
  signers: readonly Readonly<{ keyId: string; scheme: SignatureScheme; credential: string; class: SignerClass; counts: boolean }>[];
  /** A-197.1: set when the event writes an owner approval policy that carries `recovery` (`OWNER_POLICY_RECOVERY_NO_WRITER`). */
  warning?: string;
}>;
/** `rotateOwnerPolicy` / `prepareOwnerPolicyRotation` input (A-96: keep every owner key, change the policy). */
export type OwnerPolicyRotation = Readonly<{
  /** The new policy, as written into the event; omit it with `resetPolicy: true` to return to the default `{threshold: 1}`. */
  ownerPolicy?: OwnerPolicy;
  resetPolicy?: boolean;
  /** Recorded in the event (default `owner policy rotation`): 1..256 UTF-8 bytes, no control characters. */
  reason?: string;
}>;
/** `commitNextKey` input. */
export type NextKeyCommitment = Readonly<{
  /** Commit to this key (e.g. an offline HSM or KMS key). Default: a new Ed25519 next-key file at `<history>.owner-next-key.json`. */
  nextSigner?: Signer;
  /**
   * Commit to this Ed25519 public key (`0x` + 64 hex or `ssh-ed25519 AAAA…`) whose private half never touches this host;
   * nothing is written for it. The rotation that reveals it needs its signer (`nextKeyFile` naming a key reference or a
   * next-key file, or `nextSigner`).
   */
  nextPublicKey?: string;
  /** Commit to the key this reference names; the reference is written to `<history>.owner-next-key.json` (no secret). */
  nextKeyReference?: OwnerKeyReference;
  /** Recorded in the rotation (default `next-key commitment`): 1..256 UTF-8 bytes, no control characters. */
  reason?: string;
  /** As for `rotateOwnerKey`: record it locally first and deliver it to the bound witnesses afterwards. */
  emergency?: boolean;
  /** Format 2: the policy the commitment's rotation sets; default the policy in force, restated as written (A-96.4). */
  ownerPolicy?: OwnerPolicy;
  /** A-96.4: return the policy to the default `{threshold: 1}` with this commitment. */
  resetPolicy?: boolean;
}>;
export type NextKeyCommitmentResult = Readonly<{
  /** The commitment-only `OWNER_KEYS_ROTATED` that recorded the commitment (the owner keys are unchanged). */
  eventId: string;
  head: HistoryHead;
  nextKeyDigests: readonly ContentHash[];
  /** The key id the next key proposes for the rotation that will reveal it. */
  keyId: string;
  /** Where the generated next key is: `<history>.owner-next-key.json` (or the pending path if moving it failed; the next open completes it). */
  nextKeyFile?: string;
  /** The key-event bundle written for it (`<history>.key-event-<position>.bundle.json`). */
  bundle?: string;
  /** As for `rotateOwnerKey` (two-phase delivery to the bound witnesses). */
  witnesses?: OwnerKeyRotationResult["witnesses"];
  rotationIncomplete?: boolean;
  emergency?: boolean;
}>;
/**
 * Where a next-key file stands against the history: `COMMITTED` (its key is the commitment of the owner keys in force),
 * `IN_FORCE` (already revealed: a stale copy of an owner key in force), `RETIRED` (a key the history retired),
 * `UNCOMMITTED` (no commitment of the keys in force names it), `UNREADABLE`.
 */
export type NextKeyFileState = "COMMITTED" | "IN_FORCE" | "RETIRED" | "UNCOMMITTED" | "UNREADABLE";
export type OwnerKeyStatus = Readonly<{
  format: HistoryFormat;
  /** The owner keys in force for the next event, and the first position they govern. */
  ownerKeys: readonly OwnerKey[];
  fromPosition: U53;
  /** `OWNER_KEYS_ROTATED` events that changed the owner keys. */
  keyRotations: number;
  /** `OWNER_KEYS_ROTATED` events that kept every owner key and only committed next keys (commitment-only rotations). */
  commitmentRotations: number;
  /** Format 2 (A-96.3): `OWNER_KEYS_ROTATED` events that kept every owner key and changed the owner approval policy. */
  policyRotations: number;
  /** Format 2 (A-91): the owner approval policy in force for the next event, as written; `null` for the default `{threshold: 1}`. */
  ownerPolicy: OwnerPolicy | null;
  /**
   * The next-key commitment of the owner keys in force (`null`: none, so a leaked current key could rotate), and the
   * event that opened their epoch with it: the genesis (`GENESIS`), a rotation to new keys (`ROTATION`) or a rotation that
   * kept the keys and only committed (`COMMITMENT`, `owner commit-next-key`).
   */
  commitment: Readonly<{ nextKeyDigests: readonly ContentHash[]; eventId: string; position: U53; source: "GENESIS" | "ROTATION" | "COMMITMENT" }> | null;
  /** `<history>.owner-key.json`, when present. */
  ownerKeyFile: string | null;
  /** `<history>.owner-next-key.json`, when present, and what it holds (`holder`: key material in the file, or a key reference). */
  nextKeyFile: Readonly<{ path: string; state: NextKeyFileState; keyId?: string; digest?: ContentHash; holder?: "file" | "reference"; signer?: string }> | null;
  /** The next-key file is on this host beside the history and its owner key: pre-rotation does not protect against a compromise of this host. */
  nextKeyOnHost: boolean;
  /** Pending key files a crashed rotation or commitment left (settled on the next open or owner write). */
  pending: readonly string[];
  /**
   * What weakens pre-rotation, one entry each: `NO_NEXT_KEY_COMMITMENT`, `NEXT_KEY_ON_HOST` (the message ends with
   * `NEXT_KEY_ON_HOST_WARNING`), `NEXT_KEY_STALE`, `NEXT_KEY_RETIRED`, `NEXT_KEY_UNCOMMITTED`, `NEXT_KEY_UNREADABLE`,
   * `KEY_FILE_PENDING`.
   */
  warnings: readonly OwnerKeyWarning[];
  /**
   * Where each key is held (docs/CUSTODY.md): the owner keys in force, the next key and the archived retired keys, one
   * entry each, `level` OK or WARN. Read from the files alone: no signer is contacted.
   */
  custody: readonly KeyCustody[];
}>;
export type OwnerKeyWarning = Readonly<{ code: string; message: string; path?: string }>;
/**
 * One key's custody in `owner status`. `holder`: `file` (private key material in a file on this host), `reference` (a
 * signer holds it: `signer` names the backend kind), `public-key-only` (only its public key is known here: the history's
 * commitment), `elsewhere` (a key in force this host holds no file for: a programmatic signer), `none` (no next-key
 * commitment), `unreadable`.
 * Codes: OWNER_KEY_FILE_ON_HOST (WARN), OWNER_KEY_REFERENCE, OWNER_KEY_ELSEWHERE, NEXT_KEY_ON_HOST (WARN),
 * NEXT_KEY_REFERENCE, NEXT_KEY_SAME_SIGNER (WARN), NEXT_KEY_OFF_HOST, NO_NEXT_KEY_COMMITMENT (WARN), RETIRED_KEY_FILE (WARN),
 * RETIRED_KEY_REFERENCE, KEY_FILE_UNREADABLE (WARN).
 */
export type KeyCustody = Readonly<{
  role: "current" | "next" | "retired";
  keyId?: string;
  holder: "file" | "reference" | "public-key-only" | "elsewhere" | "none" | "unreadable";
  signer?: string;
  description?: string;
  path?: string;
  level: "OK" | "WARN";
  code: string;
  message: string;
}>;
/** The `owner status` warning while the next key is on the host. */
export const NEXT_KEY_ON_HOST_WARNING = "move it offline; pre-rotation only protects you if the next key is not on this host";

/** `rollback`: the pin, an anchor log or a remote witness shows that events were removed or replaced (see `ok` / `failures` for the verdict). */
export type OwnerVerification = VerificationReport & Readonly<{ rollback: boolean }>;
const withRollback = (report: VerificationReport): OwnerVerification =>
  Object.freeze({ ...report, rollback: report.pinnedHeadStatus === "ROLLBACK" || report.anchorLogStatus === "ROLLBACK" || report.remoteWitnessStatus === "ROLLBACK" });

export interface LocalOwner {
  /** This whole handle is privileged host configuration; do not give it to an agent. */
  readonly format: HistoryFormat;
  createAgent(input: Readonly<{ id: string }>): Promise<WriteResult>;
  createRole(input: Readonly<{ id: string; exclusive?: boolean }>): Promise<WriteResult>;
  grant(input: Grant): Promise<WriteResult>;
  delegate(input: Delegation): Promise<WriteResult>;
  prohibit(input: Prohibition): Promise<WriteResult>;
  revoke(authority: string): Promise<WriteResult>;
  appoint(input: Appointment): Promise<WriteResult>;
  unappoint(input: Unappointment): Promise<WriteResult>;
  terminate(input: Termination): Promise<WriteResult>;
  declareSuccession(input: Readonly<{ id: string; from: string; to: string; role: string }>): Promise<WriteResult>;
  /**
   * Records the handover (retirement, transfer) and, in format 2, seals it with a `STATE_CHECKPOINT` (SPEC §7.3) named in
   * `eventIds`. When this handle cannot sign the seal to the policy (A-174.2), the seal is not written: `checkpoint` reports
   * `CHECKPOINT_SUPPRESSED {reason: NO_SIGNER}` and `eventIds` names the handover steps only.
   */
  succeed(input: Succession): Promise<Readonly<{ status: "HANDOVER_RECORDED"; eventIds: readonly string[]; head: HistoryHead; checkpoint?: CheckpointSuppression }>>;
  admitRuntime(input: RuntimeAdmission): Promise<WriteResult>;
  advanceEpoch(input: Readonly<{ agent: string; from: number; to: number }>): Promise<WriteResult>;
  /**
   * Format 1: replace the owner key set with an `OWNER_KEYS_ROTATED` event
   * signed by the current owner key.
   *
   * With bound remote witnesses (and without `emergency`) the rotation is
   * two-phase (docs/reference/witness-operations.md §7.1): flush; every bound witness must be at
   * the local head (else WITNESS_UNAVAILABLE, ROTATION_NEEDS_WITNESSES);
   * prepare, persist the sealed record `<history>.rotation.pending.json`,
   * deliver the rotation with the old-key statement for its head to every
   * bound witness, and only then append it locally. None accepted: abort
   * (ROTATION_ABORTED) or, when an answer was lost, keep the record
   * (ROTATION_OUTCOME_UNKNOWN; writes refuse with ROTATION_PENDING until an
   * owner command resolves it). Some accepted: recorded, the rest queued
   * (`rotationIncomplete`). Otherwise (`emergency: true`, no bound witness)
   * local-first: `prepareOwnerKeyRotation` then `commitOwnerKeyRotation`
   * under one writer lock, then delivered to the witnesses. Every rotation
   * writes its key-event bundle (`bundle`).
   *
   * When the owner keys in force committed to a next key (pre-rotation; the
   * default since `createLocalOwner` commits one), the new owner key must be
   * that key: from `nextKeyFile` (default `<history>.owner-next-key.json`) or
   * `nextSigner`; without it the rotation refuses with KEY_UNAVAILABLE. The
   * event carries the revealed key's proof of possession
   * (`nextKeyAuthorizations`) and commits the new set to a fresh next key
   * (`nextKeyDigests`; a new Ed25519 next-key file unless `newNextSigner`).
   * Without a commitment, a new Ed25519 key file is generated (or `newSigner`
   * is used) as before, and a fresh next key is committed unless `nextKey:
   * false`.
   *
   * Files: the new owner key file is staged as `<history>.owner-key.pending.json`
   * and the new next key as `<history>.owner-next-key.pending.json`; the event is
   * appended; then the old key file is archived as
   * `<history>.owner-key.<keyId>.retired.json`, the staged owner key replaces
   * `<history>.owner-key.json`, and the staged next key replaces
   * `<history>.owner-next-key.json` (a crash anywhere in between is completed,
   * or undone when nothing was recorded, on the next open). Later control
   * events and pins use the new key; heads up to and including the rotation
   * stay attested by the old one. See `OwnerKeyRotation`.
   */
  rotateOwnerKey(input?: OwnerKeyRotation): Promise<OwnerKeyRotationResult & Readonly<{ warning?: string }>>;
  /**
   * The first half of `rotateOwnerKey`: under the writer lock, settles leftover key files, stages the key files the
   * rotation needs as pending files, builds and signs the `OWNER_KEYS_ROTATED` event (with its `nextKeyAuthorizations`
   * and `nextKeyDigests`), checks it against the current state and computes the head it will produce, without
   * appending anything. `commitOwnerKeyRotation` records it.
   */
  prepareOwnerKeyRotation(input?: OwnerKeyRotation): Promise<PreparedOwnerKeyRotation>;
  /**
   * The second half: under the writer lock, checks that the staged key files still hold the prepared keys, appends
   * exactly `prepared.event` at `prepared.previousHead` (HISTORY_CONFLICT if the history moved), asserts that the
   * recorded head equals `prepared.head`, hands the rotation to the remote witnesses and swaps the key files. A
   * prepared rotation is committed at most once, by the handle that prepared it.
   */
  commitOwnerKeyRotation(prepared: PreparedOwnerKeyRotation, options?: Readonly<{ additionalAuthorizations?: readonly ControlAuthorizationEntry[] }>): Promise<OwnerKeyRotationResult>;
  /**
   * Format 2 (A-96): an `OWNER_KEYS_ROTATED` that keeps every owner key (and the next-key commitment) and changes the owner
   * approval policy, signed by this handle's key. Refused with CONTROL_AUTHORIZATION_INVALID `{required, present}` when
   * the policy in force needs more than one signature for it: use `prepareOwnerPolicyRotation` and `submitControlEvent`.
   */
  rotateOwnerPolicy(input: OwnerPolicyRotation): Promise<WriteResult & Readonly<{ warning?: string }>>;
  /** `rotateOwnerPolicy` in two phases: the prepared rotation for the owner keys to sign (see `prepareControlEvent`). */
  prepareOwnerPolicyRotation(input: OwnerPolicyRotation): Promise<PreparedControlEvent>;
  /**
   * Format 2 (A-92.4): fixes a control (◆) event at the current head (id, timestamp, `data` without signatures; `data` is
   * the event's SPEC data, e.g. `{grant: …}` for AUTHORITY_GRANTED) and returns its `/2` challenge, the number of owner
   * signatures it needs and the owner keys that can sign it. Nothing is signed or written. A rotation that changes owner
   * keys goes through `prepareOwnerKeyRotation` (key files), not here.
   */
  prepareControlEvent(input: Readonly<{ type: EventType; data: Readonly<Record<string, unknown>> }>): Promise<PreparedControlEvent>;
  /**
   * The second phase: the first authorization becomes `controlAuthorization`, the others `additionalControlAuthorizations`;
   * HISTORY_CONFLICT if the history moved since `prepared` (prepare again: a consent is never re-signed onto a new head);
   * CONTROL_AUTHORIZATION_INVALID `{required, present}` before anything is appended when the signatures do not satisfy the
   * policy in force (A-92.2); then appended like any owner write (with the automatic checkpoint after it).
   */
  submitControlEvent(prepared: PreparedControlEvent, authorizations: readonly ControlAuthorizationEntry[]): Promise<WriteResult & Readonly<{ warning?: string }>>;
  /**
   * Format 1, pre-rotation for a history whose owner keys in force have no commitment (created with `nextKey: false`, or
   * rotated without one): records an `OWNER_KEYS_ROTATED` that keeps every owner key and carries `nextKeyDigests` (a
   * commitment-only rotation, signed by the owner key in force; the keys are unchanged), committing them to a next key:
   * a new Ed25519 next-key file (staged as `<history>.owner-next-key.pending.json`, moved to
   * `<history>.owner-next-key.json` once recorded), `nextSigner`, `nextPublicKey` or `nextKeyReference`. It goes through
   * the same path as `rotateOwnerKey` (two-phase with bound witnesses unless `emergency`). Refused (TRANSITION_REJECTED)
   * when the keys in force already have a commitment: only a rotation to a committed key starts a new one.
   */
  commitNextKey(input?: NextKeyCommitment): Promise<NextKeyCommitmentResult & Readonly<{ warning?: string }>>;
  /**
   * Writes the key-event bundle (`<history>.key-event-<position>.bundle.json`, docs/reference/witness-operations.md §7.3) of every owner key
   * event at or after `since`: the event, the heads around it, the statement for its head (signed by the key in force
   * there, previous = the head before it) and, for a pre-rotated rotation, a `chain` from the last head the owner knew a
   * bound witness held. A witness operator imports it with `irontrellis-witness import-key-events` or `POST /v1/admin/key-events`.
   */
  exportKeyEvents(options?: Readonly<{ since?: number }>): Promise<readonly KeyEventExport[]>;
  /** The owner keys in force, their next-key commitment and where the next-key file is (no network, no writes). */
  ownerKeyStatus(): OwnerKeyStatus;
  observe(options?: ObservationOptions): Observation;
  authorize(action: Action, options?: ObservationOptions): ReturnType<Observation["authorize"]>;
  why(action: Action, options?: ObservationOptions): ReturnType<Observation["why"]>;
  responsible(action: Action, options?: ObservationOptions): ReturnType<Observation["responsible"]>;
  survives(agent: string, options?: ObservationOptions): ReturnType<Observation["survives"]>;
  handover(agent: string, options?: ObservationOptions): HandoverReport;
  /**
   * A runtime session as the history records it, beside its agent's current control epoch and termination (read-only,
   * synchronous, from the replayed state: no event scan); `null` when no session `sessionId` was admitted. What a
   * per-call session check reads (the hook's PreToolUse fencing) without exporting the history.
   */
  runtimeSession(sessionId: string): RuntimeSessionView | null;
  capacity(): CapacityReport;
  // ---- format 2 (SPEC §7.3, §9, §11, §15; docs/API.md §1). Each write is owner-signed; on a legacy or format-1 file it is FORMAT_READ_ONLY.
  /** SPEC §9.1: declares a budget (`EVENT_DATA_INVALID` → INVALID_INPUT before signing; a duplicate id or the 257th budget → TRANSITION_REJECTED). */
  /**
   * A-179.4: when the genesis sets a session time horizon H and the budget is a `FIXED_WINDOW` with `lengthMs ≤ H`, the
   * result carries `warning` (a session alone can carry time across a whole window); the budget is declared either way.
   */
  declareBudget(input: BudgetDeclaration): Promise<WriteResult & Readonly<{ warning?: string }>>;
  /** SPEC §9.1: prospective update of an ACTIVE budget (all six keys required; the rollover earned so far is frozen in `carryBase`). */
  updateBudget(input: BudgetUpdate): Promise<WriteResult>;
  /** SPEC §9.1: closes an ACTIVE budget; it never reopens. */
  closeBudget(input: Readonly<{ budgetId: string }>): Promise<WriteResult>;
  /** SPEC §11.1: registers a counterparty's keys (re-registering an ACTIVE id is refused; a RETIRED one keeps its receipt chain). */
  registerCounterparty(input: Readonly<{ counterpartyId: string; keys: readonly CounterpartyKey[]; /** A-32.3: deliberately rebind a key id or credential this RETIRED counterparty used before. */ allowKeyRebind?: boolean }>): Promise<WriteResult>;
  /** SPEC §11.1: retires an ACTIVE counterparty. */
  retireCounterparty(input: Readonly<{ counterpartyId: string }>): Promise<WriteResult>;
  /**
   * SPEC §7.3: records a `STATE_CHECKPOINT` committing to the head, root, record count and projection head of the state
   * before it. The root is recomputed from the records before signing and must equal the state's own (CHECKPOINT_MISMATCH:
   * a self-check that must never fire). `checkpointId` defaults to `checkpoint:<position>`.
   */
  checkpoint(input?: Readonly<{ checkpointId?: string }>): Promise<CheckpointResult>;
  /** SPEC §9.7 (read-only, synchronous): the headroom of a budget at `at` (default: the handle's clock), or `null` for an unknown budget. */
  headroom(input: HeadroomInput): Headroom | null;
  /** SPEC §15 (read-only, synchronous): the export view between two positions. */
  exportView(input: ExportViewInput): ExportView;
  /** A-45.4 (read-only): a counterparty's chain state, or `null` when it was never registered. */
  counterpartyState(counterpartyId: string): CounterpartyState | null;
  /** SPEC §7.1 (read-only): `rootAt(head.position)`, its leaf count and the projection head — a self-check helper (INVALID_INPUT for a non-format-2 file). */
  stateRoot(): StateRootReport;
  /** SPEC §13.3 (read-only, synchronous): the `continuity-attempt-duty-view/1` record of a duty with an active policy, else `null`. */
  inspectDutyPolicy(input: Readonly<{ dutyId: string }>): DutyPolicyView | null;
  verify(): OwnerVerification;
  /** `verify()` plus the remote witnesses (see `HistoryStore.verifyWithWitnesses`). */
  verifyWithWitnesses(options?: Readonly<{ allowUnreachableWitness?: boolean }>): Promise<OwnerVerification>;
  /** Asks the remote witnesses now (see `HistoryStore.checkWitnesses`); lifts the `requireOnOpen` gate. */
  checkWitnesses(options?: Readonly<{ force?: boolean }>): Promise<WitnessView>;
  /** Local knowledge of the remote witnesses (no network); `undefined` when none is configured. */
  witnessStatus(): WitnessStatusReport | undefined;
  /**
   * Adds a remote witness. Before anything is written: checks that it serves
   * `verifierKey` (`GET /v1/witness`), registers the genesis, checks that its
   * latest head for the history (if any) is a prefix of this copy, and that
   * every head statement it still needs can be signed (a rotation head it has
   * not recorded needs the key that rotation retired). Then writes the policy
   * (with `update`) to `<history>.witness.json`, brings the witnesses up to the
   * head, binds the witness in the history (an owner-signed `WITNESSES_BOUND`
   * event carrying its signed REGISTERED receipt: a copy of the history from
   * here on keeps it whatever the side file says) and submits the head.
   * Failures, with nothing written: WITNESS_REJECTED (a refusal, another key, an
   * invalid answer), KEY_UNAVAILABLE (a statement no available key can sign),
   * ROLLBACK_DETECTED (it holds a head this copy lacks), WITNESS_UNAVAILABLE
   * (unreachable, unless `options.allowOffline`).
   */
  addWitness(config: RemoteWitnessConfig, update?: WitnessPolicyUpdate, options?: AddWitnessOptions): Promise<WitnessChange>;
  /**
   * Removes one witness or several (by url or verifier key): an owner-signed
   * unbinding when the history binds them, then the side-file policy. It is an
   * owner write, refused while any witness shows a rollback, except with
   * `acceptRemoteLoss` for exactly the witnesses that show it (see
   * `RemoveWitnessOptions`). A witness the out-of-band minimum policy names
   * cannot be removed here.
   */
  removeWitness(witness: string | readonly string[], options?: RemoveWitnessOptions): Promise<WitnessChange>;
  exportHistory(): readonly CanonicalEvent[];
  /**
   * Resolves once every pending head attestation has been written to the
   * pinned head (`<history>.head`). A local key file attests each write
   * synchronously, so this resolves at once; an asynchronous (KMS/HSM)
   * `signer` attests after the write has returned, so **call
   * `await owner.flush()` before the process exits** or the last pinned head
   * may be left unattested. The recorded events are durable either way. A
   * failed attestation rejects once: SIGNER_FAILED (the signer threw) or
   * WRITE_UNCONFIRMED (the pinned head could not be rewritten).
   */
  flush(): Promise<void>;
  /**
   * Releases the store's cached history; every later call on this handle
   * fails with READ_UNAVAILABLE. Idempotent. It does not wait for pending
   * attestations: with a KMS (async) signer, `await owner.flush()` first.
   */
  close(): void;
}

export type Config = Readonly<{
  historyFile: string;
  domain: AuthorizationDomain;
  owner: string;
  controller: string;
  now: () => number;
  ids: () => string;
  format: HistoryFormat;
  /** Whether the caller named `format` (an explicit format 1 or legacy asks for the earlier writer; see `LocalOwnerOptions.format`). */
  formatGiven: boolean;
  signer: Signer | undefined;
  /** Where `signer` came from: the caller (`option`, never replaced by a key file) or `<history>.owner-key.json`. */
  signerSource?: "option" | "key-file";
  maxEvents: number | null | undefined;
  maxStateRecords: number | null | undefined;
  checkpointPolicy: Readonly<{ everyEvents: number | null }> | undefined;
  projection: "irontrellis-projection/2" | null | undefined;
  sessionTimeHorizonMs: number | null | undefined;
  refusals: "record" | "off";
  /** A-23 / A-38 (defaults `REFUSAL_POLICY_DEFAULTS`). */
  refusalPolicy?: Readonly<{ coalesceMs: number; maxPerMinute: number; recordBudgetMs: number }>;
  trust: "FULL_REPLAY" | "CHECKPOINT_RESUME";
  historyId: ContentHash | undefined;
  signatureScheme: SignatureScheme;
  acceptRollback: boolean;
  allowUnpinned: boolean;
  reuseExistingKey: boolean;
  witnessRecovery?: boolean;
  /** A-41.2 opt-in (see `LocalOwnerOptions.enforceFromReadOnlyHistory`). */
  enforceFromReadOnlyHistory?: boolean;
  witness?: WitnessPolicy | false;
  /** `createLocalOwner` only: commit to a next key in the first write (default true for format 1). */
  nextKey: boolean;
  nextSigner?: Signer;
  ownerKeyReference?: OwnerKeyReference;
  nextKeyReference?: OwnerKeyReference;
  /** `createLocalOwner`, format 2 (A-91): the genesis owner keys beside the handle's own, and epoch 0's policy. */
  coOwnerKeys?: readonly OwnerKey[];
  ownerPolicy?: OwnerPolicy;
}>;

const isSigner = (value: unknown): value is Signer =>
  value !== null && typeof value === "object" && typeof (value as Signer).keyId === "string" && typeof (value as Signer).credential === "string" &&
  typeof (value as Signer).scheme === "string" && typeof (value as Signer).signHash === "function";

// ---------------------------------------------------------------- A-32.3 key roles (writer rules of the owner API, INVALID_INPUT)

/** C-35: "equal" credentials are the same scheme and the same lowercase credential string. */
export const credentialRoleKey = (scheme: string, credential: string): string => `${scheme}\u0000${credential.toLowerCase()}`;
/** Every credential the history declares, with the role it serves (owner key of an epoch, a session, a counterparty key). */
export function credentialRolesOf(state: ReplayState): Map<string, string> {
  const roles = new Map<string, string>();
  state.ownerKeyEpochs.forEach((epoch, index) => { for (const key of epoch.keys) roles.set(credentialRoleKey(key.scheme, key.credential), `owner key ${key.keyId} (epoch ${index})`); });
  for (const session of state.runtimeSessions.values()) roles.set(credentialRoleKey(session.credentialScheme, session.credentialAddressKey), `the credential of session ${session.id}`);
  for (const record of state.counterparties.values()) {
    for (const key of (record.keys as readonly Readonly<{ keyId: string; scheme: string; credential: string }>[] | undefined) ?? []) roles.set(credentialRoleKey(key.scheme, key.credential), `key ${key.keyId} of counterparty ${String(record.counterpartyId)}`);
  }
  return roles;
}
/**
 * A-32.3 for `registerCounterparty`: no key equal to an owner key, a session credential or another counterparty's key;
 * re-registering a RETIRED counterparty may not bind a keyId it used before to another credential, nor a credential it
 * retired under another keyId, unless `allowKeyRebind`.
 */
function assertCounterpartyKeys(state: ReplayState, data: { counterpartyId: string; keys: readonly Readonly<{ keyId: string; scheme: string; credential: string }>[] }, allowKeyRebind: boolean): void {
  const own = state.counterparties.get(data.counterpartyId);
  const ownKeys = new Set((((own?.keys as readonly Readonly<{ scheme: string; credential: string }>[] | undefined) ?? [])).map((k) => credentialRoleKey(k.scheme, k.credential)));
  const roles = credentialRolesOf(state);
  for (const key of data.keys) {
    const role = roles.get(credentialRoleKey(key.scheme, key.credential));
    if (role !== undefined && !ownKeys.has(credentialRoleKey(key.scheme, key.credential))) throw new IronTrellisError("INVALID_INPUT", false, `registerCounterparty: key ${key.keyId} is already in use as ${role} (A-32.3)`, { reason: "CREDENTIAL_REUSE", role });
  }
  if (own === undefined || allowKeyRebind) return;
  const bound = new Map<string, string>(), byCredential = new Map<string, string>();
  for (const event of state.events) {
    if (event.type !== "COUNTERPARTY_REGISTERED" || event.data.counterpartyId !== data.counterpartyId) continue;
    for (const k of event.data.keys as readonly Readonly<{ keyId: string; scheme: string; credential: string }>[]) { bound.set(k.keyId, credentialRoleKey(k.scheme, k.credential)); byCredential.set(credentialRoleKey(k.scheme, k.credential), k.keyId); }
  }
  for (const key of data.keys) {
    const credential = credentialRoleKey(key.scheme, key.credential);
    const before = bound.get(key.keyId), keyIdBefore = byCredential.get(credential);
    if ((before !== undefined && before !== credential) || (keyIdBefore !== undefined && keyIdBefore !== key.keyId)) {
      throw new IronTrellisError("INVALID_INPUT", false, `registerCounterparty: key ${key.keyId} rebinds a key id or credential this counterparty used before; pass allowKeyRebind: true to do so deliberately (A-32.3)`, { reason: "KEY_REBIND" });
    }
  }
}

/** Validate host configuration. Callbacks (clock, ids, signer) are pinned once and never captured as data. */
export function configuration(input: LocalOwnerOptions): Config {
  requireCondition(input !== null && typeof input === "object");
  const clock = input.now, ids = input.ids, signer = input.signer;
  requireCondition(typeof clock === "function" && (ids === undefined || typeof ids === "function") && (signer === undefined || isSigner(signer)));
  requireCondition((input.nextSigner === undefined || isSigner(input.nextSigner)) && (input.nextKey === undefined || typeof input.nextKey === "boolean"));
  const ownerKeyReference = input.ownerKeyReference === undefined ? undefined : capturedReference(input.ownerKeyReference, OWNER_KEY_REF_VERSION, "ownerKeyReference");
  const nextKeyReference = input.nextKeyReference === undefined ? undefined : capturedReference(input.nextKeyReference, OWNER_NEXT_KEY_REF_VERSION, "nextKeyReference");
  const publicOnly = input.nextPublicKey === undefined ? undefined : (() => {
    try { return publicKeySigner(parsePublicKey(input.nextPublicKey), "owner:next"); } catch (error) { throw new IronTrellisError("INVALID_INPUT", false, `nextPublicKey: ${error instanceof Error ? error.message : String(error)}`); }
  })();
  if (ownerKeyReference !== undefined && signer !== undefined) throw new IronTrellisError("INVALID_INPUT", false, "pass the owner key once: signer or ownerKeyReference");
  if ([input.nextSigner, nextKeyReference, publicOnly].filter((v) => v !== undefined).length > 1) throw new IronTrellisError("INVALID_INPUT", false, "pass the next key once: nextSigner, nextKeyReference or nextPublicKey");
  const nextSigner = input.nextSigner ?? publicOnly;
  requireCondition(!(input.nextKey === false && (nextSigner !== undefined || nextKeyReference !== undefined)));
  // The witness policy carries a transport callback; it is checked here and kept as given (host configuration).
  const witness = input.witness;
  if (witness !== undefined && witness !== false) {
    try { normalizeWitnessPolicy(witness); } catch (error) { throw new IronTrellisError("INVALID_INPUT", false, error instanceof Error ? error.message : String(error)); }
  }
  // Optional host settings given as `undefined` count as absent (host configuration is trusted; `{ ...config, maxEvents: undefined }` is a common idiom).
  const flags = ["acceptRollback", "allowUnpinned", "reuseExistingKey", "witnessRecovery", "enforceFromReadOnlyHistory"] as const;
  const settings = ["format", "maxEvents", "signatureScheme", "maxStateRecords", "checkpointPolicy", "projection", "sessionTimeHorizonMs", "refusals", "refusalPolicy", "trust", "historyId"] as const;
  const given = (key: (typeof settings)[number] | (typeof flags)[number]): Record<string, unknown> => (input[key] === undefined ? {} : { [key]: input[key] });
  const data = record(
    { historyFile: input.historyFile, domain: input.domain, owner: input.owner, controller: input.controller, ...Object.assign({}, ...settings.map(given)), ...Object.assign({}, ...flags.map(given)) },
    ["historyFile", "domain", "owner", "controller"], [...settings, ...flags],
  );
  requireCondition(typeof data.historyFile === "string" && data.historyFile.length > 0 && !data.historyFile.includes("\0"));
  requireCondition(data.format === undefined || data.format === LEGACY_FORMAT || data.format === TRELLIS_FORMAT || data.format === TRELLIS2_FORMAT);
  // A-185.3 / A-194: the public API writes format 2 only; the legacy and format-1 writers are test tooling (internal-format1).
  if (data.format !== undefined && data.format !== TRELLIS2_FORMAT && !hasFormat1TestTooling(input)) {
    throw new IronTrellisError("INVALID_INPUT", false, `format ${String(data.format)}: the public API writes format 2 (irontrellis-event/2) only (SPEC §16.1); legacy and format-1 files open read only`);
  }
  requireCondition(data.maxEvents === undefined || data.maxEvents === null || (time(data.maxEvents) > 0));
  requireCondition(data.maxStateRecords === undefined || data.maxStateRecords === null || (time(data.maxStateRecords) > 0));
  if (data.checkpointPolicy !== undefined) {
    const policy = record(data.checkpointPolicy, ["everyEvents"]);
    requireCondition(policy.everyEvents === null || time(policy.everyEvents) >= 1);
  }
  requireCondition(data.projection === undefined || data.projection === null || data.projection === PROJECTION_VERSION);
  requireCondition(data.sessionTimeHorizonMs === undefined || data.sessionTimeHorizonMs === null || time(data.sessionTimeHorizonMs) >= 1);
  requireCondition(data.refusals === undefined || data.refusals === "record" || data.refusals === "off");
  const refusalPolicy = data.refusalPolicy === undefined ? undefined : (() => {
    const p = record(data.refusalPolicy, [], ["coalesceMs", "maxPerMinute", "recordBudgetMs"]);
    const coalesceMs = p.coalesceMs === undefined ? 60_000 : time(p.coalesceMs), maxPerMinute = p.maxPerMinute === undefined ? 6 : time(p.maxPerMinute), recordBudgetMs = p.recordBudgetMs === undefined ? 250 : time(p.recordBudgetMs);
    requireCondition(maxPerMinute >= 1);
    return Object.freeze({ coalesceMs, maxPerMinute, recordBudgetMs });
  })();
  requireCondition(data.trust === undefined || data.trust === "FULL_REPLAY" || data.trust === "CHECKPOINT_RESUME");
  requireCondition(data.historyId === undefined || isContentHash(data.historyId));
  requireCondition(data.signatureScheme === undefined || data.signatureScheme === "ed25519" || data.signatureScheme === "eip191-personal-sign-keccak256");
  for (const flag of flags) requireCondition(data[flag] === undefined || typeof data[flag] === "boolean");
  const readClock = (): number => {
    let value: unknown;
    try { value = clock(); } catch { throw new IronTrellisError("CLOCK_INVALID"); }
    try { return time(value); } catch { throw new IronTrellisError("CLOCK_INVALID"); }
  };
  return Object.freeze({
    historyFile: data.historyFile, domain: captureDomain(data.domain), owner: identifier(data.owner), controller: identifier(data.controller),
    now: readClock, ids: ids ?? randomUUID, format: (data.format as HistoryFormat | undefined) ?? TRELLIS2_FORMAT, formatGiven: data.format !== undefined,
    signer, ...(signer === undefined ? {} : { signerSource: "option" as const }),
    maxEvents: data.maxEvents as number | null | undefined, signatureScheme: (data.signatureScheme as SignatureScheme | undefined) ?? "ed25519",
    maxStateRecords: data.maxStateRecords as number | null | undefined,
    checkpointPolicy: data.checkpointPolicy === undefined ? undefined : Object.freeze({ everyEvents: (data.checkpointPolicy as { everyEvents: number | null }).everyEvents }),
    projection: data.projection as "irontrellis-projection/2" | null | undefined, refusals: (data.refusals as "record" | "off" | undefined) ?? "record",
    sessionTimeHorizonMs: data.sessionTimeHorizonMs as number | null | undefined,
    ...(refusalPolicy === undefined ? {} : { refusalPolicy }),
    trust: (data.trust as "FULL_REPLAY" | "CHECKPOINT_RESUME" | undefined) ?? "CHECKPOINT_RESUME", historyId: data.historyId as ContentHash | undefined,
    acceptRollback: data.acceptRollback === true, allowUnpinned: data.allowUnpinned === true, reuseExistingKey: data.reuseExistingKey === true,
    ...(data.witnessRecovery === true ? { witnessRecovery: true } : {}), ...(witness === undefined ? {} : { witness }),
    ...(data.enforceFromReadOnlyHistory === true ? { enforceFromReadOnlyHistory: true } : {}),
    nextKey: input.nextKey !== false, ...(nextSigner === undefined ? {} : { nextSigner }),
    ...(ownerKeyReference === undefined ? {} : { ownerKeyReference }), ...(nextKeyReference === undefined ? {} : { nextKeyReference }),
    ...(input.coOwnerKeys === undefined ? {} : { coOwnerKeys: capturedOwnerKeys(input.coOwnerKeys) }),
    ...(input.ownerPolicy === undefined ? {} : { ownerPolicy: capturedOwnerPolicy(input.ownerPolicy, "ownerPolicy") }),
  });
}
/** Caller owner keys (A-91 `coOwnerKeys`): 1..63 plain `{keyId, scheme, credential}`; the genesis schema judges them. */
function capturedOwnerKeys(value: unknown): readonly OwnerKey[] {
  requireCondition(Array.isArray(value) && value.length >= 1 && value.length <= 63);
  return Object.freeze((value as readonly unknown[]).map((key) => {
    const r = record(key, ["keyId", "scheme", "credential"]);
    requireCondition(r.scheme === "ed25519" || r.scheme === "eip191-personal-sign-keccak256");
    requireCondition(typeof r.credential === "string");
    return Object.freeze({ keyId: identifier(r.keyId), scheme: r.scheme as SignatureScheme, credential: r.credential as string });
  }));
}
/** A caller's owner approval policy, captured as plain data (no behaviour); its shape and validity are the engine's (A-91). */
function capturedOwnerPolicy(value: unknown, name: string): OwnerPolicy {
  const captured = captureData(value, 256 * 1024, 4096, 8);
  if (captured === null || typeof captured !== "object" || Array.isArray(captured)) throw new IronTrellisError("INVALID_INPUT", false, `${name}: must be an owner approval policy record`);
  return captured as unknown as OwnerPolicy;
}
/** A caller's key reference, checked and filed under `version` (an owner reference given as a next key is re-labelled, and back). */
export function capturedReference(value: unknown, version: KeyReferenceVersion, name: string): OwnerKeyReference {
  let parsed: OwnerKeyReference;
  try { parsed = parseKeyReference(JSON.parse(JSON.stringify(value)), name); } catch (error) { throw new IronTrellisError("INVALID_INPUT", false, error instanceof Error ? error.message : String(error)); }
  return withReferenceVersion(parsed, version);
}
const captureDomain = (value: unknown): AuthorizationDomain => {
  const protocol = (value as { protocol?: unknown } | null)?.protocol;
  if (protocol === "irontrellis") {
    const d = record(value, ["protocol", "version", "deploymentId"]);
    requireCondition(d.version === "1" || d.version === "2");
    return Object.freeze({ protocol: "irontrellis", version: d.version, deploymentId: identifier(d.deploymentId) }) as TrellisDomain;
  }
  const d = record(value, ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]);
  requireCondition(d.protocol === "continuity" && d.version === "0.2");
  return Object.freeze({
    protocol: "continuity", version: "0.2", deploymentId: identifier(d.deploymentId), chainId: identifier(d.chainId), verifyingContract: identifier(d.verifyingContract),
  }) as LegacyDomain;
};

// ---------------------------------------------------------------- store plumbing (shared with the runtime ports)

const PASS_THROUGH: ReadonlySet<string> = new Set<IronTrellisErrorCode>([
  "ROLLBACK_DETECTED", "INVALID_HISTORY", "HISTORY_EXISTS", "READ_UNAVAILABLE", "KEY_UNAVAILABLE", "CAPACITY_CONTROL_ONLY", "CAPACITY_EVENT_LIMIT", "CONTROL_AUTHORIZATION_INVALID",
  "HISTORY_FILE_LIMIT", "KEY_EXISTS", "ANCHOR_LOG_UNREADABLE", "WITNESS_UNREADABLE", "WITNESS_UNAVAILABLE", "WITNESS_SPLIT_VIEW", "SIGNER_FAILED",
  // Format 2 (SPEC §18): the store's fence and the replay codes the API reports as such; every other rejected transition is TRANSITION_REJECTED (with the replay code in `detail`).
  "FORMAT_READ_ONLY", "CAPACITY_EXCEEDED", "CAPACITY_RESERVED", "EFFECT_LIMIT", "COUNTERPARTY_SIGNATURE_INVALID", "REFUSAL_NOT_REPRODUCED", "INVALID_INPUT", "SESSION_FENCED", "CLOCK_AHEAD_OF_READER",
  "MIGRATION_MARKER_INVALID", "HISTORY_IDENTITY_MISMATCH", "ATTESTED_STATE_ROOT_MISMATCH", "OBSERVATION_DUPLICATE",
  "CHALLENGE_PROFILE_READ_ONLY",
]);
/**
 * Witness-client failures the owner API reports as WITNESS_UNAVAILABLE (the witness code is kept in `detail.cause`),
 * except a refused registration, which is WITNESS_REJECTED.
 */
const WITNESS_FAILURES: ReadonlySet<string> = new Set(["WITNESS_REJECTED", "WITNESS_INVALID_RESPONSE"]);
/** Translate engine/store failures into the owner API's stable codes. `fallback` is the code for an unrecognised failure. */
export function translate(error: unknown, fallback: "WRITE_UNCONFIRMED" | "READ_UNAVAILABLE" | "TRANSITION_REJECTED"): never {
  if (error instanceof IronTrellisError) throw error;
  if (error instanceof EngineError) {
    // STORE_BUSY keeps its message and detail (the lock path and its holder).
    if (error.code === "STORE_BUSY") throw new IronTrellisError("HISTORY_CONFLICT", false, error.message, error.detail);
    if (error.code === "STORE_CONFLICT") throw new IronTrellisError("HISTORY_CONFLICT");
    if (error.code === "WRITE_UNCONFIRMED") throw new IronTrellisError("WRITE_UNCONFIRMED", true, error.message, error.detail);
    if (PASS_THROUGH.has(error.code)) throw new IronTrellisError(error.code as IronTrellisErrorCode, false, error.message, error.detail);
    // A witness that refused to register the history: its own state (sticky until the policy changes), not unavailability.
    if (error.code === "WITNESS_REJECTED" && (error.detail as { reason?: unknown } | undefined)?.reason === "REGISTRATION_REFUSED") {
      throw new IronTrellisError("WITNESS_REJECTED", false, error.message, error.detail);
    }
    if (WITNESS_FAILURES.has(error.code)) throw new IronTrellisError("WITNESS_UNAVAILABLE", false, error.message, { ...(error.detail as object | undefined), cause: error.code });
    if (fallback === "WRITE_UNCONFIRMED") throw new IronTrellisError("TRANSITION_REJECTED", false, error.message, error.detail);
    throw new IronTrellisError(fallback, false, error.message, error.detail);
  }
  throw new IronTrellisError(fallback, fallback === "WRITE_UNCONFIRMED");
}

export function openStore(config: Config): HistoryStore {
  let store: HistoryStore;
  try {
    store = openHistoryStore(config.historyFile, {
      acceptRollback: config.acceptRollback, allowUnpinned: config.allowUnpinned, ...(config.signer === undefined ? {} : { signer: config.signer }),
      ...(config.witness === undefined ? {} : { witness: config.witness }),
      // SPEC §16.1: a legacy or format-1 file is read only, unless the caller named that format (the earlier writer; `LocalOwnerOptions.format`).
      readOnlyFormats: !(config.formatGiven && config.format !== TRELLIS2_FORMAT),
      // SPEC §7.5: the local API resumes from the snapshot by default (`trust`); A-19.4: the expected identity, when configured.
      trust: config.trust, ...(config.historyId === undefined ? {} : { historyId: config.historyId }),
    });
  } catch (error) {
    translate(error, "READ_UNAVAILABLE");
  }
  requireCondition(store.format !== undefined, "READ_UNAVAILABLE");
  return store;
}

/** The store's current state after the profile check: the selected domain, owner and policy must be the file's. */
export function currentState(store: HistoryStore, config: Config): ReplayState {
  let state: ReplayState;
  try { state = store.state(); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  const genesis = state.genesis, principal = state.events[1];
  requireCondition(
    genesis.policyVersion === POLICY_VERSIONS[state.format] && canonicalEncode(genesis.domain) === canonicalEncode(config.domain) &&
      principal?.type === "PRINCIPAL_CREATED" && principal.data.principalId === config.owner,
    "PROFILE_MISMATCH",
  );
  return state;
}

export const newEvent = (config: Config, type: EventType, timestamp: number, data: Readonly<Record<string, unknown>>): CanonicalEvent =>
  Object.freeze({ id: newEventId(config), type, timestamp, data });
/** A fresh event id (`event:<ids()>`); A-54 writers draw it before signing so the challenge binds it. */
export const newEventId = (config: Config): string => `event:${config.ids()}`;

/**
 * A signer's failure as the owner API reports it: KEY_UNAVAILABLE (the signer does not hold the key: removed from the
 * ssh-agent, a public-key-only next key) and SIGNER_FAILED (unreachable, refused, timed out, a signature that does not
 * verify) keep their message and detail; anything else is a bare SIGNER_FAILED (a signer's own error text is not echoed).
 */
export function signerFailure(error: unknown): IronTrellisError {
  if (error instanceof IronTrellisError && (error.code === "KEY_UNAVAILABLE" || error.code === "SIGNER_FAILED")) return error;
  if (error instanceof EngineError && (error.code === "KEY_UNAVAILABLE" || error.code === "SIGNER_FAILED")) return new IronTrellisError(error.code, false, error.message, error.detail);
  return new IronTrellisError("SIGNER_FAILED");
}

/** The owner key for control signatures; the key file is loaded lazily so read-only openers never need it. */
function ownerSigner(config: Config): Signer {
  if (config.signer !== undefined) return config.signer;
  try { return loadOwnerKeyFile(ownerKeyPathFor(config.historyFile)); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
}
/**
 * Attach the owner's control authorization (format 1 control events only).
 * Local key material signs synchronously so a legacy or locally-keyed write
 * completes within the caller's synchronous turn (no lock is released across
 * an `await`); a KMS-style signer yields a promise.
 */
const signControl = (config: Config, state: ReplayState, event: CanonicalEvent, previousHead: HistoryHead | null, cosigned = false): CanonicalEvent | Promise<CanonicalEvent> => {
  if (!isTrellis(state.format) || !CONTROL_EVENT_TYPES.has(event.type)) return event;
  const signer = ownerSigner(config), algorithm = state.hashAlgorithm;
  // A-92.4: the writer's pre-check of one signature against the policy in force (`cosigned`: the caller collects more).
  if (!cosigned) assertSingleSigner(state, event.type, signer, event);
  const effect = controlEffect(event.data);
  const hash = controlAuthorizationHash({
    domain: state.genesis.domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
    previousHead: previousHead === null ? null : { hash: previousHead.hash, position: previousHead.position },
    effectHash: controlEffectHash({ ...event, data: effect }, algorithm),
  }, algorithm);
  const attach = (signature: HexSignature): CanonicalEvent =>
    Object.freeze({ id: event.id, type: event.type, timestamp: event.timestamp, data: Object.freeze({ ...effect, controlAuthorization: Object.freeze({ keyId: signer.keyId, signature }) }) });
  const failed = (error: unknown): never => { throw signerFailure(error); };
  if (signer.signHashSync !== undefined) { try { return attach(signer.signHashSync(hash)); } catch (error) { return failed(error); } }
  // An external signer (an ssh-agent, Vault, a command: each request may be a person's approval or a hardware touch) is
  // asked only for a key in force: a key file swapped for another reference asks nobody.
  if (!ownerKeyInForce(state, state.head.position + 1, signer)) {
    throw new IronTrellisError("CONTROL_AUTHORIZATION_INVALID", false,
      `the owner key ${signer.keyId} (${signer.custody?.description ?? "a signer"}) is not an owner key in force for this history; its signer was not asked`);
  }
  return signer.signHash(hash, { purpose: "control-authorization", historyId: state.eventHistoryHashes[0]! }).then(attach, failed);
};

/**
 * A-92.4 / A-92.6 writer pre-check: refuses (CONTROL_AUTHORIZATION_INVALID with `{required, present}`) a control event of
 * `type` that one signature by `signer` cannot authorize under the policy in force for the next event: it needs two or
 * more owner signatures (`M_eff`, with power reduction by effect when `event` is given, A-106.2), or the key is AGENT (an
 * agent never signs alone). Nothing is signed or written. A history without a policy always passes.
 */
function assertSingleSigner(state: ReplayState, type: EventType, signer: Readonly<{ keyId: string; scheme: SignatureScheme; credential: string }>, event?: CanonicalEvent): void {
  if (!isFormat2(state.format)) return;
  const next = state.head.position + 1, policy = ownerPolicyAt(state, next);
  if (policy === undefined) return;
  const required = event === undefined ? effectiveThreshold(policy, type) : controlThreshold(policy, event, state);
  const agent = ownerKeyClass(policy, ownerKeysAt(state, next), signer) === "AGENT";
  if (required < 2 && !agent) return;
  const present = agent && type === "OWNER_KEYS_ROTATED" ? 0 : 1;
  // A-116.1 / A-127.3: say why a lowered byType count did not apply (the event does not reduce power in this state).
  const lowered = event !== undefined && required > effectiveThreshold(policy, type);
  const why = !lowered ? "" : type === "AGENT_TERMINATED"
    ? " (the agent is on the anchor path of a live prohibition, so terminating it is not a power reduction; fence it instead, A-127.2)"
    : " (in this state the event does not reduce power, so the lowered count does not apply, A-116.1)";
  throw new IronTrellisError("CONTROL_AUTHORIZATION_INVALID", false,
    `${type} needs ${required} owner signature(s) under the owner approval policy in force${why}${agent ? ` and ${signer.keyId} is an AGENT key, which never authorizes alone` : ""}; collect the co-signatures with prepareControlEvent and submitControlEvent`,
    { required, present });
}

/** How many times an owner write waits for this handle's witness sections before it gives up with the lock error. */
const WRITER_WAITS = 64;
/**
 * Runs a synchronous write under the store's writer lock. While this store's own witness session holds that lock (a
 * locked section signing a head statement with an asynchronous signer: ssh-agent, KMS, a command), the write waits for
 * the session's sections to finish and tries again, instead of failing with the lock this very process holds. Any other
 * failure, and a lock held by another process (the store already waited for it), is thrown as it is.
 */
async function whenWriterFree<T>(store: HistoryStore, write: () => T): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return write();
    } catch (error) {
      const settled = error instanceof EngineError && error.code === "STORE_BUSY" && attempt < WRITER_WAITS ? witnessSessionOf(store)?.lockedSectionsSettled() : undefined;
      if (settled === undefined) throw error;
      await settled;
    }
  }
}

/**
 * A checkpoint this handle cannot sign to the policy, reported as `CHECKPOINT_SUPPRESSED {reason: NO_SIGNER}` and never written
 * short: A-92.3(b), the handle's keys cannot form a counting set of `M_eff(STATE_CHECKPOINT)` (KEY_UNAVAILABLE, or
 * CONTROL_AUTHORIZATION_INVALID before signing); A-119.3, the only counting set would violate rule T2 at the intended timestamp
 * (A-172.2's TRANSITION_REJECTED {reason: ATTESTATION_HORIZON}; TRANSITION_INVALID kept for a replay-coded refusal).
 */
function noSignerRefusal(error: unknown): boolean {
  const code = error instanceof IronTrellisError || error instanceof EngineError ? error.code : undefined;
  const detail = error instanceof IronTrellisError ? error.detail : undefined;
  const horizon = code === "TRANSITION_REJECTED" && detail !== null && typeof detail === "object" && (detail as { reason?: unknown }).reason === "ATTESTATION_HORIZON";
  return code === "KEY_UNAVAILABLE" || code === "CONTROL_AUTHORIZATION_INVALID" || code === "TRANSITION_INVALID" || horizon;
}
/** A-172.2: rule T2 refused by the writer: TRANSITION_REJECTED {reason: ATTESTATION_HORIZON, horizon}, never TRANSITION_INVALID. */
function horizonRefusal(time: Readonly<{ reason: string; horizon: U53 }>): IronTrellisError {
  return new IronTrellisError("TRANSITION_REJECTED", false, time.reason, { reason: "ATTESTATION_HORIZON", horizon: time.horizon });
}
/**
 * A prospective control event the replay rules refuse: CONTROL_AUTHORIZATION_INVALID as such, anything else TRANSITION_REJECTED;
 * a rule-T2 refusal carries `{reason: ATTESTATION_HORIZON, horizon}` (A-172.2).
 */
function prospectiveRefusal(state: ReplayState, event: CanonicalEvent, position: U53, failure: Readonly<{ code: string; reason: string }>): IronTrellisError {
  if (failure.code === "CONTROL_AUTHORIZATION_INVALID") return new IronTrellisError("CONTROL_AUTHORIZATION_INVALID", false, failure.reason);
  const time = failure.code === "TRANSITION_INVALID" && isFormat2(state.format) ? singleSignerTimeFailure(state, event, position, controlRuleAt(state, event, position)) : undefined;
  return time === undefined ? new IronTrellisError("TRANSITION_REJECTED", false, failure.reason) : horizonRefusal(time);
}
/**
 * One owner-side append: capacity → clock → control signature (format 1) →
 * conditional append at `expectedHead`. The store validates the transition
 * incrementally; a rejected event never touches the file.
 */
export async function appendEvent(store: HistoryStore, config: Config, state: ReplayState, event: CanonicalEvent, expectedHead: HistoryHead, presigned = false): Promise<WriteResult> {
  assertWritable(store);
  { const before = witnessBeforeWrite(store); if (before !== undefined) await before; }
  try { assertCapacityTransition(state, [event]); } catch (error) { translate(error, "TRANSITION_REJECTED"); }
  requireCondition(event.timestamp >= expectedHead.canonicalTime, "CLOCK_INVALID");
  // A-109.1 writer pre-check: under an ATTESTED owner policy a session-signed or administrative event never passes an
  // attestation's expiry. A-172.2: the API refuses with TRANSITION_REJECTED {reason: ATTESTATION_EXPIRY, expiresAt}, never the
  // replay code TRANSITION_INVALID.
  // A-179.4: a ◇ or ▲ event that would fail rule T3 is not signed. The session-signed paths that reach this function run the same
  // checks before they ask for the session's signature (session-write-checks.ts; the full list of signer call sites and their
  // checks is in the step 5 records, DEVIATIONS r2.2), so this is the last line for an already-signed event. A path that
  // signs and appends without coming here, such as the durable coordinator's consumption and outcome records, checks itself.
  assertSessionWriteTime(state, event, expectedHead.position + 1);
  // `presigned`: the event already carries every owner signature (submitControlEvent).
  const signing = presigned ? event : signControl(config, state, event, expectedHead);
  const signed = signing instanceof Promise ? await signing : signing;
  // A-119.4 writer pre-check: rule T2 for a control event this handle signed alone (A-172.2: TRANSITION_REJECTED
  // {reason: ATTESTATION_HORIZON, horizon}).
  if (!presigned && isFormat2(state.format) && CONTROL_EVENT_TYPES.has(signed.type)) {
    const position = expectedHead.position + 1, time = singleSignerTimeFailure(state, signed, position, controlRuleAt(state, signed, position));
    if (time !== undefined) throw horizonRefusal(time);
  }
  let result: WriteResult;
  try {
    result = Object.freeze({ eventId: signed.id, head: await whenWriterFree(store, () => store.appendAtExpectedHead(signed, expectedHead)) });
  } catch (error) {
    translate(error, "WRITE_UNCONFIRMED");
  }
  await attested(store);
  { const after = witnessAfterWrite(store); if (after !== undefined) { await after; await attested(store); } }
  return result;
}

/**
 * A-41: whether an enforcement caller may act on the history at `path` (format `format`). A fenced history (a
 * `.migrated` marker) is always `FORMAT_READ_ONLY {reason: MIGRATED, target}`; a legacy or format-1 history is
 * `FORMAT_READ_ONLY {reason: LEGACY | FORMAT_1}` unless `optIn` (`enforceFromReadOnlyHistory`, never-migrated files
 * only), in which case the returned warning MUST be logged on this open. Format 2: `undefined`.
 */
export function enforcementWarning(path: string, format: HistoryFormat | undefined, optIn: boolean): string | undefined {
  const marker = readMigratedMarker(path);
  if (marker !== undefined) {
    const target = markerTargetPath(path, marker.target); // A-184.1: either form, resolved against the source's directory
    throw new IronTrellisError("FORMAT_READ_ONLY", false, `history ${path} was migrated to ${target}: an enforcement caller never acts on a fenced history (A-41); point it at the target`, { reason: "MIGRATED", target });
  }
  if (format === undefined || format === TRELLIS2_FORMAT) return undefined;
  const reason = format === LEGACY_FORMAT ? "LEGACY" : "FORMAT_1";
  const kind = reason === "LEGACY" ? "legacy" : "format-1";
  if (!optIn) {
    throw new IronTrellisError("FORMAT_READ_ONLY", false, `history ${path} is a ${kind} file: enforcement callers refuse it (A-41); migrate it to format 2 (irontrellis migrate), or set "enforceFromReadOnlyHistory": true in the hook or gateway config to keep enforcing from this never-migrated file`, { reason });
  }
  return `IronTrellis: enforcing from the ${kind} history ${path} (enforceFromReadOnlyHistory); migrate it to format 2 (irontrellis migrate)`;
}
/** A-41 for the local handles: the earlier writer named by `format` (A-30, test and compatibility only) counts as the opt-in. */
export function assertEnforceable(store: HistoryStore, config: Config): void {
  const warning = enforcementWarning(store.path, store.format, config.enforceFromReadOnlyHistory === true || (config.formatGiven && config.format === store.format));
  if (warning !== undefined && config.enforceFromReadOnlyHistory === true) process.emitWarning(warning, { code: "IRONTRELLIS_READ_ONLY_ENFORCEMENT" });
}

/** SPEC §16.1: a read-only file refuses every write before any clock, key or witness is consulted. */
export function assertWritable(store: HistoryStore): void {
  const reason = store.readOnlyReason();
  if (reason === undefined) return;
  throw new IronTrellisError("FORMAT_READ_ONLY", false, `history ${store.path} is a ${reason === "LEGACY" ? "legacy" : "format-1"} file: it opens read only (SPEC §16.1); migrate it to format 2 to write, or open it with that format named explicitly for the earlier writer`, { reason });
}

/**
 * Waits until the pin of the write just made carries its attestation (an asynchronous signer attests after the append:
 * KMS, ssh-agent, command). Never rejects: a failed attestation is reported by `flush()` (SIGNER_FAILED), the event
 * itself is durable either way. Nothing to wait for with local key material (it attests within the append).
 */
export async function attested(store: HistoryStore): Promise<void> {
  await store.attestationsSettled();
}

/**
 * Remote witnesses around an owner-keyed write: before the first write of the
 * process, the witnesses are asked (a rollback they show refuses the write);
 * after it, sync mode submits the head statement (rollback evidence throws; an
 * unreachable witness leaves it queued). No-ops without remote witnesses or
 * without an owner key in force.
 */
export function witnessBeforeWrite(store: HistoryStore): Promise<void> | undefined {
  // `undefined` when there is nothing to wait for: a write without remote witnesses stays synchronous up to the store lock.
  const session = witnessSessionOf(store);
  if (session?.active !== true) return undefined;
  let pending: Promise<void> | undefined;
  try { pending = session.beforeOwnerWrite(); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  return pending?.catch((error: unknown) => translate(error, "READ_UNAVAILABLE"));
}
export function witnessAfterWrite(store: HistoryStore): Promise<void> | undefined {
  const session = witnessSessionOf(store);
  if (session?.active !== true) return undefined;
  let pending: Promise<void> | undefined;
  try { pending = session.afterOwnerWrite(); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  return pending?.catch((error: unknown) => translate(error, "READ_UNAVAILABLE"));
}

// ---------------------------------------------------------------- event data builders

const constraintsOf = (r: Record<string, unknown>, extra: Partial<AuthorityConstraints> = {}): AuthorityConstraints => Object.freeze({
  actions: identifiers(r.actions), resources: identifiers(r.resources),
  quantitative: Object.hasOwn(r, "maxAmount") || Object.hasOwn(r, "maxCumulativeAmount"),
  ...optional(r, "expiresAt", time), ...optional(r, "notBefore", time), ...optional(r, "maxAmount", amount), ...optional(r, "maxCumulativeAmount", amount),
  ...optional(r, "maxTransactions", time),
  maxDelegationDepth: 0, requiredIntersectionIds: [], ...extra,
}) as AuthorityConstraints;

const permissionGrant = (r: Record<string, unknown>, owner: string, state: ReplayState) => {
  const id = identifier(r.id), parent = Object.hasOwn(r, "parent") ? identifier(r.parent) : undefined;
  const from = Object.hasOwn(r, "from") ? identifier(r.from) : owner;
  if (Object.hasOwn(r, "independent")) requireCondition(typeof r.independent === "boolean");
  // A delegation inherits its parent's root; an unknown parent is left for replay to refuse (TRANSITION_REJECTED).
  const parentGrant = parent === undefined ? undefined : state.authorities.get(parent)?.grant;
  const root = parentGrant?.kind === "PERMISSION" ? parentGrant.rootAuthorityId : id;
  return {
    kind: "PERMISSION" as const, authorityId: id, grantorId: from, granteeId: identifier(r.to), rootAuthorityId: root,
    ...(parent === undefined ? {} : { parentAuthorityId: parent }), independent: r.independent !== false,
    constraints: constraintsOf(r, {
      expiresAt: time(r.expiresAt),
      maxDelegationDepth: Object.hasOwn(r, "delegable") ? time(r.delegable) : 0,
      requiredIntersectionIds: Object.hasOwn(r, "requires") ? identifiers(r.requires) : [],
    }),
  };
};
const GRANT_REQUIRED = ["id", "to", "actions", "resources", "expiresAt"];
const GRANT_OPTIONAL = ["notBefore", "maxAmount", "maxCumulativeAmount", "maxTransactions", "delegable", "requires", "independent", "parent", "from"];

const successionSteps = (config: Config, r: Record<string, unknown>) => {
  const id = identifier(r.id), rule = identifier(r.rule), fromAgent = identifier(r.fromAgent), fromTenure = identifier(r.fromTenure);
  const toAgent = identifier(r.toAgent), toTenure = identifier(r.toTenure), role = identifier(r.role), number = time(r.number);
  requireCondition(number > 0);
  return [
    { id: `handover:${id}:retire`, type: "AGENT_TERMINATED" as const,
      data: { agentId: fromAgent, principalId: config.owner, successionRuleId: rule, roleId: role, roleTenureId: fromTenure } },
    { id: `handover:${id}:transfer`, type: "ROLE_TRANSFERRED" as const,
      data: { roleId: role, fromAgentId: fromAgent, fromRoleTenureId: fromTenure, toAgentId: toAgent, toRoleTenureId: toTenure, toTenureNumber: number,
        principalId: config.owner, transferKind: "SUCCESSION", successionRuleId: rule } },
  ];
};

const OPEN_STATUSES: ReadonlySet<string> = new Set(["OPEN", "OUTCOME_UNKNOWN", "DISPUTED"]);
const live = (expiresAt: U53 | undefined, notBefore: U53 | undefined, at: number): boolean =>
  (expiresAt === undefined || at < expiresAt) && (notBefore === undefined || at >= notBefore);

/** The plain-language offboarding summary: what an agent holds when it leaves and what does not follow it. */
function handoverReport(state: ReplayState, agentId: string, at: number): HandoverReport {
  const agent = state.agents.get(agentId);
  requireCondition(agent !== undefined, "INVALID_INPUT");
  const tenures = [...(state.currentTenureIdsByAgent.get(agentId) ?? [])].map((id) => state.tenures.get(id)).filter((t) => t !== undefined)
    .map((t) => Object.freeze({ roleId: t.roleId, tenureId: t.id, tenureNumber: t.tenureNumber, ...(t.successionRuleId === undefined ? {} : { successionRuleId: t.successionRuleId }) }));
  const sessions = (state.runtimeSessionIdsByAgent.get(agentId) ?? []).map((id) => state.runtimeSessions.get(id)).filter((s) => s !== undefined)
    .map((s) => Object.freeze({ sessionId: s.id, controlEpoch: s.controlEpoch, credentialKeyId: s.credentialKeyId, ...(s.expiresAt === undefined ? {} : { expiresAt: s.expiresAt }),
      current: !agent.terminated && s.controlEpoch === agent.currentControlEpoch && !sessionExpiredAt(state, s, at) })); // A-149.0
  const openDuties = [
    ...[...state.obligations.values()].filter((o) => o.performanceAssigneeId === agentId && OPEN_STATUSES.has(o.status)).map((o) => Object.freeze({
      kind: "OBLIGATION" as const, id: o.record.obligationId, status: o.status, assignee: o.performanceAssigneeId, description: o.record.description,
      deadline: o.record.deadline, sourceIntentId: o.record.sourceIntentId, successionRuleId: o.record.successionRuleId })),
    ...[...state.attemptDuties.values()].filter((d) => d.currentAssigneeId === agentId && OPEN_STATUSES.has(String(d.record.status))).map((d) => Object.freeze({
      kind: "ATTEMPT_DUTY" as const, id: d.record.dutyId, status: String(d.record.status), assignee: d.currentAssigneeId, description: String(d.record.description),
      deadline: Number(d.record.deadline), sourceIntentId: d.record.sourceIntentId })),
  ];
  const liveGrants = [], delegationsIssued = [];
  for (const a of state.authorities.values()) {
    const g = a.grant;
    if (g.kind !== "PERMISSION" || a.revocationEventId !== undefined || !live(g.constraints.expiresAt, g.constraints.notBefore, at)) continue;
    const expiry = g.constraints.expiresAt === undefined ? {} : { expiresAt: g.constraints.expiresAt };
    if (g.granteeId === agentId) liveGrants.push(Object.freeze({ authorityId: g.authorityId, grantorId: g.grantorId, rootAuthorityId: g.rootAuthorityId,
      delegated: g.parentAuthorityId !== undefined, actions: g.constraints.actions, resources: g.constraints.resources, ...expiry, followsSuccession: false as const }));
    if (g.grantorId === agentId) delegationsIssued.push(Object.freeze({ authorityId: g.authorityId, granteeId: g.granteeId, actions: g.constraints.actions, resources: g.constraints.resources, ...expiry }));
  }
  return Object.freeze({
    agent: agentId, terminated: agent.terminated, asOf: at, head: state.head, tenures, sessions, openDuties, liveGrants, delegationsIssued,
    survives: survivesState(state, { targetAgentId: agentId, evaluationTime: at, disclosure: publicQueryDisclosure("SURVIVES", state.format) }),
  });
}

// ---------------------------------------------------------------- owner key files around a rotation

/** Best effort; skipped on Windows, which cannot fsync a directory (platform.ts). */
const fsyncDirectoryOf = (path: string): void => { syncDirectorySync(dirname(path), { bestEffort: true }); };
let archiveCounter = 0;
/** Writes `text` to `path` (mode 0600, temp + fsync + rename + directory fsync). */
function writePrivateAtomically(path: string, text: string): void {
  const temporary = `${path}.tmp-${process.pid}-${(archiveCounter += 1)}`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    writeSync(fd, Buffer.from(text));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try { replaceFileSync(temporary, path); } catch (error) { try { unlinkSync(temporary); } catch { /* best effort */ } throw error; }
  fsyncDirectoryOf(path);
}
/**
 * Copies the key file at `from` to `<history>.owner-key.<keyId>.retired.json`
 * (mode 0600, temp + fsync + rename); a name already holding other bytes gets a
 * `-2`, `-3`… suffix, the same bytes are not written twice. Returns the path.
 */
function archiveOwnerKeyFile(from: string, historyFile: string, keyId: string): string {
  const bytes = readFileSync(from);
  let target = retiredOwnerKeyPathFor(historyFile, keyId);
  for (let n = 2; existsSync(target); n += 1) {
    if (readFileSync(target).equals(bytes)) return target;
    target = `${historyFile}.owner-key.${keyIdFileFragment(keyId)}-${n}.retired.json`;
  }
  const temporary = `${target}.tmp-${process.pid}-${(archiveCounter += 1)}`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    writeSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try { replaceFileSync(temporary, target); } catch (error) { try { unlinkSync(temporary); } catch { /* best effort */ } throw error; }
  fsyncDirectoryOf(target);
  return target;
}

type KeyFileSettlement = Readonly<{ completed: boolean; signer?: Signer; keyFile?: string; retiredKeyFile?: string }>;

// ---------------------------------------------------------------- the prepared-rotation record (docs/reference/witness-operations.md §7.1)

/** The prepared-rotation record when it is OUTSTANDING against `state`: its staged key files are kept, whatever settles them. */
function outstandingRotation(historyFile: string, state: ReplayState): PendingRotationRecord | undefined {
  const path = pendingRotationPathFor(historyFile);
  if (!existsSync(path)) return undefined;
  const record = readPendingRotation(path);
  if (record === undefined || record === null) return undefined;
  return judgePendingRotation(state, record).status === "OUTSTANDING" ? record : undefined;
}
/** A record that is no longer OUTSTANDING (the rotation was appended, or the history moved on without it) is removed. */
function dropSettledRecord(historyFile: string, state: ReplayState): void {
  const path = pendingRotationPathFor(historyFile);
  if (!existsSync(path)) return;
  const record = readPendingRotation(path);
  if (record === undefined) return;
  if (record !== null && judgePendingRotation(state, record).status === "OUTSTANDING") return;
  try { removePendingRotation(path); } catch { /* next time */ }
}

/** Test-only fault injection: the named step of a two-phase rotation "crashes" (throws `RotationFault`, and nothing is cleaned up). */
export class RotationFault extends Error {}
let rotationFault: string | undefined;
/** Not exported from the package root: tests simulate a crash at one of `after-stage`, `after-record`, `after-delivery`, `after-append`, `after-owner-key-swap`. */
export function setRotationFaultForTests(point: string | undefined): void {
  rotationFault = point;
}
const faultAt = (point: string): void => {
  if (rotationFault === point) { rotationFault = undefined; throw new RotationFault(`simulated crash ${point}`); }
};
/**
 * Brings the key files next to `historyFile` in line with the owner key set in
 * force after `state`'s head (crash recovery of `rotateOwnerKey`). Call it
 * under the writer lock with a fresh state. A pending key file
 * (`<history>.owner-key.pending.json`) whose key the history declares in its
 * current set means the rotation was recorded but the files were not swapped:
 * the key file is archived when its key is no longer in force and the pending
 * file takes its place. A pending key the history never declared means the
 * rotation was never recorded: it is removed. Anything else is left alone.
 */
function settleOwnerKeyFiles(historyFile: string, state: ReplayState): KeyFileSettlement | undefined {
  const pending = pendingOwnerKeyPathFor(historyFile), keyPath = ownerKeyPathFor(historyFile);
  if (!isTrellis(state.format) || !existsSync(pending)) return undefined;
  let candidate: Signer;
  try { candidate = loadOwnerKeyFile(pending); } catch { return undefined; } // unreadable: left for the operator
  const next = state.head.position + 1;
  if (ownerKeyInForce(state, next, candidate)) {
    let retiredKeyFile: string | undefined;
    if (existsSync(keyPath)) {
      let old: Signer | undefined;
      try { old = loadOwnerKeyFile(keyPath); } catch { old = undefined; }
      if (old !== undefined && ownerKeyInForce(state, next, old)) return undefined; // both in force: not a rotation this engine made
      retiredKeyFile = archiveOwnerKeyFile(keyPath, historyFile, old?.keyId ?? "unreadable");
    }
    replaceFileSync(pending, keyPath);
    fsyncDirectoryOf(keyPath);
    return Object.freeze({ completed: true, signer: candidate, keyFile: keyPath, ...(retiredKeyFile === undefined ? {} : { retiredKeyFile }) });
  }
  const declared = state.ownerKeyEpochs.some((epoch) => epoch.keys.some((key) => key.keyId === candidate.keyId || key.credential.toLowerCase() === candidate.credential.toLowerCase()));
  if (!declared) {
    // Staged by a prepared rotation that is still outstanding (docs/reference/witness-operations.md §7.1): kept, it may yet be recorded.
    const outstanding = outstandingRotation(historyFile, state);
    if (outstanding !== undefined && sameKeyMaterial(outstanding.incoming, candidate)) return undefined;
    unlinkSync(pending);
    fsyncDirectoryOf(pending);
    return Object.freeze({ completed: false });
  }
  return undefined;
}
/** Every digest any epoch of `state` committed to. */
const everCommitted = (state: ReplayState): ReadonlySet<string> => new Set(state.ownerKeyEpochs.flatMap((epoch) => epoch.nextKeyDigests ?? []));
const sameKeyMaterial = (a: Readonly<{ scheme: string; credential: string }>, b: Readonly<{ scheme: string; credential: string }>): boolean =>
  a.scheme === b.scheme && a.credential.toLowerCase() === b.credential.toLowerCase();

type NextKeyFileSettlement = Readonly<{ completed: boolean; nextKeyFile?: string }>;
/**
 * The next-key half of the crash recovery (commitments and pre-rotated rotations; call it under the writer lock with a
 * fresh state, after `settleOwnerKeyFiles`). A pending next-key file (`<history>.owner-next-key.pending.json`) whose
 * digest the owner keys in force committed to means the event was recorded but the file was not moved: it replaces
 * `<history>.owner-next-key.json` (whose key, if it was the one the rotation revealed, is by then the owner key file).
 * A pending next key no epoch ever committed to was never recorded: it is removed. Anything else is left alone, and so
 * is a next-key file that still holds a key in force the owner key file does not hold.
 */
function settleNextKeyFiles(historyFile: string, state: ReplayState): NextKeyFileSettlement | undefined {
  const pending = pendingNextOwnerKeyPathFor(historyFile), nextPath = nextOwnerKeyPathFor(historyFile);
  if (!isTrellis(state.format) || !existsSync(pending)) return undefined;
  let candidate: Signer;
  try { candidate = loadNextOwnerKeyFile(pending); } catch { return undefined; } // unreadable: left for the operator
  const digest = ownerKeyDigest(candidate);
  const current = state.ownerKeyEpochs.at(-1);
  if (current?.nextKeyDigests?.includes(digest) === true) {
    if (existsSync(nextPath)) {
      let old: Signer;
      try { old = loadNextOwnerKeyFile(nextPath); } catch { return undefined; } // unreadable: never overwritten, left for the operator
      if (!sameKeyMaterial(old, candidate)) {
        // Only a copy of a key the history declared (the key the rotation revealed, now an owner key, or a retired one) is
        // replaced; the committed next key itself and a key the history never declared are never overwritten.
        if (current.nextKeyDigests.includes(ownerKeyDigest(old))) return undefined;
        if (!state.ownerKeyEpochs.some((epoch) => epoch.keys.some((key) => sameKeyMaterial(key, old)))) return undefined;
      }
    }
    replaceFileSync(pending, nextPath);
    fsyncDirectoryOf(nextPath);
    return Object.freeze({ completed: true, nextKeyFile: nextPath });
  }
  const declared = state.ownerKeyEpochs.some((epoch) => epoch.keys.some((key) => sameKeyMaterial(key, candidate)));
  if (!everCommitted(state).has(digest) && !declared) {
    const outstanding = outstandingRotation(historyFile, state);
    if (outstanding?.nextKeyDigests?.includes(digest) === true) return undefined;
    unlinkSync(pending);
    fsyncDirectoryOf(pending);
    return Object.freeze({ completed: false });
  }
  return undefined;
}

/** Both halves of the recovery, owner key first (the next-key file may hold the key the owner key file is waiting for). */
function settleKeyFiles(historyFile: string, state: ReplayState): Readonly<{ current?: KeyFileSettlement; next?: NextKeyFileSettlement }> {
  let current: KeyFileSettlement | undefined, next: NextKeyFileSettlement | undefined;
  dropSettledRecord(historyFile, state);
  try { current = settleOwnerKeyFiles(historyFile, state); } catch { current = undefined; }
  try { next = settleNextKeyFiles(historyFile, state); } catch { next = undefined; }
  return Object.freeze({ ...(current === undefined ? {} : { current }), ...(next === undefined ? {} : { next }) });
}

/** `settleOwnerKeyFiles` (and the next-key files) under the store's writer lock; skipped (next time) when the lock is busy or anything fails. */
function settleOwnerKeyFilesLocked(store: HistoryStore, historyFile: string): KeyFileSettlement | undefined {
  if (!existsSync(pendingOwnerKeyPathFor(historyFile)) && !existsSync(pendingNextOwnerKeyPathFor(historyFile)) && !existsSync(pendingRotationPathFor(historyFile))) return undefined;
  try { return store.withExclusiveWriter(() => settleKeyFiles(historyFile, store.state()).current); } catch { return undefined; }
}

/** The next-key half alone (handles with a caller's signer never swap owner key files), under the writer lock. */
function settleNextKeyFilesLocked(store: HistoryStore, historyFile: string): undefined {
  if (!existsSync(pendingNextOwnerKeyPathFor(historyFile)) && !existsSync(pendingRotationPathFor(historyFile))) return undefined;
  try { store.withExclusiveWriter(() => { const state = store.state(); dropSettledRecord(historyFile, state); settleNextKeyFiles(historyFile, state); }); } catch { /* next time */ }
  return undefined;
}

/** The next free `owner:N` key id not in `seen`. */
export const nextFreeOwnerKeyId = (seen: ReadonlySet<string>): string => {
  let n = 1;
  for (const id of seen) {
    const match = /^owner:([1-9][0-9]{0,8})$/.exec(id);
    if (match !== null) n = Math.max(n, Number(match[1]) + 1);
  }
  while (seen.has(`owner:${n}`)) n += 1;
  return `owner:${n}`;
};

/** The next free `owner:N` key id: one past the highest N any epoch used, skipping ids already seen. */
const nextOwnerKeyId = (state: ReplayState): string => nextFreeOwnerKeyId(new Set(state.ownerKeyEpochs.flatMap((epoch) => epoch.keys.map((key) => key.keyId))));
const utf8Bytes = (text: string): number => Buffer.byteLength(text, "utf8");

// ---------------------------------------------------------------- rotation input, challenge signing, owner key status

type RotationOptions = Readonly<{
  newSigner?: Signer; nextSigner?: Signer; newNextSigner?: Signer; nextKeyFile?: string; nextKey?: boolean; keyId?: string; reason?: string; retire?: readonly string[]; emergency?: boolean;
  newNextPublicKey?: string; newNextKeyReference?: OwnerKeyReference;
  ownerPolicy?: OwnerPolicy; resetPolicy?: boolean;
  /** `commitNextKey`: keep every owner key and only add the commitment (a commitment-only rotation). Not a public option. */
  commitOnly?: true;
}>;
/** `rotateOwnerKey` / `prepareOwnerKeyRotation` input, checked before anything is read or written. */
function rotationOptions(input: OwnerKeyRotation): RotationOptions {
  requireCondition(input !== null && typeof input === "object" && !Array.isArray(input));
  const signers = ["newSigner", "nextSigner", "newNextSigner", "newNextKeyReference"] as const;
  const allowed: readonly string[] = [...signers, "keyId", "reason", "retire", "nextKeyFile", "nextKey", "emergency", "newNextPublicKey", "ownerPolicy", "resetPolicy"];
  requireCondition(Object.keys(input).every((key) => allowed.includes(key)));
  requireCondition(input.resetPolicy === undefined || typeof input.resetPolicy === "boolean");
  if (input.ownerPolicy !== undefined && input.resetPolicy === true) throw new IronTrellisError("INVALID_INPUT", false, "pass ownerPolicy or resetPolicy, not both");
  const policy = input.ownerPolicy === undefined ? undefined : capturedOwnerPolicy(input.ownerPolicy, "ownerPolicy");
  for (const key of ["newSigner", "nextSigner", "newNextSigner"] as const) requireCondition(input[key] === undefined || isSigner(input[key]));
  const r = record(Object.fromEntries(Object.entries(input).filter(([key, value]) => !(signers as readonly string[]).includes(key) && key !== "ownerPolicy" && key !== "resetPolicy" && value !== undefined)), [], ["keyId", "reason", "retire", "nextKeyFile", "nextKey", "emergency", "newNextPublicKey"]);
  let newNextPublicKey: string | undefined;
  if (r.newNextPublicKey !== undefined) {
    try { newNextPublicKey = parsePublicKey(r.newNextPublicKey as string); } catch (error) { throw new IronTrellisError("INVALID_INPUT", false, `newNextPublicKey: ${error instanceof Error ? error.message : String(error)}`); }
  }
  const newNextKeyReference = input.newNextKeyReference === undefined ? undefined : capturedReference(input.newNextKeyReference, OWNER_NEXT_KEY_REF_VERSION, "newNextKeyReference");
  if ([input.newNextSigner, newNextPublicKey, newNextKeyReference].filter((v) => v !== undefined).length > 1) {
    throw new IronTrellisError("INVALID_INPUT", false, "pass the new next key once: newNextSigner, newNextPublicKey or newNextKeyReference");
  }
  requireCondition(r.emergency === undefined || typeof r.emergency === "boolean");
  const reason = r.reason;
  requireCondition(reason === undefined || (typeof reason === "string" && reason.length > 0 && utf8Bytes(reason) <= 256 && !/[\u0000-\u001f\u007f]/.test(reason)));
  const retire = r.retire ?? "all";
  requireCondition(retire === "all" || (Array.isArray(retire) && retire.length <= 64));
  const retireList = retire === "all" ? undefined : (retire as unknown[]).map(identifier);
  requireCondition(retireList === undefined || new Set(retireList).size === retireList.length);
  const keyId = r.keyId === undefined ? undefined : identifier(r.keyId);
  const nextKeyFile = r.nextKeyFile;
  requireCondition(nextKeyFile === undefined || (typeof nextKeyFile === "string" && nextKeyFile.length > 0 && !nextKeyFile.includes("\0")));
  requireCondition(r.nextKey === undefined || typeof r.nextKey === "boolean");
  const { newSigner, nextSigner, newNextSigner } = input;
  if (newSigner !== undefined && (nextSigner !== undefined || nextKeyFile !== undefined)) throw new IronTrellisError("INVALID_INPUT", false, "newSigner cannot be combined with nextSigner or nextKeyFile: a pre-rotated rotation's new key is the committed next key");
  if (nextSigner !== undefined && nextKeyFile !== undefined) throw new IronTrellisError("INVALID_INPUT", false, "pass the committed next key once: nextSigner or nextKeyFile");
  if (r.nextKey === false && (newNextSigner !== undefined || newNextPublicKey !== undefined || newNextKeyReference !== undefined)) {
    throw new IronTrellisError("INVALID_INPUT", false, "a new next key (newNextSigner, newNextPublicKey, newNextKeyReference) cannot be combined with nextKey: false");
  }
  const fixed = newSigner ?? nextSigner;
  if (fixed !== undefined) requireCondition(keyId === undefined || keyId === fixed.keyId);
  return Object.freeze({
    ...(newSigner === undefined ? {} : { newSigner }), ...(nextSigner === undefined ? {} : { nextSigner }), ...(newNextSigner === undefined ? {} : { newNextSigner }),
    ...(nextKeyFile === undefined ? {} : { nextKeyFile: resolvePath(nextKeyFile as string) }), ...(r.nextKey === undefined ? {} : { nextKey: r.nextKey as boolean }),
    ...(keyId === undefined ? {} : { keyId }), ...(reason === undefined ? {} : { reason: reason as string }), ...(retireList === undefined ? {} : { retire: Object.freeze(retireList) }),
    ...(r.emergency === true ? { emergency: true } : {}),
    ...(newNextPublicKey === undefined ? {} : { newNextPublicKey }), ...(newNextKeyReference === undefined ? {} : { newNextKeyReference }),
    ...(policy === undefined ? {} : { ownerPolicy: policy }), ...(input.resetPolicy === true ? { resetPolicy: true } : {}),
  });
}
/** The control-authorization challenge of a format-1 control event at `previousHead` (what the owner key and a rotation's revealed keys sign). */
const controlChallenge = (state: ReplayState, event: CanonicalEvent, previousHead: HistoryHead | null): ContentHash => controlAuthorizationHash({
  domain: state.genesis.domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
  previousHead: previousHead === null ? null : { hash: previousHead.hash, position: previousHead.position }, effectHash: controlEffectHash(event, state.hashAlgorithm),
}, state.hashAlgorithm);
/** Caller owner signatures `[{keyId, signature}]` (1..max), captured; their validity is the replay's (A-92.2). */
function authorizationEntries(value: unknown, max: number): readonly ControlAuthorizationEntry[] {
  requireCondition(Array.isArray(value) && value.length <= max);
  return Object.freeze((value as readonly unknown[]).map((entry) => {
    const r = record(entry, ["keyId", "signature"]);
    requireCondition(typeof r.signature === "string" && /^0x[0-9a-f]+$/.test(r.signature));
    return Object.freeze({ keyId: identifier(r.keyId), signature: r.signature as HexSignature });
  }));
}
/**
 * One co-signer's part of a two-phase control event (A-92.4): `signer` signs the prepared `/2` challenge hash. Run it
 * wherever the key is (another process, host or person); pass the entries to `submitControlEvent` or
 * `commitOwnerKeyRotation`. The signer's custody layer sees purpose `control-authorization`.
 */
export async function authorizeControlEvent(signer: Signer, prepared: Readonly<{ challengeHash: ContentHash }>, context: Readonly<{ historyId?: ContentHash }> = {}): Promise<ControlAuthorizationEntry> {
  requireCondition(isSigner(signer) && prepared !== null && typeof prepared === "object" && isContentHash(prepared.challengeHash));
  const signature = await signWith(signer, prepared.challengeHash, { purpose: "control-authorization", ...(context.historyId === undefined ? {} : { historyId: context.historyId }) } as SignContext);
  return Object.freeze({ keyId: signer.keyId, signature });
}
/** A signature by `signer` (synchronously when it can); SIGNER_FAILED / KEY_UNAVAILABLE (`signerFailure`) when it throws. */
async function signWith(signer: Signer, hash: ContentHash, context: SignContext): Promise<HexSignature> {
  try { return signer.signHashSync !== undefined ? signer.signHashSync(hash) : await signer.signHash(hash, context); } catch (error) { throw signerFailure(error); }
}

/**
 * The owner keys in force for the next event of `state`, their next-key commitment, and the key files beside
 * `historyFile` (`LocalOwner#ownerKeyStatus`; the CLI's `owner status`). Reads files, never writes. The warnings name
 * what weakens pre-rotation: no commitment, a next-key file on this host, a stale or uncommitted next-key file.
 */
export function ownerKeyStatusOf(historyFile: string, state: ReplayState): OwnerKeyStatus {
  const keyPath = ownerKeyPathFor(historyFile), nextPath = nextOwnerKeyPathFor(historyFile);
  const pending = [pendingOwnerKeyPathFor(historyFile), pendingNextOwnerKeyPathFor(historyFile)].filter((path) => existsSync(path));
  if (!isTrellis(state.format)) {
    return Object.freeze({ format: state.format, ownerKeys: [], fromPosition: 0, keyRotations: 0, commitmentRotations: 0, policyRotations: 0, ownerPolicy: null, commitment: null, ownerKeyFile: null, nextKeyFile: null, nextKeyOnHost: false, pending: [], warnings: [], custody: [] });
  }
  const next = state.head.position + 1;
  const epoch = state.ownerKeyEpochs.at(-1)!;
  let commitment: OwnerKeyStatus["commitment"] = null;
  if (epoch.nextKeyDigests !== undefined) {
    // The event that fixed it: the genesis, or the rotation that opened the epoch (keys kept: a commitment-only rotation); a
    // policy rotation (A-96) carries the commitment over unchanged, so the search goes back past policy rotations.
    const epochs = state.ownerKeyEpochs;
    let index = epochs.length - 1;
    const carried = (a: OwnerKeyEpoch, b: OwnerKeyEpoch): boolean => keepsEveryOwnerKey(a.keys, b.keys) && a.nextKeyDigests !== undefined &&
      a.nextKeyDigests.length === b.nextKeyDigests!.length && a.nextKeyDigests.every((digest) => b.nextKeyDigests!.includes(digest)) && !sameOwnerPolicy(a.policy, b.policy);
    while (index > 0 && carried(epochs[index - 1]!, epochs[index]!)) index -= 1;
    const position = epochs[index]!.fromPosition === 0 ? 0 : epochs[index]!.fromPosition - 1;
    const previous = position === 0 ? undefined : ownerKeysAt(state, position);
    const source = position === 0 ? "GENESIS" as const : keepsEveryOwnerKey(previous!, epochs[index]!.keys) ? "COMMITMENT" as const : "ROTATION" as const;
    commitment = Object.freeze({ nextKeyDigests: epoch.nextKeyDigests, eventId: state.events[position]!.id, position, source });
  }
  let nextKeyFile: OwnerKeyStatus["nextKeyFile"] = null;
  let nextKey: Signer | undefined;
  if (existsSync(nextPath)) {
    try {
      const key = loadNextOwnerKeyFile(nextPath), digest = ownerKeyDigest(key);
      const fileState: NextKeyFileState = epoch.nextKeyDigests?.includes(digest) === true ? "COMMITTED"
        : ownerKeysAt(state, next).some((k) => sameKeyMaterial(k, key)) ? "IN_FORCE"
        : state.ownerKeyEpochs.some((e) => e.keys.some((k) => sameKeyMaterial(k, key))) ? "RETIRED" : "UNCOMMITTED";
      const holder = key.custody?.holder === "reference" ? "reference" as const : "file" as const;
      nextKeyFile = Object.freeze({ path: nextPath, state: fileState, keyId: key.keyId, digest, holder, ...(key.custody?.signer === undefined ? {} : { signer: key.custody.signer }) });
      nextKey = key;
    } catch {
      nextKeyFile = Object.freeze({ path: nextPath, state: "UNREADABLE" as const });
    }
  }
  let ownerFileKey: Signer | undefined, ownerFileUnreadable = false;
  if (existsSync(keyPath)) { try { ownerFileKey = loadOwnerKeyFile(keyPath); } catch { ownerFileUnreadable = true; } }
  const warnings: OwnerKeyWarning[] = [];
  const warn = (code: string, message: string, path?: string): void => { warnings.push(Object.freeze({ code, message, ...(path === undefined ? {} : { path }) })); };
  if (commitment === null) {
    warn("NO_NEXT_KEY_COMMITMENT", "the owner keys in force have no next-key commitment: whoever holds the current owner key can rotate this history to a key of their choice; commit one (irontrellis owner commit-next-key: a rotation that keeps the owner keys) and keep it offline");
  }
  const sameSigner = nextKeyFile?.state === "COMMITTED" && nextKeyFile.holder === "reference" && ownerFileKey?.custody?.identity !== undefined &&
    nextKey?.custody?.identity === ownerFileKey.custody.identity;
  if (nextKeyFile !== null) {
    if (nextKeyFile.state === "COMMITTED" && nextKeyFile.holder === "reference") {
      if (sameSigner) warn("NEXT_KEY_SAME_SIGNER", `the committed next key is held by the same signer as the current owner key (${nextKey!.custody!.description}): whoever can use that signer can rotate this history; keep the next key in another signer (another agent socket, a hardware key kept offline) — pre-rotation only protects you if the next key cannot be used where the current key can`, nextPath);
    } else if (nextKeyFile.state === "COMMITTED") warn("NEXT_KEY_ON_HOST", `the next key ${nextPath} sits beside the current owner key: ${NEXT_KEY_ON_HOST_WARNING}`, nextPath);
    else if (nextKeyFile.state === "IN_FORCE") warn("NEXT_KEY_STALE", `${nextPath} holds an owner key already in force (a stale copy left by a rotation): remove it`, nextPath);
    else if (nextKeyFile.state === "RETIRED") warn("NEXT_KEY_RETIRED", `${nextPath} holds a retired owner key: it can never rotate this history; archive it offline with the retired keys`, nextPath);
    else if (nextKeyFile.state === "UNCOMMITTED") warn("NEXT_KEY_UNCOMMITTED", `${nextPath} holds a key the owner keys in force did not commit to: it cannot rotate this history`, nextPath);
    else warn("NEXT_KEY_UNREADABLE", `${nextPath} cannot be read as a next-key file`, nextPath);
  }
  if (epoch.policy?.recovery !== undefined) warn("OWNER_POLICY_RECOVERY_NO_WRITER", OWNER_POLICY_RECOVERY_NO_WRITER.slice("OWNER_POLICY_RECOVERY_NO_WRITER: ".length));
  for (const path of pending) warn("KEY_FILE_PENDING", `pending key file ${path}: an interrupted rotation or commitment; the next open or owner write completes it or removes it`, path);
  const custody = custodyOf(historyFile, state, { keyPath, ownerFileKey, ownerFileUnreadable, nextPath, nextKeyFile, nextKey, sameSigner, commitment: epoch.nextKeyDigests });
  return Object.freeze({
    format: state.format, ownerKeys: ownerKeysAt(state, next), fromPosition: epoch.fromPosition,
    ...ownerKeyRotationCounts(state), ownerPolicy: epoch.policy ?? null, commitment,
    ownerKeyFile: existsSync(keyPath) ? keyPath : null, nextKeyFile, nextKeyOnHost: nextKeyFile?.state === "COMMITTED" && nextKeyFile.holder !== "reference", pending: Object.freeze(pending),
    warnings: Object.freeze(warnings), custody,
  });
}

/** `OwnerKeyStatus.custody`: one entry per owner key in force, for the next key, and per archived retired key. Files only. */
function custodyOf(historyFile: string, state: ReplayState, seen: Readonly<{
  keyPath: string; ownerFileKey: Signer | undefined; ownerFileUnreadable: boolean; nextPath: string; nextKeyFile: OwnerKeyStatus["nextKeyFile"]; nextKey: Signer | undefined;
  sameSigner: boolean; commitment: readonly ContentHash[] | undefined;
}>): readonly KeyCustody[] {
  const out: KeyCustody[] = [];
  const add = (entry: KeyCustody): void => { out.push(Object.freeze(entry)); };
  const next = state.head.position + 1;
  for (const key of ownerKeysAt(state, next)) {
    const file = seen.ownerFileKey !== undefined && sameKeyMaterial(seen.ownerFileKey, key) ? seen.ownerFileKey : undefined;
    if (file?.custody?.holder === "reference") {
      add({ role: "current", keyId: key.keyId, holder: "reference", signer: file.custody.signer ?? "unknown", description: file.custody.description, path: seen.keyPath, level: "OK", code: "OWNER_KEY_REFERENCE",
        message: `held by ${file.custody.description}; ${seen.keyPath} holds only a reference (no secret)` });
    } else if (file !== undefined) {
      add({ role: "current", keyId: key.keyId, holder: "file", description: `key file ${seen.keyPath}`, path: seen.keyPath, level: "WARN", code: "OWNER_KEY_FILE_ON_HOST",
        message: `the private key is in ${seen.keyPath} on this host: any process that can read it (the agent too, when it runs as this OS user) can sign as the owner; keep it in an ssh-agent, a KMS or another OS user's files (docs/CUSTODY.md)` });
    } else {
      add({ role: "current", keyId: key.keyId, holder: seen.ownerFileUnreadable ? "unreadable" : "elsewhere", level: seen.ownerFileUnreadable ? "WARN" : "OK",
        code: seen.ownerFileUnreadable ? "KEY_FILE_UNREADABLE" : "OWNER_KEY_ELSEWHERE",
        message: seen.ownerFileUnreadable ? `${seen.keyPath} cannot be read as an owner key file` : "no key file here holds this key (a programmatic signer, or another host)" });
    }
  }
  const nf = seen.nextKeyFile;
  if (seen.commitment === undefined) {
    add({ role: "next", holder: "none", level: "WARN", code: "NO_NEXT_KEY_COMMITMENT", message: "no next-key commitment: whoever holds the current owner key can rotate this history (irontrellis owner commit-next-key)" });
  } else if (nf?.state === "COMMITTED" && nf.holder === "reference") {
    add({ role: "next", keyId: nf.keyId!, holder: "reference", signer: nf.signer!, description: seen.nextKey!.custody!.description, path: seen.nextPath,
      level: seen.sameSigner ? "WARN" : "OK", code: seen.sameSigner ? "NEXT_KEY_SAME_SIGNER" : "NEXT_KEY_REFERENCE",
      message: seen.sameSigner ? `held by the same signer as the current owner key (${seen.nextKey!.custody!.description})` : `held by ${seen.nextKey!.custody!.description}; ${seen.nextPath} holds only a reference` });
  } else if (nf?.state === "COMMITTED") {
    add({ role: "next", keyId: nf.keyId!, holder: "file", description: `key file ${seen.nextPath}`, path: seen.nextPath, level: "WARN", code: "NEXT_KEY_ON_HOST", message: `the private next key is in ${seen.nextPath}: ${NEXT_KEY_ON_HOST_WARNING}` });
  } else {
    add({ role: "next", holder: "public-key-only", level: "OK", code: "NEXT_KEY_OFF_HOST", message: `only the commitment (${seen.commitment.join(", ")}) is here; bring the next key's reference or key file for the rotation that reveals it` });
  }
  for (const path of retiredOwnerKeyFilesFor(historyFile)) {
    let key: Signer;
    try { key = loadOwnerKeyFile(path); } catch { continue; }
    if (!state.ownerKeyEpochs.some((epoch) => epoch.keys.some((k) => k.keyId === key.keyId && sameKeyMaterial(k, key))) || ownerKeyInForce(state, next, key)) continue;
    if (key.custody?.holder === "reference") {
      add({ role: "retired", keyId: key.keyId, holder: "reference", signer: key.custody.signer ?? "unknown", description: key.custody.description, path, level: "OK", code: "RETIRED_KEY_REFERENCE",
        message: `retired; ${path} is a reference to ${key.custody.description} (it signs rotation-head statements for witnesses that lack the rotation)` });
    } else {
      add({ role: "retired", keyId: key.keyId, holder: "file", path, level: "WARN", code: "RETIRED_KEY_FILE",
        message: `the retired private key is in ${path}: it can still sign a copy cut back before its rotation; move it offline once every bound witness recorded the rotation` });
    }
  }
  return Object.freeze(out);
}

// ---------------------------------------------------------------- the handle

/** `requireOnOpen` gate still closed: the profile is checked on the first read after `checkWitnesses()`. */
const awaitingWitnessCheck = (error: unknown): boolean =>
  error instanceof IronTrellisError && error.code === "WITNESS_UNAVAILABLE" && (error.detail as { reason?: unknown } | undefined)?.reason === "NOT_CHECKED";

/** A remote witness's finding against this copy (what `witnessRecovery` opens despite). */
const witnessFinding = (error: unknown): boolean => {
  if (!(error instanceof IronTrellisError)) return false;
  const reason = (error.detail as { reason?: unknown } | undefined)?.reason;
  return error.code === "WITNESS_SPLIT_VIEW" || (error.code === "ROLLBACK_DETECTED" && (reason === "WITNESS_AHEAD" || reason === "WITNESS_FORK"));
};
const isPrefixOf = (head: Readonly<{ hash: string; position: number }>, state: ReplayState): boolean =>
  head.position <= state.head.position && state.eventHistoryHashes[head.position] === head.hash;

function attach(store: HistoryStore, config: Config): LocalOwner {
  const current = (): ReplayState => currentState(store, config);
  try { current(); } catch (error) { if (!awaitingWitnessCheck(error) && !(config.witnessRecovery === true && witnessFinding(error))) throw error; }
  /**
   * A key-file signer retired by a rotation another handle recorded is replaced
   * by the key file's current key (completing a crashed rotation first), so a
   * long-lived handle keeps signing with the key in force. Caller signers
   * (`options.signer`) are never replaced.
   */
  const refreshSigner = (state: ReplayState): void => {
    if (!isTrellis(state.format) || config.signerSource !== "key-file" || config.signer === undefined) return;
    const next = state.head.position + 1;
    if (ownerKeyInForce(state, next, config.signer)) return;
    settleOwnerKeyFilesLocked(store, config.historyFile);
    let loaded: Signer;
    try { loaded = loadOwnerKeyFile(ownerKeyPathFor(config.historyFile)); } catch { return; }
    if (!ownerKeyInForce(state, next, loaded)) return; // the write then fails with CONTROL_AUTHORIZATION_INVALID
    config = Object.freeze({ ...config, signer: loaded });
    store.setSigner(loaded);
  };
  /**
   * The remote-witness check before an owner write (witnessBeforeWrite). Writes whose event data is built from the
   * current state call it BEFORE reading that state: under `requireOnOpen` the first read of a fresh process is gated
   * (NOT_CHECKED) until the witnesses were asked, and this check is what asks them. `undefined` when there is nothing to
   * wait for, and then it is not awaited: a write without remote witnesses stays synchronous up to the store lock.
   */
  const witnessChecked = (): Promise<void> | undefined => {
    // Key files staged by a prepared-rotation record the check completes or discards (docs/reference/witness-operations.md §7.1) are settled
    // before the write: moved into place when the rotation is recorded, removed when it was discarded. Only then: files a
    // caller staged with prepareOwnerKeyRotation (no record) stay until its commitOwnerKeyRotation, as before.
    const hadRecord = existsSync(pendingRotationPathFor(config.historyFile));
    const checked = witnessBeforeWrite(store);
    const staged = existsSync(pendingOwnerKeyPathFor(config.historyFile)) || existsSync(pendingNextOwnerKeyPathFor(config.historyFile));
    if (!hadRecord || !staged) return checked;
    return (checked ?? Promise.resolve()).then(() => {
      if (config.signerSource === "option") settleNextKeyFilesLocked(store, config.historyFile);
      else settleOwnerKeyFilesLocked(store, config.historyFile);
    });
  };
  const writeOwned = async (type: EventType, data: Readonly<Record<string, unknown>>, id?: string): Promise<WriteResult> => {
    { const checked = witnessChecked(); if (checked !== undefined) await checked; }
    const state = current(), head = state.head;
    refreshSigner(state);
    // The clock is read after the head is taken: a competing append during the clock call surfaces as HISTORY_CONFLICT, never a stale write.
    // Format 2 (SPEC §3.3): every Amount of an owner-written event is a decimal string on the wire (a grant's caps, a budget's amounts).
    // A-22.3: a power-reducing control event is never refused for a clock behind the head: it is written at
    // `max(now, head.canonicalTime)` and the result reports CLOCK_BEHIND_HEAD with the skew. Other writes keep the format-1 engine's CLOCK_INVALID.
    const now = config.now();
    const behind = state.format === TRELLIS2_FORMAT && POWER_REDUCING_TYPES.has(type) && now < head.canonicalTime;
    const event = newEvent(config, type, behind ? head.canonicalTime : now, state.format === TRELLIS2_FORMAT ? wireAmounts(data) : data);
    const result = await appendEvent(store, config, state, id === undefined ? event : Object.freeze({ ...event, id }), head);
    return behind ? Object.freeze({ ...result, clock: Object.freeze({ code: "CLOCK_BEHIND_HEAD" as const, skewMs: head.canonicalTime - now }) }) : result;
  };
  /** An owner write, followed by the automatic checkpoint the genesis policy asks for (SPEC §7.3, format 2). */
  const write = async (type: EventType, data: Readonly<Record<string, unknown>>): Promise<WriteResult> => {
    const result = await writeOwned(type, data);
    // A-46.2 / A-66.2: a failed or suppressed automatic checkpoint never obscures the committed write; it is reported on it.
    const suppressed = await autoCheckpoint();
    return suppressed === undefined ? result : Object.freeze({ ...result, checkpoint: suppressed });
  };
  // ---------------------------------------------------------------- format 2: checkpoints, budgets, counterparties (SPEC §7.3, §9.1, §11.1)
  const requireFormat2 = (what: string): void => {
    assertWritable(store);
    if (store.format !== TRELLIS2_FORMAT) throw new IronTrellisError("INVALID_INPUT", false, `${what} needs a format-2 history; this file is ${store.format ?? "empty"} (migrate it)`);
  };
  /** The `STATE_CHECKPOINT` data committing to `state` (the state before the checkpoint event), after the root self-check. */
  const checkpointData = (state: ReplayState, checkpointId: string): Readonly<Record<string, unknown>> => {
    const kept = rootAt(state, state.head.position), recomputed = stateRootOfRecords(stateRecordsOf(state));
    if (kept === undefined || kept !== recomputed.root || recomputed.count !== state.stateRecords.size) {
      throw new IronTrellisError("CHECKPOINT_MISMATCH", false, `the state root recomputed from the ${recomputed.count} records (${recomputed.root}) differs from the engine's own (${kept}); not writing a checkpoint`, { kept, recomputed: recomputed.root });
    }
    return Object.freeze({
      checkpointId, head: { hash: state.head.hash, position: state.head.position }, stateRoot: kept, recordCount: recomputed.count, derivationVersion: STATE_DERIVATION_VERSION,
      projectionHead: projectionHeadAt(state, state.head.position) ?? null,
    });
  };
  const writeCheckpoint = async (checkpointId: string | undefined, id?: string): Promise<CheckpointResult> => {
    { const checked = witnessChecked(); if (checked !== undefined) await checked; }
    const state = current(), head = state.head;
    refreshSigner(state);
    const data = checkpointData(state, checkpointId ?? `checkpoint:${head.position + 1}`);
    const event = newEvent(config, "STATE_CHECKPOINT", config.now(), data);
    const result = await appendEvent(store, config, state, id === undefined ? event : Object.freeze({ ...event, id }), head);
    return Object.freeze({ ...result, stateRoot: data.stateRoot as ContentHash, recordCount: data.recordCount as U53, projectionHead: data.projectionHead as ContentHash | null });
  };
  /**
   * SPEC §7.3 `checkpointPolicy.everyEvents`: a checkpoint once that many events were accepted since the last one (or
   * since the genesis). Checked after every owner write of this handle (events other handles appended count too).
   */
  // A-66.1: the counter is derived from the accepted history (non-checkpoint events since the latest accepted checkpoint,
  // manual, automatic or the handover seal), so a reopen recomputes it and a failed attempt never resets it; one attempt
  // per qualifying append; an automatic checkpoint never triggers another (it is not counted). Opening never appends.
  let reserveReported = false;
  const autoCheckpoint = async (): Promise<CheckpointSuppression | undefined> => {
    if (store.format !== TRELLIS2_FORMAT) return undefined;
    const state = current();
    const every = state.genesis.checkpointPolicy?.everyEvents ?? null;
    if (every === null) return undefined;
    for (let position = state.head.position; position > state.head.position - every && position >= 0; position -= 1) {
      if (state.events[position]!.type === "STATE_CHECKPOINT") return undefined;
    }
    // A-46.2 (G2): suppressed when a one-record non-control event would be refusable under A-3 step 2 after the trigger
    // (R(p) + 1 > T_R or B(p) ≥ T_B; this covers capacity() RESERVED and FULL); reported once per open.
    if (state.stateRecords.size + 1 > RESERVE_THRESHOLD_RECORDS || state.canonicalBytes >= RESERVE_THRESHOLD_BYTES) {
      if (reserveReported) return undefined;
      reserveReported = true;
      return Object.freeze({ code: "CHECKPOINT_SUPPRESSED" as const, reason: "RESERVE" as const });
    }
    try {
      await writeCheckpoint(undefined);
      return undefined;
    } catch (error) {
      const code = error instanceof IronTrellisError || error instanceof EngineError ? error.code : undefined;
      const reason = noSignerRefusal(error) ? "NO_SIGNER" as const : code === "SIGNER_FAILED" ? "SIGNER_FAILED" as const : "STORE_FAILED" as const;
      return Object.freeze({ code: "CHECKPOINT_SUPPRESSED" as const, reason, message: error instanceof Error ? error.message : String(error) });
    }
  };
  /** A format-2 control effect from caller data: captured (no behaviour), Amounts normalized to strings, checked against the closed schema before any signature. */
  const controlData = (type: EventType, input: unknown, what: string): Readonly<Record<string, unknown>> => {
    const captured = captureData(input, 1024 * 1024, 4096, 16);
    requireCondition(captured !== null && typeof captured === "object" && !Array.isArray(captured));
    const data = wireAmounts(captured as Readonly<Record<string, unknown>>);
    const validation = validateEvent({ id: "event:probe", type, timestamp: 0, data }, TRELLIS2_FORMAT, 1);
    if (!validation.ok) throw new IronTrellisError("INVALID_INPUT", false, `${what}: ${validation.reason}`, { code: validation.code });
    return validation.event.data;
  };
  /** An owner-signed witness binding (`WITNESSES_BOUND` / `WITNESSES_UNBOUND`, see witness-session.ts `witnessBindingEvent`), with the policy minimum it signs. */
  const bind = async (action: WitnessBindingAction, witnesses: readonly BindingWitness[], policy: BoundPolicy, acceptedLoss?: AcceptedLossRecord): Promise<WriteResult> => {
    const event = witnessBindingEvent({ action, witnesses, policy, ...(acceptedLoss === undefined ? {} : { acceptedLoss }) });
    return write(event.type, event.data);
  };
  /**
   * The policy minimum an unbinding of `removed` signs: the history's bound policy (its quorum capped at the witnesses
   * that stay bound). Never taken from the side file: an attacker could have edited it.
   */
  const policyAfterUnbinding = (state: ReplayState, removed: readonly string[]): BoundPolicy => {
    const remaining = boundWitnessesOf(state).filter((b) => !removed.includes(b.verifierKey)).length;
    return bindingPolicyOf(boundPolicyOf(state), remaining);
  };
  /** The owner signer, only when it holds a key in force for the next event (KEY_UNAVAILABLE otherwise); nothing is written. */
  const requireOwnerKey = (state: ReplayState, what: string): Signer => {
    let signer: Signer | undefined;
    try { signer = ownerSigner(config); } catch { signer = undefined; }
    if (signer === undefined || !ownerKeyInForce(state, state.head.position + 1, signer)) {
      throw new IronTrellisError("KEY_UNAVAILABLE", false, `${what} needs the owner key in force (${ownerKeysAt(state, state.head.position + 1).map((key) => key.keyId).join(", ")}); this handle does not hold it`);
    }
    return signer;
  };
  /** After a binding: submit the current head now; rollback evidence throws, anything else is reported. */
  const settleWitnessChange = async (witness: StoredWitnessConfig, bound: boolean, eventId: string | undefined): Promise<WitnessChange> => {
    let error: { code: string; message: string } | undefined;
    try { await store.flush(); } catch (failure) {
      if (failure instanceof EngineError && (failure.code === "ROLLBACK_DETECTED" || failure.code === "WITNESS_SPLIT_VIEW")) translate(failure, "READ_UNAVAILABLE");
      error = { code: failure instanceof EngineError || failure instanceof IronTrellisError ? failure.code : "WITNESS_UNAVAILABLE", message: failure instanceof Error ? failure.message : String(failure) };
    }
    return Object.freeze({ witness, bound, ...(eventId === undefined ? {} : { eventId }), status: store.witnessStatus(), submitted: error === undefined, ...(error === undefined ? {} : { error: Object.freeze(error) }) });
  };
  const observe = (options: ObservationOptions = {}): Observation => {
    const o = record(options, [], ["at", "expectHead"]) as ObservationOptions;
    const state = current();
    // The host clock is the default evaluation time (docs/API.md §1), read only when the caller gives no `at`.
    return Object.hasOwn(o, "at") ? observeState(state, o) : observeState(state, o, config.now());
  };
  // ---------------------------------------------------------------- A-92.4 two-phase control events (prepare, collect signatures, submit)

  /** The prepared control event at the current head; nothing is signed (`data` is already checked against the closed schema). */
  const prepareControl = async (type: EventType, data: Readonly<Record<string, unknown>>): Promise<PreparedControlEvent> => {
    { const checked = witnessChecked(); if (checked !== undefined) await checked; }
    const state = current(), head = state.head, next = head.position + 1;
    // A-22.3: a power-reducing type is fixed at max(now, head time); every other type keeps CLOCK_INVALID.
    const now = config.now(), timestamp = POWER_REDUCING_TYPES.has(type) ? Math.max(now, head.canonicalTime) : now;
    requireCondition(timestamp >= head.canonicalTime, "CLOCK_INVALID");
    const event = newEvent(config, type, timestamp, data);
    try { assertCapacityTransition(state, [event]); } catch (error) { translate(error, "TRANSITION_REJECTED"); }
    const rule = controlRuleAt(state, event, next);
    const challenge = controlAuthorizationChallenge({
      domain: state.genesis.domain, eventId: event.id, eventType: type, timestamp, previousHead: { hash: head.hash, position: head.position },
      effectHash: controlEffectHash(event, state.hashAlgorithm),
    });
    return Object.freeze({ event, previousHead: head, challenge, challengeHash: controlChallenge(state, event, head), required: rule.required, signers: eligibleSigners(event, rule), ...recoveryWarningOf(event) });
  };
  /** The data of a policy rotation (A-96): every owner key and the commitment in force kept, the policy changed. */
  const policyRotationData = (state: ReplayState, input: OwnerPolicyRotation): Readonly<Record<string, unknown>> => {
    const r = record(input, [], ["ownerPolicy", "resetPolicy", "reason"]);
    requireCondition(r.resetPolicy === undefined || typeof r.resetPolicy === "boolean");
    const reason = r.reason ?? "owner policy rotation";
    requireCondition(typeof reason === "string" && reason.length > 0 && utf8Bytes(reason) <= 256 && !/[\u0000-\u001f\u007f]/.test(reason));
    if ((r.ownerPolicy === undefined) === (r.resetPolicy !== true)) throw new IronTrellisError("INVALID_INPUT", false, "pass the new ownerPolicy, or resetPolicy: true to return to the default {threshold: 1}");
    const next = state.head.position + 1, epoch = state.ownerKeyEpochs.at(-1)!, keys = ownerKeysAt(state, next);
    const policy = r.ownerPolicy === undefined ? undefined : capturedOwnerPolicy(r.ownerPolicy, "ownerPolicy");
    if (sameOwnerPolicy(policy, epoch.policy)) throw new IronTrellisError("INVALID_INPUT", false, "that is already the owner approval policy in force, as written; a rotation that changes nothing is refused");
    if (policy !== undefined) {
      const invalid = ownerPolicyFailure(policy, keys);
      if (invalid !== undefined) throw new IronTrellisError("INVALID_INPUT", false, invalid, { code: "EVENT_DATA_INVALID" });
    }
    return Object.freeze({
      ownerKeys: keys, reason, ...(epoch.nextKeyDigests === undefined ? {} : { nextKeyDigests: epoch.nextKeyDigests }), ...(policy === undefined ? {} : { ownerPolicy: policy }),
    });
  };
  /** A-92.4 submit: the prepared event with its signatures, checked under the writer's view of the head (HISTORY_CONFLICT, then A-92.2), then appended. */
  const submitControl = async (prepared: PreparedControlEvent, authorizations: readonly ControlAuthorizationEntry[]): Promise<WriteResult> => {
    requireCondition(prepared !== null && typeof prepared === "object" && prepared.event !== null && typeof prepared.event === "object" && prepared.previousHead !== null && typeof prepared.previousHead === "object");
    const entries = authorizationEntries(authorizations, 64);
    requireCondition(entries.length >= 1);
    const type = prepared.event.type;
    requireCondition(CONTROL_EVENT_TYPES.has(type));
    const [first, ...rest] = entries;
    const event: CanonicalEvent = Object.freeze({
      id: prepared.event.id, type, timestamp: prepared.event.timestamp,
      data: Object.freeze({ ...controlEffect(prepared.event.data), controlAuthorization: first!, ...(rest.length === 0 ? {} : { [ADDITIONAL_CONTROL_AUTHORIZATIONS]: Object.freeze(rest) }) }),
    });
    { const checked = witnessChecked(); if (checked !== undefined) await checked; }
    const state = current(), head = state.head, next = head.position + 1;
    if (!sameHead(head, prepared.previousHead)) {
      throw new IronTrellisError("HISTORY_CONFLICT", false, `the history moved since the event was prepared (prepared at ${prepared.previousHead.position}, now at ${head.position}); prepare it again and collect fresh signatures`, { prepared: prepared.previousHead, head });
    }
    const rule = controlRuleAt(state, event, next), required = rule.required;
    const failure = controlSignatureFailure(event, rule);
    const quorum = failure === undefined ? controlQuorumFailure(event, rule) : undefined;
    if (failure !== undefined || quorum !== undefined) {
      const { signers } = controlQuorum(event, rule);
      throw new IronTrellisError("CONTROL_AUTHORIZATION_INVALID", false, failure ?? quorum!.reason, { required, present: quorum?.present ?? signers.filter((signer) => signer.counts).length });
    }
    // A-119.4 writer pre-check: rule T2 (A-172.2: TRANSITION_REJECTED {reason: ATTESTATION_HORIZON, horizon}).
    const time = singleSignerTimeFailure(state, event, next, rule);
    if (time !== undefined) throw horizonRefusal(time);
    const result = await appendEvent(store, config, state, event, head, true);
    const suppressed = await autoCheckpoint();
    const warned = recoveryWarningOf(event);
    return suppressed === undefined && warned.warning === undefined ? result : Object.freeze({ ...result, ...(suppressed === undefined ? {} : { checkpoint: suppressed }), ...warned });
  };

  // ---------------------------------------------------------------- owner key rotation (prepare, commit) and next-key commitments

  /** What the handle keeps about a prepared rotation (never exposed: the prepared record is what the caller sees). */
  type RotationInternals = Readonly<{ incoming: Signer; oldSigner: Signer; fileKey: Signer | undefined; nextNext: Signer | undefined; consumedNextFile: string | undefined; commitOnly: boolean }>;
  const rotationInternals = new WeakMap<PreparedOwnerKeyRotation, RotationInternals>();
  /**
   * A prepared rotation with its co-signatures (A-92.4), under the writer lock: HISTORY_CONFLICT if the history moved, the
   * A-92.2 pre-check (CONTROL_AUTHORIZATION_INVALID `{required, present}`), and the head recomputed with the co-signatures
   * (they are part of the event). Without co-signatures the prepared rotation is returned as it is (after the same checks).
   */
  const cosignRotation = (prepared: PreparedOwnerKeyRotation, additional: readonly ControlAuthorizationEntry[]): PreparedOwnerKeyRotation => {
    const state = current(), head = state.head, next = head.position + 1;
    // A moved history: the append at `previousHead` fails with HISTORY_CONFLICT and settles the staged files (commitRotation).
    if (!sameHead(head, prepared.previousHead)) return prepared;
    if (!isFormat2(state.format)) { requireCondition(additional.length === 0); return prepared; }
    const event: CanonicalEvent = additional.length === 0 ? prepared.event
      : Object.freeze({ ...prepared.event, data: Object.freeze({ ...prepared.event.data, [ADDITIONAL_CONTROL_AUTHORIZATIONS]: Object.freeze(additional.slice()) }) });
    const quorum = controlQuorumFailure(event, controlRuleAt(state, event, next));
    if (quorum !== undefined) throw new IronTrellisError("CONTROL_AUTHORIZATION_INVALID", false, quorum.reason, { required: quorum.required, present: quorum.present });
    if (additional.length === 0) return prepared;
    const prospective = withProspectiveEvent(state, event);
    if (!prospective.ok) throw prospectiveRefusal(state, event, next, prospective);
    const cosigned: PreparedOwnerKeyRotation = Object.freeze({ ...prepared, event, head: prospective.head, fromPosition: prospective.head.position + 1 });
    rotationInternals.set(cosigned, rotationInternals.get(prepared)!);
    rotationInternals.delete(prepared);
    return cosigned;
  };
  /** Runs `body` under the writer lock; engine failures are translated (an IronTrellisError passes through). */
  const lockedRotation = async <T>(body: (writer: Readonly<{ appendAtExpectedHead(event: CanonicalEvent, expected: HistoryHead): HistoryHead }>) => Promise<T>): Promise<T> => {
    try {
      return await whenWriterFree(store, () => store.withExclusiveWriter((writer) => body(writer)));
    } catch (error) {
      if (error instanceof IronTrellisError || error instanceof RotationFault) throw error;
      translate(error, "WRITE_UNCONFIRMED");
    }
  };
  /** The rotation goes to every witness now, whatever the mode (docs/WITNESS.md §7); an unreachable witness keeps it first in the queue. */
  const afterRotation = async (): Promise<void> => {
    const session = witnessSessionOf(store);
    let after: Promise<void> | undefined;
    try { after = session?.active === true ? session.afterRotation() : undefined; } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    if (after !== undefined) await after.catch((error: unknown) => translate(error, "READ_UNAVAILABLE"));
  };
  /**
   * Builds, signs and checks a rotation under the writer lock (the caller holds it), staging the key files it needs as
   * pending files; nothing is appended. On any failure the files it staged are removed again.
   */
  const prepareRotation = async (options: RotationOptions, cosigned = false): Promise<PreparedOwnerKeyRotation> => {
    const historyFile = config.historyFile, keyPath = ownerKeyPathFor(historyFile), pendingPath = pendingOwnerKeyPathFor(historyFile);
    const nextPath = nextOwnerKeyPathFor(historyFile), pendingNextPath = pendingNextOwnerKeyPathFor(historyFile);
    let state = current();
    // A rotation or commitment that crashed before its file swap is completed (or its orphans removed) first; a pending file still in the way is refused below.
    settleKeyFiles(historyFile, state);
    refreshSigner(state);
    state = current();
    const head = state.head, next = head.position + 1;
    const signer = ownerSigner(config);
    if (!ownerKeyInForce(state, next, signer)) {
      throw new IronTrellisError("KEY_UNAVAILABLE", false, `the owner signer's key ${signer.keyId} is not an owner key in force at position ${next}; only a current owner key can rotate the owner keys`, { keyId: signer.keyId });
    }
    const currentKeys = ownerKeysAt(state, next);
    const commitOnly = options.commitOnly === true;
    // Format 2 (A-91, A-96.4): the policy the rotation sets. A key rotation without `ownerPolicy` returns to the default, which
    // the writer refuses for a non-default policy unless `resetPolicy`; a next-key commitment restates the policy in force.
    const inForce = ownerPolicyAt(state, next);
    if ((options.ownerPolicy !== undefined || options.resetPolicy === true) && !isFormat2(state.format)) throw new IronTrellisError("INVALID_INPUT", false, "ownerPolicy and resetPolicy need a format-2 history (A-91)");
    if (options.ownerPolicy === undefined && options.resetPolicy !== true && !commitOnly && !isDefaultOwnerPolicy(inForce)) {
      throw new IronTrellisError("INVALID_INPUT", false, "the owner keys in force have an owner approval policy, and a rotation without ownerPolicy would return it to the default {threshold: 1}: restate the policy (ownerPolicy) or pass resetPolicy: true (A-96.4)", { reason: "POLICY_RESET", ownerPolicy: inForce });
    }
    const resulting = options.ownerPolicy ?? (commitOnly && options.resetPolicy !== true ? inForce : undefined);
    if (!cosigned) assertSingleSigner(state, "OWNER_KEYS_ROTATED", signer);
    const retired = commitOnly ? [] : options.retire ?? currentKeys.map((key) => key.keyId);
    for (const keyId of retired) {
      if (!currentKeys.some((key) => key.keyId === keyId)) throw new IronTrellisError("INVALID_INPUT", false, `cannot retire ${keyId}: it is not an owner key in force (current keys: ${currentKeys.map((key) => key.keyId).join(", ")})`);
    }
    const seen = new Set(state.ownerKeyEpochs.flatMap((epoch) => epoch.keys.map((key) => key.keyId)));
    const commitment = state.ownerKeyEpochs.at(-1)!.nextKeyDigests;
    if (commitOnly && commitment !== undefined) {
      throw new IronTrellisError("TRANSITION_REJECTED", false,
        `the owner keys in force (since position ${state.ownerKeyEpochs.at(-1)!.fromPosition}) already have a next-key commitment; it cannot be replaced: only a rotation to the committed key starts a new one`, { nextKeyDigests: commitment });
    }
    if (commitment === undefined && (options.nextSigner !== undefined || options.nextKeyFile !== undefined)) {
      throw new IronTrellisError("INVALID_INPUT", false, "the owner keys in force have no next-key commitment to satisfy; rotate without nextKeyFile / nextSigner (a new key is generated, or pass newSigner)");
    }
    if (commitment !== undefined && options.newSigner !== undefined) {
      throw new IronTrellisError("INVALID_INPUT", false, "the owner keys in force committed to a next key (pre-rotation): the new owner key must be that key; pass nextKeyFile or nextSigner instead of newSigner");
    }
    if (commitment !== undefined && options.nextKey === false) {
      throw new IronTrellisError("INVALID_INPUT", false, "a rotation out of owner keys that committed to a next key must commit to the next key of the new set; nextKey: false is refused");
    }
    // Pre-rotation: the committed key the rotation reveals, from its next-key file or a signer.
    let revealed: Signer | undefined, source: string | undefined;
    if (commitment !== undefined) {
      if (options.nextSigner !== undefined) revealed = options.nextSigner;
      else {
        source = options.nextKeyFile ?? (existsSync(nextPath) ? nextPath : undefined);
        if (source === undefined) {
          throw new IronTrellisError("KEY_UNAVAILABLE", false,
            `the owner keys in force committed to a next key (pre-rotation) and only that key can replace them: bring its next-key file back (irontrellis owner rotate-key --next-key <file>, or nextKeyFile) or pass nextSigner; the current key alone cannot rotate`,
            { nextKeyFile: nextPath, nextKeyDigests: commitment });
        }
        try { revealed = loadNextOwnerKeyFile(source); } catch (error) {
          if (error instanceof EngineError) throw new IronTrellisError("KEY_UNAVAILABLE", false, error.message, { ...(error.detail as object | undefined), nextKeyFile: source });
          throw error;
        }
      }
      const digest = ownerKeyDigest(revealed);
      if (!commitment.includes(digest)) {
        throw new IronTrellisError("KEY_UNAVAILABLE", false,
          `${source ?? `nextSigner ${revealed.keyId}`} does not hold the next key the owner keys in force committed to (its digest ${digest} is not among ${commitment.join(", ")})`,
          { nextKeyDigests: commitment, digest, ...(source === undefined ? {} : { nextKeyFile: source }) });
      }
    }
    // A commitment-only rotation adds no key: the owner signer stands in as the "incoming" key (nothing is staged for it).
    const fixedSigner = commitOnly ? signer : options.newSigner ?? options.nextSigner;
    const proposed = revealed !== undefined && fixedSigner === undefined && !seen.has(revealed.keyId) && /^[^\u0000-\u001f\u007f]{1,128}$/.test(revealed.keyId) ? revealed.keyId : undefined;
    const keyId = fixedSigner?.keyId ?? options.keyId ?? proposed ?? nextOwnerKeyId(state);
    if (!commitOnly && seen.has(keyId)) throw new IronTrellisError("INVALID_INPUT", false, `key id ${keyId} was already used by this history; a key id is never reused`, { keyId });
    // A key file (generated, or the promoted next key) replaces `<history>.owner-key.json` unless the new key is a caller's signer.
    const replacesKeyFile = fixedSigner === undefined;
    let fileKey: Signer | undefined;
    if (existsSync(keyPath)) { try { fileKey = loadOwnerKeyFile(keyPath); } catch { fileKey = undefined; } }
    const fileKeyStays = fileKey !== undefined && ownerKeyInForce(state, next, fileKey) && !retired.includes(fileKey.keyId);
    if (replacesKeyFile && fileKeyStays) {
      throw new IronTrellisError("INVALID_INPUT", false, `the owner key file holds ${fileKey!.keyId}, which this rotation keeps in force; retire it too, or pass ${commitment === undefined ? "newSigner" : "nextSigner"} to add a key without replacing the key file`, { keyPath });
    }
    if (replacesKeyFile && existsSync(pendingPath)) {
      throw new IronTrellisError("KEY_EXISTS", false, `a pending owner key file is in the way: ${pendingPath} (left by an earlier rotation that cannot be matched to this history); move it aside, then rotate again`, { keyPath: pendingPath });
    }
    const wantsNext = options.nextKey !== false;
    const stagesNext = wantsNext && options.newNextSigner === undefined && options.newNextPublicKey === undefined;
    if (stagesNext && existsSync(pendingNextPath)) {
      throw new IronTrellisError("KEY_EXISTS", false, `a pending next-key file is in the way: ${pendingNextPath} (left by an earlier rotation or commitment that cannot be matched to this history); move it aside, then rotate again`, { keyPath: pendingNextPath });
    }
    // The fresh next key will replace `<history>.owner-next-key.json`: only a file holding the key this rotation reveals, or a
    // copy of a key the history declared, may be there; anything else (unreadable, or a key the history never declared) is refused.
    if (stagesNext && existsSync(nextPath) && source !== nextPath) {
      let there: Signer | undefined;
      try { there = loadNextOwnerKeyFile(nextPath); } catch { there = undefined; }
      const declaredCopy = there !== undefined && state.ownerKeyEpochs.some((epoch) => epoch.keys.some((key) => sameKeyMaterial(key, there!)));
      const revealedCopy = there !== undefined && revealed !== undefined && sameKeyMaterial(there, revealed);
      if (!declaredCopy && !revealedCopy) {
        throw new IronTrellisError("KEY_EXISTS", false, `a next-key file is in the way: ${nextPath} holds ${there === undefined ? "something unreadable" : "a key this history never declared nor committed to"}, and the rotation's fresh next key would replace it; move it aside, then rotate again`, { keyPath: nextPath });
      }
    }
    if (stagesNext && commitOnly && existsSync(nextPath)) {
      throw new IronTrellisError("KEY_EXISTS", false, `a next-key file is already at ${nextPath}, and the owner keys in force did not commit to it; move it aside, then commit again`, { keyPath: nextPath });
    }
    const staged: string[] = [];
    try {
      let incoming: Signer;
      if (fixedSigner !== undefined) incoming = fixedSigner;
      else {
        try { incoming = revealed !== undefined ? promoteNextOwnerKeyFile(source!, pendingPath, keyId) : createOwnerKeyFile(pendingPath, keyId); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
        staged.push(pendingPath);
        fsyncDirectoryOf(pendingPath);
      }
      let nextNext: Signer | undefined;
      if (wantsNext) {
        const proposedNextId = nextFreeOwnerKeyId(new Set([...seen, keyId]));
        if (options.newNextSigner !== undefined) nextNext = options.newNextSigner;
        else if (options.newNextPublicKey !== undefined) nextNext = publicKeySigner(options.newNextPublicKey, proposedNextId);
        else {
          try {
            nextNext = options.newNextKeyReference !== undefined ? writeKeyReferenceFile(pendingNextPath, options.newNextKeyReference) : createNextOwnerKeyFile(pendingNextPath, proposedNextId);
          } catch (error) { translate(error, "READ_UNAVAILABLE"); }
          staged.push(pendingNextPath);
        }
        if (sameKeyMaterial(nextNext, incoming) || state.ownerKeyEpochs.some((epoch) => epoch.keys.some((key) => sameKeyMaterial(key, nextNext!)))) {
          throw new IronTrellisError("INVALID_INPUT", false, "the next key must be a new key: not the new owner key, and no key this history declared");
        }
      }
      const ownerKeys: readonly OwnerKey[] = commitOnly ? currentKeys : Object.freeze([
        ...currentKeys.filter((key) => !retired.includes(key.keyId)),
        Object.freeze({ keyId: incoming.keyId, scheme: incoming.scheme, credential: incoming.credential }),
      ]);
      const nextKeyDigests = nextNext === undefined ? undefined : Object.freeze([ownerKeyDigest(nextNext)]);
      if (resulting !== undefined) {
        const invalid = ownerPolicyFailure(resulting, ownerKeys);
        if (invalid !== undefined) throw new IronTrellisError("INVALID_INPUT", false, invalid, { code: "EVENT_DATA_INVALID" });
      }
      const unsigned = newEvent(config, "OWNER_KEYS_ROTATED", config.now(), {
        ownerKeys, ...(options.reason === undefined ? {} : { reason: options.reason }), ...(nextKeyDigests === undefined ? {} : { nextKeyDigests }),
        ...(resulting === undefined ? {} : { ownerPolicy: resulting }),
      });
      requireCondition(unsigned.timestamp >= head.canonicalTime, "CLOCK_INVALID");
      try { assertCapacityTransition(state, [unsigned]); } catch (error) { translate(error, "TRANSITION_REJECTED"); }
      const signing = signControl(config, state, unsigned, head, true);
      let event = signing instanceof Promise ? await signing : signing;
      if (revealed !== undefined) {
        // Proof of possession: the revealed key signs the same control-authorization challenge (it binds the whole event but these signatures).
        const proof = await signWith(revealed, controlChallenge(state, event, head), { purpose: "next-key-proof", historyId: state.eventHistoryHashes[0]! });
        event = Object.freeze({
          id: event.id, type: event.type, timestamp: event.timestamp,
          data: Object.freeze({ ...event.data, nextKeyAuthorizations: Object.freeze([Object.freeze({ keyId: incoming.keyId, scheme: incoming.scheme, signature: proof })]) }),
        });
      }
      // The head the history will have, computed in memory with the store's history hasher (and every replay rule checked; with
      // co-signatures to collect, every rule but the quorum, which the commit checks with them: A-92.4).
      const required = isFormat2(state.format) ? effectiveThreshold(inForce, "OWNER_KEYS_ROTATED") : 1;
      const prospective = withProspectiveEvent(state, event, undefined, { deferQuorum: required > 1 });
      if (!prospective.ok) throw prospectiveRefusal(state, event, head.position + 1, prospective);
      const challenge = controlAuthorizationChallenge({
        domain: state.genesis.domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
        previousHead: { hash: head.hash, position: head.position }, effectHash: controlEffectHash(event, state.hashAlgorithm),
      });
      const prepared: PreparedOwnerKeyRotation = Object.freeze({
        event, previousHead: head, head: prospective.head, ownerKeys, keyId: incoming.keyId, retired: Object.freeze(retired.slice()), fromPosition: prospective.head.position + 1,
        preRotated: revealed !== undefined, ...(nextKeyDigests === undefined ? {} : { nextKeyDigests }), signedBy: signer.keyId,
        required, challenge, challengeHash: controlChallenge(state, event, head),
        files: Object.freeze({
          ...(staged.includes(pendingPath) ? { pendingKeyFile: pendingPath } : {}), ...(staged.includes(pendingNextPath) ? { pendingNextKeyFile: pendingNextPath } : {}),
          ...(source === undefined ? {} : { nextKeySource: source }),
        }),
      });
      rotationInternals.set(prepared, Object.freeze({ incoming, oldSigner: signer, fileKey, nextNext, consumedNextFile: source, commitOnly }));
      return prepared;
    } catch (error) {
      for (const file of staged) { try { unlinkSync(file); } catch { /* already gone */ } }
      if (staged.length > 0) fsyncDirectoryOf(staged[0]!);
      throw error;
    }
  };
  /**
   * Records a prepared rotation under the writer lock (the caller holds it): the staged key files are checked, exactly
   * `prepared.event` is appended at `prepared.previousHead`, the recorded head must equal `prepared.head`, the witness
   * hand-off is signed with the old key, then the key files are swapped (owner key first, then the next key).
   */
  const commitRotation = async (writer: Readonly<{ appendAtExpectedHead(event: CanonicalEvent, expected: HistoryHead): HistoryHead }>, prepared: PreparedOwnerKeyRotation): Promise<OwnerKeyRotationResult> => {
    const inner = rotationInternals.get(prepared);
    if (inner === undefined) throw new IronTrellisError("INVALID_INPUT", false, "not a rotation this handle prepared, or one already committed: prepare it again with prepareOwnerKeyRotation");
    rotationInternals.delete(prepared);
    const historyFile = config.historyFile, keyPath = ownerKeyPathFor(historyFile), nextPath = nextOwnerKeyPathFor(historyFile);
    const { pendingKeyFile, pendingNextKeyFile } = prepared.files;
    // The staged files must still hold the prepared keys: an open elsewhere removes pending key files no epoch declares yet.
    const stagedHolds = (path: string, load: (path: string) => Signer, key: Signer | undefined): boolean => {
      try { return key !== undefined && sameKeyMaterial(load(path), key); } catch { return false; }
    };
    if ((pendingKeyFile !== undefined && !stagedHolds(pendingKeyFile, loadOwnerKeyFile, inner.incoming)) ||
        (pendingNextKeyFile !== undefined && !stagedHolds(pendingNextKeyFile, loadNextOwnerKeyFile, inner.nextNext))) {
      throw new IronTrellisError("KEY_UNAVAILABLE", false, "a key file this rotation staged is gone or was changed (another process settled it); nothing was recorded: prepare the rotation again", { files: prepared.files });
    }
    let rotationHead: HistoryHead;
    const session = witnessSessionOf(store);
    try {
      // Past the ROTATION_PENDING guard: this is the prepared rotation's own append (docs/reference/witness-operations.md §7.1).
      const append = (): HistoryHead => writer.appendAtExpectedHead(prepared.event, prepared.previousHead);
      try { rotationHead = session === undefined ? append() : session.allowingPending(append); } catch (error) { translate(error, "WRITE_UNCONFIRMED"); }
    } catch (error) {
      // Not recorded (or not known to be): staged keys the history does not declare are removed, never adopted.
      try { settleKeyFiles(historyFile, current()); } catch { /* the next open settles it */ }
      throw error;
    }
    if (rotationHead.hash !== prepared.head.hash || rotationHead.position !== prepared.head.position || rotationHead.canonicalTime !== prepared.head.canonicalTime) {
      throw new IronTrellisError("WRITE_UNCONFIRMED", true, `the recorded rotation head (position ${rotationHead.position}, ${rotationHead.hash}) is not the prepared head (position ${prepared.head.position}, ${prepared.head.hash})`, { recorded: rotationHead, prepared: prepared.head });
    }
    faultAt("after-append");
    // Remote witnesses (docs/WITNESS.md §7): while the old key is still held, sign the statement for the rotation head with it
    // and persist it with the rotation in the side file, BEFORE the key files are swapped. A crash before this point is
    // recovered from the archived key file; the submission itself happens after the swap (sync mode) or in the worker.
    // The bound witnesses that already recorded it (two-phase rotation) are learned first.
    if (session?.active === true) session.commitDelivered();
    if (session?.active === true) {
      try { await session.recordRotation({ rotation: prepared.event, previousHead: prepared.previousHead, rotationHead, oldSigner: inner.oldSigner }); } catch { /* recoverable, see above */ }
    }
    const after = current();
    dropSettledRecord(historyFile, after);
    // Files: a staged owner key moves into place (the retired key file is archived first); with a caller's signer a retired key file is archived away.
    let keyFile: string | undefined, retiredKeyFile: string | undefined, nextKeyFile: string | undefined;
    if (pendingKeyFile !== undefined) {
      let settled: KeyFileSettlement | undefined;
      try { settled = settleOwnerKeyFiles(historyFile, after); } catch { settled = undefined; }
      keyFile = settled?.completed === true ? keyPath : pendingKeyFile;
      retiredKeyFile = settled?.retiredKeyFile;
      faultAt("after-owner-key-swap");
    } else if (inner.fileKey !== undefined && !ownerKeyInForce(after, rotationHead.position + 1, inner.fileKey)) {
      try {
        retiredKeyFile = archiveOwnerKeyFile(keyPath, historyFile, inner.fileKey.keyId);
        unlinkSync(keyPath);
        fsyncDirectoryOf(keyPath);
      } catch { /* left in place: a retired key cannot sign anything this history accepts */ }
    }
    if (pendingNextKeyFile !== undefined) {
      let settled: NextKeyFileSettlement | undefined;
      try { settled = settleNextKeyFiles(historyFile, after); } catch { settled = undefined; }
      nextKeyFile = settled?.completed === true ? nextPath : pendingNextKeyFile;
    } else if (inner.consumedNextFile === nextPath && existsSync(nextPath)) {
      // The revealed key's next-key file now duplicates the owner key file (no new next-key file replaced it): removed once the owner key file holds the key.
      try {
        if (sameKeyMaterial(loadNextOwnerKeyFile(nextPath), inner.incoming) && sameKeyMaterial(loadOwnerKeyFile(keyPath), inner.incoming)) { unlinkSync(nextPath); fsyncDirectoryOf(nextPath); }
      } catch { /* left: owner status reports it */ }
    }
    // A commitment-only rotation keeps the signer (and where it comes from); any other rotation signs with the new key from now on.
    if (!inner.commitOnly) {
      config = Object.freeze({ ...config, signer: inner.incoming, signerSource: pendingKeyFile === undefined ? "option" as const : "key-file" as const });
      store.setSigner(inner.incoming);
    }
    return Object.freeze({
      eventId: prepared.event.id, head: rotationHead, keyId: inner.incoming.keyId, ownerKeys: prepared.ownerKeys, retired: prepared.retired, fromPosition: rotationHead.position + 1,
      ...(keyFile === undefined ? {} : { keyFile }), ...(retiredKeyFile === undefined ? {} : { retiredKeyFile }),
      preRotated: prepared.preRotated, ...(prepared.nextKeyDigests === undefined ? {} : { nextKeyDigests: prepared.nextKeyDigests }), ...(nextKeyFile === undefined ? {} : { nextKeyFile }),
      ...(inner.nextNext === undefined ? {} : { nextKeyId: inner.nextNext.keyId }), ...(inner.commitOnly ? { commitmentOnly: true } : {}),
    });
  };

  // ---------------------------------------------------------------- two-phase rotation (docs/reference/witness-operations.md §7.1) and key-event bundles (§7.3)

  /** Whether a bound witness this process asked has not recorded a rotation of the history (the "rotation incomplete" state). */
  const incompleteOf = (): Readonly<{ rotationIncomplete?: boolean }> => {
    let status: WitnessStatusReport | undefined;
    try { status = store.witnessStatus(); } catch { status = undefined; }
    // Not confirmed by a bound witness (it lacks the rotation, or was not reached) counts as incomplete.
    return status === undefined || status.bound.length === 0 ? {} : { rotationIncomplete: status.witnesses.some((w) => w.bound && w.pendingRotations !== 0) };
  };

  /**
   * Resolves a leftover prepared rotation (`<history>.rotation.pending.json`): the witnesses are asked; a witness that holds
   * its head makes the store append it (then the key files are settled), a record no bound witness holds is discarded (its
   * staged key files go with the next settle). Returns the record while it stays OUTSTANDING (a bound witness did not
   * answer), else `undefined`.
   */
  const resolveLeftoverRotation = async (): Promise<PendingRotationRecord | undefined> => {
    const path = pendingRotationPathFor(config.historyFile);
    if (!existsSync(path)) return undefined;
    const session = witnessSessionOf(store);
    let status: Awaited<ReturnType<NonNullable<typeof session>["resolvePending"]>> | "UNRESOLVED" = "UNRESOLVED";
    try { status = session === undefined ? "UNRESOLVED" : await session.resolvePending(); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    try {
      store.withExclusiveWriter(() => { settleKeyFiles(config.historyFile, current()); });
    } catch { /* the next open settles it */ }
    refreshSigner(current());
    if (status !== "UNRESOLVED") return undefined;
    return outstandingRotation(config.historyFile, current());
  };

  /**
   * `--emergency` while a prepared rotation is outstanding and its outcome at a bound witness is unknown: that prepared
   * rotation is recorded now (it may already be at a witness, so no other rotation may take its place). Only a record
   * whose new owner key this handle holds (its staged key file, or the caller's signer) is recorded; nothing is signed
   * anew but the pinned head.
   */
  const recordOutstanding = async (record: PendingRotationRecord, options: RotationOptions): Promise<OwnerKeyRotationResult> => {
    const staged = (() => { try { return loadOwnerKeyFile(pendingOwnerKeyPathFor(config.historyFile)); } catch { return undefined; } })();
    const given = options.newSigner ?? options.nextSigner;
    // A commitment-only rotation's "incoming" key is the owner key in force, which this handle signs with.
    const keeping = keepsEveryOwnerKey(ownerKeysAt(current(), record.previousHead.position + 1), (record.event.data.ownerKeys ?? []) as readonly OwnerKey[]);
    const own = keeping ? (() => { try { return ownerSigner(config); } catch { return undefined; } })() : undefined;
    const incoming = [staged, given, own].find((signer) => signer !== undefined && sameKeyMaterial(signer, record.incoming) && signer.keyId === record.incoming.keyId);
    if (incoming === undefined) {
      throw new IronTrellisError("KEY_UNAVAILABLE", false,
        `a prepared owner key rotation (position ${record.head.position}) is outstanding, but this handle does not hold its new owner key ${record.incoming.keyId} (its staged key file is gone and no matching signer was given); resolve it when the witnesses answer, or remove ${pendingRotationPathFor(config.historyFile)} deliberately once you know no witness holds its head`,
        { position: record.head.position });
    }
    const session = witnessSessionOf(store);
    const oldSigner = ownerSigner(config);
    const head = await lockedRotation(async (writer) => {
      const state = current();
      if (judgePendingRotation(state, record).status !== "OUTSTANDING") throw new IronTrellisError("HISTORY_CONFLICT", false, "the prepared rotation is no longer outstanding; rotate again");
      let recorded: HistoryHead;
      const append = (): HistoryHead => writer.appendAtExpectedHead(record.event, record.previousHead);
      try { recorded = session === undefined ? append() : session.allowingPending(append); } catch (error) { translate(error, "WRITE_UNCONFIRMED"); }
      if (session?.active === true) {
        try { await session.recordRotation({ rotation: record.event, previousHead: record.previousHead, rotationHead: recorded, oldSigner }); } catch { /* the archived key file signs it later */ }
      }
      settleKeyFiles(config.historyFile, current());
      return recorded;
    });
    await attested(store);
    refreshSigner(current());
    if (given !== undefined && !keeping) { config = Object.freeze({ ...config, signer: given, signerSource: "option" as const }); store.setSigner(given); }
    const state = current(), ownerKeys = ownerKeysAt(state, head.position + 1);
    const retired = ownerKeysAt(state, head.position).filter((key) => !ownerKeys.some((k) => k.keyId === key.keyId)).map((key) => key.keyId);
    const bundle = await writeBundleQuietly(head.position, record.statement);
    await afterRotation();
    return Object.freeze({
      eventId: record.event.id, head, keyId: record.incoming.keyId, ownerKeys, retired: Object.freeze(retired), fromPosition: head.position + 1,
      preRotated: record.event.data.nextKeyAuthorizations !== undefined, ...(record.nextKeyDigests === undefined ? {} : { nextKeyDigests: record.nextKeyDigests }),
      ...(keeping ? { commitmentOnly: true } : {}), emergency: true, ...(bundle === undefined ? {} : { bundle }), ...incompleteOf(),
    });
  };

  /**
   * The two-phase rotation (docs/reference/witness-operations.md §7.1), the default when the history binds remote witnesses:
   *  1. flush, and require every bound witness's verified latest head to be the local head r - 1;
   *  2. under the writer lock: prepare the rotation in memory (key files staged), sign the old-key statement for head r,
   *     persist the prepared-rotation record;
   *  3. hand statement and rotation to every bound witness (`POST …/key-events`, still under the lock);
   *  4. none accepted: abort (nothing appended, staged files and record removed, WITNESS_UNAVAILABLE); an unknown outcome
   *     keeps the record (the next owner command resolves it); otherwise append exactly the prepared event, swap the key
   *     files, clear the record, and queue the rotation for the witnesses that did not take it ("rotation incomplete").
   */
  const twoPhaseRotation = async (options: RotationOptions): Promise<OwnerKeyRotationResult> => {
    const session = witnessSessionOf(store)!;
    const path = pendingRotationPathFor(config.historyFile);
    const needEvery = "rotation needs every bound witness; retry, or rotate with --emergency";
    for (let attempt = 0; ; attempt += 1) {
      // Answers count only when learned in this attempt: `started` is past every answer learned before (their `at` is at most
      // the current millisecond), so an answer from the same millisecond before the attempt never passes for a fresh one.
      const started = Date.now() + 1;
      while (Date.now() < started) await new Promise((resolve) => setTimeout(resolve, 1));
      let flushError: unknown;
      try { await store.flush(); } catch (error) {
        if (error instanceof EngineError && (error.code === "ROLLBACK_DETECTED" || error.code === "WITNESS_SPLIT_VIEW")) translate(error, "READ_UNAVAILABLE");
        flushError = error;
      }
      const lagging = session.boundNotAt(current().head, started);
      if (lagging.length > 0) {
        throw new IronTrellisError("WITNESS_UNAVAILABLE", false,
          `${needEvery} (not confirmed at the current head: ${lagging.join(", ")}${flushError instanceof Error ? `; ${flushError.message}` : ""}); nothing was written`,
          { reason: "ROTATION_NEEDS_WITNESSES", witnesses: lagging });
      }
      const outcome = await lockedRotation(async (writer) => {
        const state = current();
        if (session.boundNotAt(state.head, started).length > 0) return "MOVED" as const;
        const prepared = await prepareRotation(options);
        const inner = rotationInternals.get(prepared)!;
        const abandon = (): void => {
          rotationInternals.delete(prepared);
          for (const file of [prepared.files.pendingKeyFile, prepared.files.pendingNextKeyFile]) if (file !== undefined) { try { unlinkSync(file); } catch { /* gone */ } }
          try { removePendingRotation(path); } catch { /* the next settle drops it */ }
        };
        let record: PendingRotationRecord;
        try {
          faultAt("after-stage");
          const statement = await signHeadStatement(inner.oldSigner, Object.freeze({
            version: HEAD_STATEMENT_VERSION, historyId: state.eventHistoryHashes[0]!, domain: state.genesis.domain as TrellisDomain, head: prepared.head,
            previous: Object.freeze({ hash: prepared.previousHead.hash, position: prepared.previousHead.position }),
          }));
          const unsealed = Object.freeze({
            version: PENDING_ROTATION_VERSION, historyId: state.eventHistoryHashes[0]!, event: prepared.event, previousHead: prepared.previousHead, head: prepared.head, statement,
            incoming: Object.freeze({ keyId: inner.incoming.keyId, scheme: inner.incoming.scheme, credential: inner.incoming.credential }),
            ...(prepared.nextKeyDigests === undefined ? {} : { nextKeyDigests: prepared.nextKeyDigests }),
            staged: Object.freeze({ ownerKey: prepared.files.pendingKeyFile !== undefined, nextKey: prepared.files.pendingNextKeyFile !== undefined }), createdAt: Date.now(),
          }) as Omit<PendingRotationRecord, "seal">;
          // Sealed by the old owner key (the key that signed the event): no field of the record can be edited without it.
          const seal = Object.freeze({ keyId: inner.oldSigner.keyId, scheme: inner.oldSigner.scheme, signature: await signWith(inner.oldSigner, pendingRotationSealHash(unsealed), { purpose: "rotation-seal", historyId: state.eventHistoryHashes[0]! }) });
          record = Object.freeze({ ...unsealed, seal });
          writePendingRotation(path, record);
        } catch (error) {
          if (!(error instanceof RotationFault)) abandon();
          throw error;
        }
        faultAt("after-record");
        const end = session.beginPreparedRotation();
        try {
          const delivery = await session.deliverPreparedRotation(record);
          faultAt("after-delivery");
          if (delivery.accepted.length === 0) {
            const refusals = delivery.refused.map((r) => `${r.url}: ${r.code}: ${r.message}`);
            if (delivery.unknown.length === 0) {
              abandon();
              throw new IronTrellisError("WITNESS_UNAVAILABLE", false, `${needEvery} (${refusals.join("; ") || "no bound witness recorded it"}); nothing was written`,
                { reason: "ROTATION_ABORTED", refused: delivery.refused });
            }
            rotationInternals.delete(prepared);
            throw new IronTrellisError("WITNESS_UNAVAILABLE", false,
              `${needEvery}: no bound witness confirmed the rotation, and whether ${delivery.unknown.map((u) => u.url).join(", ")} recorded it is unknown (${delivery.unknown.map((u) => u.message).join("; ")}); the prepared rotation is kept in ${path} and the next owner command completes or discards it`,
              { reason: "ROTATION_OUTCOME_UNKNOWN", pendingPath: path, refused: delivery.refused, unknown: delivery.unknown });
          }
          const rotated = await commitRotation(writer, prepared);
          return { rotated, delivery, record, oldSigner: inner.oldSigner };
        } finally {
          end();
        }
      });
      await attested(store);
      if (outcome === "MOVED") {
        if (attempt < 2) continue;
        throw new IronTrellisError("HISTORY_CONFLICT", false, "the history kept moving while the rotation waited for the witnesses; rotate again");
      }
      const bundle = await writeBundleQuietly(outcome.rotated.head.position, outcome.record.statement, [outcome.oldSigner]);
      await afterRotation();
      return Object.freeze({ ...outcome.rotated, witnesses: outcome.delivery, emergency: false, ...(bundle === undefined ? {} : { bundle }), ...incompleteOf() });
    }
  };

  /** A signer for an owner key in force at `position`: the handle's, one given, the key file, or an archived retired key file. */
  const signerAt = (state: ReplayState, position: number, extra: readonly (Signer | undefined)[] = []): Signer | undefined => {
    const candidates: (Signer | undefined)[] = [...extra, config.signer];
    for (const candidate of candidates) if (candidate !== undefined && ownerKeyInForce(state, position, candidate)) return candidate;
    for (const file of [ownerKeyPathFor(config.historyFile), ...retiredOwnerKeyFilesFor(config.historyFile)]) {
      let loaded: Signer;
      try { loaded = loadOwnerKeyFile(file); } catch { continue; }
      if (ownerKeyInForce(state, position, loaded)) return loaded;
    }
    return undefined;
  };

  /**
   * The key-event bundle of the owner key event at `position` (docs/reference/witness-operations.md §7.3): the statement for its head
   * (previous = the head before it; `statement` when already signed), and for a pre-rotated rotation the chain from the
   * last head a bound witness is known to hold (docs/reference/witness-operations.md §7.4). Written to `<history>.key-event-<position>.bundle.json` (0600).
   */
  const writeBundle = async (position: number, statement?: SignedHeadStatement, extraSigners: readonly (Signer | undefined)[] = []): Promise<KeyEventExport> => {
    const state = current();
    const event = state.events[position];
    if (event === undefined || event.type !== "OWNER_KEYS_ROTATED") throw new IronTrellisError("INVALID_INPUT", false, `position ${position} holds no owner key event`);
    const kind = "ROTATED" as const;
    const historyId = state.eventHistoryHashes[0]!;
    const at = (p: number) => Object.freeze({ hash: state.eventHistoryHashes[p]!, position: p });
    const eventHead = Object.freeze({ hash: state.eventHistoryHashes[position]!, position, canonicalTime: event.timestamp });
    const signer = signerAt(state, position, extraSigners);
    const sign = async (previous: Readonly<{ hash: ContentHash; position: number }>): Promise<SignedHeadStatement> => {
      if (signer === undefined) throw new IronTrellisError("KEY_UNAVAILABLE", false, `no owner key in force at position ${position} is available to sign the head statement of the key event there (keep the retired key file beside the history)`);
      return signHeadStatement(signer, Object.freeze({ version: HEAD_STATEMENT_VERSION, historyId, domain: state.genesis.domain as TrellisDomain, head: eventHead, previous }));
    };
    const signed = statement ?? await sign(at(position - 1));
    let chain: SignedHeadStatement | undefined;
    const preRotated = (() => { let found: OwnerKeyEpoch | undefined; for (const e of state.ownerKeyEpochs) if (e.fromPosition <= position) found = e; return found?.nextKeyDigests !== undefined; })();
    const from = preRotated ? witnessSessionOf(store)?.chainFrom(state, position) : undefined;
    if (from !== undefined && from.position < position - 1) { try { chain = await sign({ hash: from.hash, position: from.position }); } catch { chain = undefined; } }
    const bundle: KeyEventBundle = Object.freeze({
      version: KEY_EVENT_BUNDLE_VERSION, historyId, event: event as unknown as Readonly<Record<string, unknown>>, previousHead: at(position - 1), eventHead: at(position), statement: signed,
      ...(chain === undefined ? {} : { chain }),
    });
    const target = keyEventBundlePathFor(config.historyFile, position);
    writePrivateAtomically(target, `${JSON.stringify(bundle, null, 2)}\n`);
    return Object.freeze({ position, kind, eventId: event.id, path: target, ...(chain === undefined ? {} : { chain: Object.freeze({ hash: chain.statement.previous!.hash, position: chain.statement.previous!.position }) }) });
  };
  /** `writeBundle` that never fails the key event it follows (its path, or `undefined`). */
  const writeBundleQuietly = async (position: number, statement?: SignedHeadStatement, extraSigners: readonly (Signer | undefined)[] = []): Promise<string | undefined> => {
    try { return (await writeBundle(position, statement, extraSigners)).path; } catch { return undefined; }
  };

  /**
   * `rotateOwnerKey` (and `commitNextKey`, a commitment-only rotation): a leftover prepared rotation is resolved first; with
   * bound witnesses (and without `emergency`) two-phase, otherwise prepared and committed under one writer lock, then
   * delivered to the witnesses (queue and key-event bundle).
   */
  const rotate = async (options: RotationOptions): Promise<OwnerKeyRotationResult> => {
    { const before = witnessBeforeWrite(store); if (before !== undefined) await before; }

    // An interrupted two-phase rotation is resolved first: completed when a witness holds its head, discarded when none does.
    const leftover = await resolveLeftoverRotation();
    if (leftover !== undefined) {
      if (options.emergency !== true) {
        throw new IronTrellisError("WITNESS_UNAVAILABLE", false,
          `a prepared owner key rotation (position ${leftover.head.position}) is outstanding and a bound witness did not answer whether it holds its head: retry when the witnesses answer, or rotate with --emergency to record that prepared rotation now`,
          { reason: "ROTATION_PENDING", position: leftover.head.position, pendingPath: pendingRotationPathFor(config.historyFile) });
      }
      return recordOutstanding(leftover, options);
    }
    const session = witnessSessionOf(store);
    if (session?.hasBoundWitnesses === true && options.emergency !== true) return twoPhaseRotation(options);
    // Emergency (or no bound witness): prepare and commit under one writer lock, deliver afterwards (queue and bundle).
    const oldSigner = (() => { try { return ownerSigner(config); } catch { return undefined; } })();
    const rotated = await lockedRotation(async (writer) => commitRotation(writer, await prepareRotation(options)));
    await attested(store);
    const bundle = await writeBundleQuietly(rotated.head.position, undefined, [oldSigner]);
    await afterRotation();
    return Object.freeze({ ...rotated, emergency: options.emergency === true, ...(bundle === undefined ? {} : { bundle }), ...incompleteOf() });
  };

  const owner: LocalOwner = {
    format: store.format as HistoryFormat,
    async createAgent(input) {
      return write("AGENT_CREATED", { agentId: identifier(record(input, ["id"]).id), principalId: config.owner, controllerId: config.controller, initialControlEpoch: 1 });
    },
    async createRole(input) {
      const r = record(input, ["id"], ["exclusive"]);
      if (Object.hasOwn(r, "exclusive")) requireCondition(typeof r.exclusive === "boolean");
      // Both event formats require `exclusive === true` (events.ts ROLE_CREATED): refuse a shared role before any clock read or write.
      if (r.exclusive === false) throw new IronTrellisError("INVALID_INPUT", false, "only exclusive roles are supported in this release");
      return write("ROLE_CREATED", { roleId: identifier(r.id), principalId: config.owner, exclusive: true });
    },
    async grant(input) {
      const r = record(input, GRANT_REQUIRED, GRANT_OPTIONAL);
      { const checked = witnessChecked(); if (checked !== undefined) await checked; }
      return write("AUTHORITY_GRANTED", { grant: permissionGrant(r, config.owner, current()) });
    },
    async delegate(input) {
      const r = record(input, [...GRANT_REQUIRED, "parent", "from"], GRANT_OPTIONAL.filter((key) => key !== "parent" && key !== "from"));
      { const checked = witnessChecked(); if (checked !== undefined) await checked; }
      return write("AUTHORITY_GRANTED", { grant: permissionGrant(r, config.owner, current()) });
    },
    async prohibit(input) {
      const r = record(input, ["id", "actions", "resources"], ["subject", "root", "anchor", "from", "global", "expiresAt", "notBefore", "maxAmount"]);
      { const checked = witnessChecked(); if (checked !== undefined) await checked; }
      if (Object.hasOwn(r, "global")) requireCondition(typeof r.global === "boolean");
      const common = { kind: "PROHIBITION" as const, authorityId: identifier(r.id), ...optional(r, "subject", identifier, "subjectActorId"), constraints: constraintsOf(r) };
      if (r.global === true) {
        requireCondition(!Object.hasOwn(r, "root") && !Object.hasOwn(r, "anchor") && !Object.hasOwn(r, "from"));
        return write("AUTHORITY_GRANTED", { grant: { ...common, scope: "GLOBAL", grantorId: current().genesis.globalPolicySourceId } });
      }
      requireCondition(Object.hasOwn(r, "root"));
      const anchor = Object.hasOwn(r, "anchor") ? { parentAuthorityId: identifier(r.anchor) } : {};
      const from = Object.hasOwn(r, "from") ? identifier(r.from) : config.owner;
      return write("AUTHORITY_GRANTED", { grant: { ...common, scope: "ROOT", grantorId: from, rootAuthorityId: identifier(r.root), ...anchor } });
    },
    async revoke(authority) {
      return write("AUTHORITY_REVOKED", { authorityId: identifier(authority), revokerId: config.owner });
    },
    async appoint(input) {
      const r = record(input, ["agent", "role", "tenure", "number"], ["succession"]);
      const number = time(r.number);
      requireCondition(number > 0);
      return write("AGENT_APPOINTED", {
        agentId: identifier(r.agent), roleId: identifier(r.role), roleTenureId: identifier(r.tenure), tenureNumber: number, principalId: config.owner,
        ...(Object.hasOwn(r, "succession") ? { successionRuleId: identifier(r.succession) } : {}),
      });
    },
    async unappoint(input) {
      const r = record(input, ["agent", "role", "tenure"]);
      return write("AGENT_UNAPPOINTED", { agentId: identifier(r.agent), roleId: identifier(r.role), roleTenureId: identifier(r.tenure), principalId: config.owner });
    },
    async terminate(input) {
      const r = record(input, ["agent", "succession", "role", "tenure"]);
      return write("AGENT_TERMINATED", {
        agentId: identifier(r.agent), principalId: config.owner, successionRuleId: identifier(r.succession), roleId: identifier(r.role), roleTenureId: identifier(r.tenure),
      });
    },
    async declareSuccession(input) {
      const r = record(input, ["id", "from", "to", "role"]);
      return write("SUCCESSION_RULE_DECLARED", {
        ruleId: identifier(r.id), principalId: config.owner, predecessorAgentId: identifier(r.from), successorAgentId: identifier(r.to), roleId: identifier(r.role),
        trigger: "AGENT_TERMINATED", permittedEventTypes: ["AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"],
      });
    },
    async succeed(input) {
      const r = record(input, ["id", "rule", "fromAgent", "fromTenure", "toAgent", "toTenure", "role", "number"]);
      const steps = successionSteps(config, r), sealId = `handover:${identifier(r.id)}:checkpoint`;
      { const before = witnessBeforeWrite(store); if (before !== undefined) await before; }
      let state = current();
      refreshSigner(state);
      // Resume an interrupted handover at its exact recorded steps; never roll retirement back.
      const remaining = steps.filter((step) => {
        const position = state.eventPositionsById.get(step.id);
        if (position === undefined) return true;
        const existing = state.events[position]!;
        requireCondition(existing.type === step.type && canonicalEncode(controlEffect(existing.data)) === canonicalEncode(step.data), "OPERATION_CONFLICT");
        return false;
      });
      if (remaining.length > 0) {
        const at = config.now();
        requireCondition(at >= state.head.canonicalTime, "CLOCK_INVALID");
        // Validate the whole handover on a private copy-on-write fork of the cached state before the first durable step (both steps or
        // nothing); a replay only when the fork is unavailable (the next event would still be inside a migrated legacy prefix).
        const base = state.head;
        let trial = forkReplayState(state);
        if (trial === undefined) {
          trial = createReplayState(state.format);
          requireCondition(replayFrom(trial, state.events).status === "ACCEPTED", "INVALID_HISTORY");
        }
        const prospective: CanonicalEvent[] = [];
        for (const step of remaining) {
          const signing = signControl(config, state, Object.freeze({ ...step, timestamp: at }), trial.head);
          const signed = signing instanceof Promise ? await signing : signing;
          const applied = applyEvent(trial, signed);
          requireCondition(applied.ok, "TRANSITION_REJECTED");
          prospective.push(signed);
        }
        // The fork reads through to the live cached state: an in-process append while a (KMS) signer ran invalidates it.
        requireCondition(sameHead(current().head, base), "HISTORY_CONFLICT");
        try { assertCapacityTransition(state, prospective); } catch (error) { translate(error, "TRANSITION_REJECTED"); }
        for (const next of prospective) {
          const head = state.head;
          requireCondition(next.timestamp >= head.canonicalTime, "CLOCK_INVALID");
          try { await whenWriterFree(store, () => store.appendAtExpectedHead(next, head)); } catch (error) { translate(error, "WRITE_UNCONFIRMED"); }
          state = current();
        }
        await attested(store);
        { const after = witnessAfterWrite(store); if (after !== undefined) await after; }
      }
      // SPEC §7.3: in format 2 the handover ends with a checkpoint sealing the state after the transfer (resumed like the steps: by its id).
      // A-174.2: when the handle's signers cannot form a counting set of M_eff(STATE_CHECKPOINT) (or rule T2 refuses the only
      // one, A-119.3), the seal is not written, never short: succeed() completes and reports CHECKPOINT_SUPPRESSED {NO_SIGNER}.
      const format2 = store.format === TRELLIS2_FORMAT;
      let suppressed: CheckpointSuppression | undefined;
      if (format2 && !state.eventPositionsById.has(sealId)) {
        try {
          await writeCheckpoint(`handover:${identifier(r.id)}`, sealId);
        } catch (error) {
          if (!noSignerRefusal(error)) throw error;
          suppressed = Object.freeze({ code: "CHECKPOINT_SUPPRESSED" as const, reason: "NO_SIGNER" as const, message: error instanceof Error ? error.message : String(error) });
        }
        state = current();
      }
      const eventIds = format2 && suppressed === undefined ? [...steps.map((step) => step.id), sealId] : steps.map((step) => step.id);
      return Object.freeze({ status: "HANDOVER_RECORDED" as const, eventIds: Object.freeze(eventIds), head: state.head, ...(suppressed === undefined ? {} : { checkpoint: suppressed }) });
    },
    async admitRuntime(input) {
      const r = record(input, ["session", "agent", "epoch", "key", "expiresAt"], ["address", "credential", "scheme"]);
      const epoch = time(r.epoch);
      requireCondition(epoch > 0);
      const legacy = store.format === LEGACY_FORMAT;
      const supplied = Object.hasOwn(r, "credential") ? r.credential : r.address;
      requireCondition(typeof supplied === "string" && (Object.hasOwn(r, "credential") !== Object.hasOwn(r, "address")));
      const isAddress = /^0x[0-9a-fA-F]{40}$/.test(supplied), isPublicKey = /^0x[0-9a-fA-F]{64}$/.test(supplied);
      const scheme: SignatureScheme = Object.hasOwn(r, "scheme") ? (r.scheme as SignatureScheme) : isPublicKey ? "ed25519" : "eip191-personal-sign-keccak256";
      requireCondition(scheme === "ed25519" ? isPublicKey && !legacy : scheme === "eip191-personal-sign-keccak256" && isAddress);
      // A-157: a format-2 PublicKey32 is `0x` + 64 lowercase hex; replay refuses any other case at C4, so the writer refuses
      // before signing and never lowercases the caller's key. An eip191 address keeps any case (recorded lowercase).
      if (store.format === TRELLIS2_FORMAT && scheme === "ed25519" && !/^0x[0-9a-f]{64}$/.test(supplied)) {
        throw new IronTrellisError("INVALID_INPUT", false, "admitRuntime: an ed25519 credential must be 0x + 64 lowercase hex (PublicKey32, r4 §3.3; A-157)", { reason: "PUBLIC_KEY_CASE" });
      }
      // A-32.3 (writer rule, format 2): a session credential is never an owner key, another session's or a counterparty's credential.
      if (store.format === TRELLIS2_FORMAT) {
        const role = credentialRolesOf(current()).get(credentialRoleKey(scheme, supplied));
        if (role !== undefined) throw new IronTrellisError("INVALID_INPUT", false, `admitRuntime: the credential is already in use as ${role} (A-32.3: one key, one role)`, { reason: "CREDENTIAL_REUSE", role });
      }
      return write("RUNTIME_SESSION_ADMITTED", {
        sessionId: identifier(r.session), agentId: identifier(r.agent), controllerId: config.controller, controlEpoch: epoch, credentialKeyId: identifier(r.key),
        ...(legacy ? { credentialAddress: supplied } : { credentialScheme: scheme, ...(scheme === "ed25519" ? { credentialPublicKey: supplied } : { credentialAddress: supplied }) }),
        expiresAt: time(r.expiresAt),
      });
    },
    async advanceEpoch(input) {
      const r = record(input, ["agent", "from", "to"]);
      const from = time(r.from), to = time(r.to);
      requireCondition(from > 0 && to === from + 1);
      return write("CONTROL_EPOCH_ADVANCED", { agentId: identifier(r.agent), controllerId: config.controller, fromEpoch: from, toEpoch: to });
    },
    async rotateOwnerKey(input = {}) {
      const options = rotationOptions(input);
      if (store.format === undefined || !isTrellis(store.format)) throw new IronTrellisError("INVALID_INPUT", false, "owner key rotation needs an owner-signed history (legacy histories have no owner keys)");
      const rotated = await rotate(options);
      const warned = recoveryWarningOf(current().events[rotated.head.position]);
      return warned.warning === undefined ? rotated : Object.freeze({ ...rotated, ...warned });
    },
    async prepareOwnerKeyRotation(input = {}) {
      const options = rotationOptions(input);
      if (store.format === undefined || !isTrellis(store.format)) throw new IronTrellisError("INVALID_INPUT", false, "owner key rotation needs an owner-signed history (legacy histories have no owner keys)");
      { const before = witnessBeforeWrite(store); if (before !== undefined) await before; }
      return lockedRotation(() => prepareRotation(options, true));
    },
    async commitOwnerKeyRotation(prepared, options = {}) {
      if (!rotationInternals.has(prepared)) throw new IronTrellisError("INVALID_INPUT", false, "not a rotation this handle prepared, or one already committed: prepare it again with prepareOwnerKeyRotation");
      requireCondition(options !== null && typeof options === "object" && Object.keys(options).every((key) => key === "additionalAuthorizations"));
      const additional = options.additionalAuthorizations === undefined ? [] : authorizationEntries(options.additionalAuthorizations, 63);
      { const before = witnessBeforeWrite(store); if (before !== undefined) await before; }
      const rotated = await lockedRotation((writer) => commitRotation(writer, cosignRotation(prepared, additional)));
      await attested(store);
      await afterRotation();
      return rotated;
    },
    async commitNextKey(input = {}) {
      requireCondition(input !== null && typeof input === "object" && !Array.isArray(input) &&
        Object.keys(input).every((key) => ["nextSigner", "nextPublicKey", "nextKeyReference", "reason", "emergency", "ownerPolicy", "resetPolicy"].includes(key)));
      requireCondition(input.nextSigner === undefined || isSigner(input.nextSigner));
      if ([input.nextSigner, input.nextPublicKey, input.nextKeyReference].filter((v) => v !== undefined).length > 1) {
        throw new IronTrellisError("INVALID_INPUT", false, "pass the next key once: nextSigner, nextPublicKey or nextKeyReference");
      }
      if (store.format === undefined || !isTrellis(store.format)) throw new IronTrellisError("INVALID_INPUT", false, "a next-key commitment needs an owner-signed history (legacy histories have no owner keys)");
      // The same input checks as a rotation's new next key (public key syntax, reference shape, reason, emergency).
      const checked = rotationOptions({
        ...(input.nextSigner === undefined ? {} : { newNextSigner: input.nextSigner }), ...(input.nextPublicKey === undefined ? {} : { newNextPublicKey: input.nextPublicKey }),
        ...(input.nextKeyReference === undefined ? {} : { newNextKeyReference: input.nextKeyReference }), reason: input.reason ?? "next-key commitment",
        ...(input.emergency === undefined ? {} : { emergency: input.emergency }),
        ...(input.ownerPolicy === undefined ? {} : { ownerPolicy: input.ownerPolicy }), ...(input.resetPolicy === undefined ? {} : { resetPolicy: input.resetPolicy }),
      });
      const rotated = await rotate(Object.freeze({ ...checked, commitOnly: true as const }));
      return Object.freeze({
        eventId: rotated.eventId, head: rotated.head, nextKeyDigests: rotated.nextKeyDigests!, keyId: rotated.nextKeyId!, ...(rotated.nextKeyFile === undefined ? {} : { nextKeyFile: rotated.nextKeyFile }),
        ...(rotated.bundle === undefined ? {} : { bundle: rotated.bundle }), ...(rotated.witnesses === undefined ? {} : { witnesses: rotated.witnesses }),
        ...(rotated.rotationIncomplete === undefined ? {} : { rotationIncomplete: rotated.rotationIncomplete }), ...(rotated.emergency === undefined ? {} : { emergency: rotated.emergency }),
        ...recoveryWarningOf(current().events[rotated.head.position]),
      });
    },
    async rotateOwnerPolicy(input) {
      requireFormat2("rotateOwnerPolicy");
      { const checked = witnessChecked(); if (checked !== undefined) await checked; }
      const state = current();
      refreshSigner(state);
      const rotationData = policyRotationData(state, input);
      const prepared = await prepareControl("OWNER_KEYS_ROTATED", rotationData);
      const signer = ownerSigner(config);
      assertSingleSigner(state, "OWNER_KEYS_ROTATED", signer);
      if (!ownerKeyInForce(state, state.head.position + 1, signer)) throw new IronTrellisError("KEY_UNAVAILABLE", false, `the owner signer's key ${signer.keyId} is not an owner key in force`);
      const signature = await signWith(signer, prepared.challengeHash, { purpose: "control-authorization", historyId: state.eventHistoryHashes[0]! });
      return submitControl(prepared, [Object.freeze({ keyId: signer.keyId, signature })]); // the A-197.1 warning comes with submitControl
    },
    async prepareOwnerPolicyRotation(input) {
      requireFormat2("prepareOwnerPolicyRotation");
      { const checked = witnessChecked(); if (checked !== undefined) await checked; }
      return prepareControl("OWNER_KEYS_ROTATED", policyRotationData(current(), input));
    },
    async prepareControlEvent(input) {
      requireFormat2("prepareControlEvent");
      const r = record(input, ["type", "data"]);
      if (typeof r.type !== "string" || !CONTROL_EVENT_TYPES.has(r.type as EventType)) throw new IronTrellisError("INVALID_INPUT", false, `prepareControlEvent: ${String(r.type)} is not a control (◆) event type`);
      const type = r.type as EventType;
      const given = r.data;
      if (given !== null && typeof given === "object" && ["controlAuthorization", ADDITIONAL_CONTROL_AUTHORIZATIONS, "sourceControlAuthorization", "nextKeyAuthorizations"].some((key) => Object.hasOwn(given, key))) {
        throw new IronTrellisError("INVALID_INPUT", false, "prepareControlEvent: data carries no signatures; they are collected over the returned challenge and passed to submitControlEvent");
      }
      const data = controlData(type, given, "prepareControlEvent");
      if (type === "OWNER_KEYS_ROTATED") {
        if (!keepsEveryOwnerKey(ownerKeysAt(current(), current().head.position + 1), data.ownerKeys as readonly OwnerKey[])) {
          throw new IronTrellisError("INVALID_INPUT", false, "prepareControlEvent: a rotation that changes owner keys goes through prepareOwnerKeyRotation (it stages the key files)");
        }
      }
      return prepareControl(type, data);
    },
    async submitControlEvent(prepared, authorizations) {
      requireFormat2("submitControlEvent");
      return submitControl(prepared, authorizations);
    },
    ownerKeyStatus() { return ownerKeyStatusOf(config.historyFile, current()); },
    async exportKeyEvents(options = {}) {
      requireCondition(options !== null && typeof options === "object" && Object.keys(options).every((key) => key === "since"));
      const since = options.since === undefined ? 0 : time(options.since);
      if (store.format === undefined || !isTrellis(store.format)) throw new IronTrellisError("INVALID_INPUT", false, "key-event bundles need an owner-signed history");
      const state = current();
      const out: KeyEventExport[] = [];
      for (let position = Math.max(1, since); position <= state.head.position; position += 1) {
        const event = state.events[position]!;
        if (event.type !== "OWNER_KEYS_ROTATED") continue;
        try { out.push(await writeBundle(position)); } catch (error) {
          out.push(Object.freeze({ position, kind: "ROTATED" as const, eventId: event.id, error: error instanceof Error ? error.message : String(error) }));
        }
      }
      return Object.freeze(out);
    },
    observe,
    authorize(action, options) { return observe(options).authorize(action); },
    why(action, options) { return observe(options).why(action); },
    responsible(action, options) { return observe(options).responsible(action); },
    survives(agent, options) { return observe(options).survives(agent); },
    handover(agent, options) {
      const o = observe(options);
      return handoverReport(current(), identifier(agent), o.evaluationTime);
    },
    runtimeSession(sessionId) {
      const state = current(), session = state.runtimeSessions.get(identifier(sessionId));
      const agent = session === undefined ? undefined : state.agents.get(session.agentId);
      if (session === undefined || agent === undefined) return null;
      return Object.freeze({
        sessionId: session.id, agentId: session.agentId, controlEpoch: session.controlEpoch, ...(session.expiresAt === undefined ? {} : { expiresAt: session.expiresAt }),
        credentialKeyId: session.credentialKeyId, agentControlEpoch: agent.currentControlEpoch, agentTerminated: agent.terminated,
      });
    },
    capacity() { return capacityOf(current()); },
    async declareBudget(input) {
      requireFormat2("declareBudget");
      const data = controlData("BUDGET_DECLARED", input, "declareBudget");
      const result = await write("BUDGET_DECLARED", data);
      // A-179.4: warn when H ≥ a declared FIXED_WINDOW lengthMs.
      const horizon = sessionTimeHorizonOf(current()), period = (data as { period?: { kind?: unknown; lengthMs?: unknown } }).period;
      if (horizon === undefined || period?.kind !== "FIXED_WINDOW" || typeof period.lengthMs !== "number" || horizon < period.lengthMs) return result;
      return Object.freeze({ ...result, warning: `SESSION_TIME_HORIZON_COVERS_WINDOW: the session time horizon (${horizon} ms) is at least this budget's window (${period.lengthMs} ms); a session alone can carry history time across a whole window (A-179.4)` });
    },
    async updateBudget(input) {
      requireFormat2("updateBudget");
      return write("BUDGET_UPDATED", controlData("BUDGET_UPDATED", input, "updateBudget"));
    },
    async closeBudget(input) {
      requireFormat2("closeBudget");
      return write("BUDGET_CLOSED", { budgetId: identifier(record(input, ["budgetId"]).budgetId) });
    },
    async registerCounterparty(input) {
      requireFormat2("registerCounterparty");
      const { allowKeyRebind, ...rest } = (input ?? {}) as Readonly<Record<string, unknown>> & { allowKeyRebind?: unknown };
      requireCondition(allowKeyRebind === undefined || typeof allowKeyRebind === "boolean");
      const data = controlData("COUNTERPARTY_REGISTERED", rest, "registerCounterparty");
      assertCounterpartyKeys(current(), data as unknown as { counterpartyId: string; keys: readonly Readonly<{ keyId: string; scheme: string; credential: string }>[] }, allowKeyRebind === true);
      return write("COUNTERPARTY_REGISTERED", data);
    },
    async retireCounterparty(input) {
      requireFormat2("retireCounterparty");
      return write("COUNTERPARTY_RETIRED", { counterpartyId: identifier(record(input, ["counterpartyId"]).counterpartyId) });
    },
    async checkpoint(input = {}) {
      requireFormat2("checkpoint");
      const r = record(input, [], ["checkpointId"]);
      return writeCheckpoint(Object.hasOwn(r, "checkpointId") ? identifier(r.checkpointId) : undefined);
    },
    headroom(input) {
      const r = record(input, ["budgetId"], ["at"]);
      const budgetId = identifier(r.budgetId), at = Object.hasOwn(r, "at") ? time(r.at) : config.now();
      return headroomState(current(), budgetId, at) as Headroom | null;
    },
    exportView(input) {
      // The pin's attestation is the head attestation this handle holds (`include.attestations`, addendum A-27.3).
      try { return exportViewState(current(), input, { headAttestations: [store.pinnedHead()?.attestation].filter((a) => a !== undefined) }); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    },
    inspectDutyPolicy(input) { return inspectDutyPolicyOf(current(), input); },
    counterpartyState(counterpartyId) { return counterpartyStateOf(current(), identifier(counterpartyId)); },
    stateRoot() {
      const state = current();
      const root = rootAt(state, state.head.position);
      if (root === undefined) throw new IronTrellisError("INVALID_INPUT", false, `stateRoot needs a format-2 history; this file is ${state.format}`);
      return Object.freeze({ stateRoot: root, recordCount: state.stateRecords.size, projectionHead: projectionHeadAt(state, state.head.position) ?? null });
    },
    verify() {
      current();
      let report: VerificationReport;
      try { report = store.verify(); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
      return withRollback(report);
    },
    async verifyWithWitnesses(options = {}) {
      requireCondition(options !== null && typeof options === "object" && (options.allowUnreachableWitness === undefined || typeof options.allowUnreachableWitness === "boolean"));
      let report: VerificationReport;
      try { report = await store.verifyWithWitnesses(options.allowUnreachableWitness === true ? { allowUnreachableWitness: true } : {}); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
      return withRollback(report);
    },
    async checkWitnesses(options = {}) {
      requireCondition(options !== null && typeof options === "object" && (options.force === undefined || typeof options.force === "boolean"));
      try { return await store.checkWitnesses(options.force === true ? { force: true } : {}); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    },
    witnessStatus() {
      try { return store.witnessStatus(); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    },
    async addWitness(input, update = {}, options = {}) {
      if (store.format === undefined || !isTrellis(store.format)) throw new IronTrellisError("INVALID_INPUT", false, "remote witnesses need an owner-signed history (a legacy history cannot be owner-signed); migrate it first");
      let witness: RemoteWitnessConfig;
      try { witness = normalizeWitnessConfig(input); } catch (error) { throw new IronTrellisError("INVALID_INPUT", false, error instanceof Error ? error.message : String(error)); }
      const changes = record(update, [], ["quorum", "mode", "maxUnwitnessedEvents", "requireOnOpen", "cacheMs"]);
      const o = record(options, [], ["allowOffline"]);
      requireCondition(o.allowOffline === undefined || typeof o.allowOffline === "boolean");
      const session = witnessSessionOf(store)!;
      // The other witnesses are asked first (their rollback evidence refuses the change); a refusal by THIS witness (a missing
      // token) is what the new configuration is meant to fix, so it does not stop the change: its checks below decide.
      try { const checked = witnessChecked(); if (checked !== undefined) await checked; } catch (error) {
        if (!(error instanceof IronTrellisError && session.refusalOf(witness.verifierKey) !== undefined && error.message === session.refusalOf(witness.verifierKey)!.message)) throw error;
      }
      const state = current();
      refreshSigner(state);
      requireOwnerKey(state, "binding a witness");
      const base = session.editablePolicy === undefined ? undefined : storedPolicyOf(session.editablePolicy);
      const historyId = state.eventHistoryHashes[0]!;
      // Everything the witness must accept is checked BEFORE anything is written, so a history is never bound to a witness
      // it cannot feed: its key (GET /v1/witness), the registration, its latest head (a prefix of this copy), and a key for
      // every head statement it still needs (a rotation head it has not recorded needs the key that rotation retired).
      const fetch = config.witness === undefined || config.witness === false ? undefined : config.witness.fetch;
      const client = remoteWitness(witness, fetch === undefined ? {} : { fetch });
      let registration: WitnessReceipt | undefined, offline: EngineError | undefined;
      let missing: readonly number[] = [];
      try {
        await client.info();
        registration = (await client.register(state.events[0])).receipt;
        const info = await client.history(historyId);
        const latest = info?.latest?.head ?? null;
        if (latest !== null && !isPrefixOf(latest, state)) {
          const ahead = latest.position > state.head.position;
          throw new IronTrellisError("ROLLBACK_DETECTED", false,
            `witness ${witness.url} holds an owner-signed head at position ${latest.position} that ${ahead ? "is past the end of" : "is not a prefix of"} this copy of the history (head position ${state.head.position}): restore a copy that contains it before binding the witness; nothing was written`,
            { reason: ahead ? "WITNESS_AHEAD" : "WITNESS_FORK", witness: witness.url, witnessedHead: latest, observedHead: state.head, source: "network" });
        }
        missing = session.headsWithoutSigner(state, { ...(info === undefined ? {} : { epochs: info.epochs }), latest });
      } catch (error) {
        if (error instanceof IronTrellisError) throw error;
        if (error instanceof EngineError && error.code === "WITNESS_UNAVAILABLE") offline = error;
        else if (error instanceof EngineError && error.code === "WITNESS_SPLIT_VIEW") translate(error, "READ_UNAVAILABLE");
        else {
          const code = error instanceof EngineError ? error.code : "WITNESS_UNAVAILABLE";
          throw new IronTrellisError("WITNESS_REJECTED", false, `witness ${witness.url} cannot be bound: ${error instanceof Error ? error.message : String(error)}; nothing was written`,
            { ...((error instanceof EngineError ? error.detail : undefined) as object | undefined), url: witness.url, cause: code });
        }
      }
      if (offline !== undefined) {
        if (o.allowOffline !== true) {
          throw new IronTrellisError("WITNESS_UNAVAILABLE", false, `${offline.message}; nothing was written. Add it when it answers, or with allowOffline (--allow-offline) to bind it now and register it later`,
            { ...(offline.detail as object | undefined), cause: offline.code });
        }
        // Nothing is known of the witness: it may need every rotation head.
        missing = session.headsWithoutSigner(state);
      }
      if (missing.length > 0) {
        throw new IronTrellisError("KEY_UNAVAILABLE", false,
          `witness ${witness.url} needs head statements for position(s) ${missing.join(", ")} signed by owner keys this process does not hold (the statement for an owner key rotation head is signed by the key that rotation retired: put its <history>.owner-key.<keyId>.retired.json back beside the history); nothing was written`,
          { positions: missing, url: witness.url });
      }
      const stored: StoredWitnessConfig = storedPolicyOf(normalizeWitnessPolicy({ witnesses: [witness] })).witnesses[0]!;
      let next: ReturnType<typeof normalizeWitnessPolicy>;
      try {
        next = normalizeWitnessPolicy({ ...(base ?? {}), witnesses: [...(base?.witnesses ?? []).filter((w) => w.verifierKey !== witness.verifierKey), stored], ...changes });
      } catch (error) { throw new IronTrellisError("INVALID_INPUT", false, error instanceof Error ? error.message : String(error)); }
      session.setPolicy(storedPolicyOf(next), { clearSplitView: [witness.verifierKey] });
      const binding: BindingWitness = Object.freeze({
        url: stored.url, verifierKey: stored.verifierKey, ...(stored.name === undefined ? {} : { name: stored.name }), ...(stored.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}),
        ...(registration === undefined ? {} : { registration }),
      });
      // Bound already: a new binding only to record a registration receipt the earlier one lacks (it was bound offline).
      // The policy minimum the binding signs (docs/reference/witness-policy.md §5.3): the owner's explicit changes over the history's current bound
      // policy, never the side file's values (an attacker may have edited them). Its quorum counts the bound witnesses only.
      const boundNow = boundWitnessesOf(state), signed = boundPolicyOf(state);
      const quorum = (changes.quorum as number | undefined) ?? signed?.quorum, requireOnOpen = (changes.requireOnOpen as boolean | undefined) ?? signed?.requireOnOpen;
      const maxUnwitnessedEvents = (changes.maxUnwitnessedEvents as number | undefined) ?? signed?.maxUnwitnessedEvents;
      const policy = bindingPolicyOf({
        ...(quorum === undefined ? {} : { quorum }), ...(requireOnOpen === undefined ? {} : { requireOnOpen }), ...(maxUnwitnessedEvents === undefined ? {} : { maxUnwitnessedEvents }),
      }, boundNow.filter((b) => b.verifierKey !== witness.verifierKey).length + 1);
      const samePolicy = signed !== undefined && signed.quorum === policy.quorum && signed.requireOnOpen === policy.requireOnOpen && signed.maxUnwitnessedEvents === policy.maxUnwitnessedEvents;
      // A new binding also moves a bound witness to a new URL (the binding pins it), records a registration receipt an earlier
      // one lacks (bound offline), or signs a changed policy minimum.
      const bound = boundNow.some((b) => b.verifierKey === witness.verifierKey && b.url === witness.url && (b.allowInsecureHttp === true) === (witness.allowInsecureHttp === true)) &&
        (registration === undefined || boundRegistrationOf(state, witness.verifierKey) !== undefined) && samePolicy;
      if (!bound) {
        // Bring every witness (the new one included) up to the current head BEFORE the binding write: under the new policy
        // the new witness holds nothing yet, so with a quorum that needs it the whole history would count as unwitnessed
        // and maxUnwitnessedEvents would refuse the binding itself. Rollback evidence throws; anything else is left to the write.
        try { await store.flush(); } catch (error) {
          if (error instanceof EngineError && (error.code === "ROLLBACK_DETECTED" || error.code === "WITNESS_SPLIT_VIEW")) translate(error, "READ_UNAVAILABLE");
        }
      }
      const eventId = bound ? undefined : (await bind("BIND", [binding], policy)).eventId;
      session.reload();
      const { registration: _receipt, ...shown } = binding;
      const change = await settleWitnessChange(shown, true, eventId);
      return Object.freeze({ ...change, registered: registration !== undefined });
    },
    async removeWitness(which, options = {}) {
      const names = typeof which === "string" ? [which] : Array.isArray(which) ? [...which] : [];
      requireCondition(names.length > 0 && names.length <= 16 && names.every((name) => typeof name === "string" && name.length > 0 && name.length <= 4096));
      const o = record(options, [], ["acceptRemoteLoss", "reason"]);
      requireCondition(o.acceptRemoteLoss === undefined || typeof o.acceptRemoteLoss === "boolean");
      const acceptLoss = o.acceptRemoteLoss === true;
      const reason = o.reason;
      if (acceptLoss) {
        requireCondition(typeof reason === "string" && reason.length > 0 && utf8Bytes(reason) <= 256 && !/[\u0000-\u001f\u007f]/.test(reason));
      } else requireCondition(reason === undefined);
      const session = witnessSessionOf(store)!;
      const known = session.active ? session.policy!.witnesses : [];
      const matches: StoredWitnessConfig[] = [];
      for (const name of names) {
        let url: string | undefined;
        try { url = /^https?:/i.test(name) ? normalizeWitnessUrl(name) : undefined; } catch { url = undefined; }
        const match = known.find((w) => w.verifierKey === name || (url !== undefined && w.url === url));
        if (match === undefined) throw new IronTrellisError("INVALID_INPUT", false, `${name} is not a remote witness of this history`);
        if (!matches.some((m) => m.verifierKey === match.verifierKey)) matches.push(Object.freeze({ url: match.url, verifierKey: match.verifierKey }));
      }
      const minimum = session.minimumPolicy;
      const required = matches.find((m) => minimum?.witnesses.some((w) => w.verifierKey === m.verifierKey) === true);
      if (required !== undefined) {
        throw new IronTrellisError("INVALID_INPUT", false, `witness ${required.url} is required by the out-of-band witness policy ${minimum!.path} (IRONTRELLIS_WITNESS_POLICY); remove it there first`, { url: required.url, policyPath: minimum!.path });
      }
      const keys = matches.map((m) => m.verifierKey);
      let eventId: string | undefined, acceptedLoss: AcceptedLossRecord | undefined;
      if (!acceptLoss) {
        // A witness that refused the registration (or denies one it signed) does not block its own removal; its rollback
        // evidence, or any other witness's, does.
        let aside: ReturnType<typeof session.setAside> | undefined;
        const setAsideRefused = (): boolean => {
          const refused = keys.filter((key) => session.refusalOf(key) !== undefined);
          if (refused.length === 0 || aside !== undefined) return false;
          aside = session.setAside(refused, { dropAlarms: false });
          return true;
        };
        try {
          setAsideRefused();
          try { const checked = witnessChecked(); if (checked !== undefined) await checked; } catch (error) {
            if (!setAsideRefused()) throw error;
            const checked = witnessChecked(); if (checked !== undefined) await checked;
          }
          const state = current();
          const boundKeys = new Set(boundWitnessesOf(state).map((b) => b.verifierKey));
          const unbind = matches.filter((m) => boundKeys.has(m.verifierKey));
          // The unbinding is an owner write: it is refused like any other while a witness shows a rollback.
          eventId = unbind.length === 0 ? undefined : (await bind("UNBIND", unbind, policyAfterUnbinding(state, unbind.map((m) => m.verifierKey)))).eventId;
        } catch (error) {
          if (aside !== undefined) session.restoreLoss(aside);
          throw error;
        }
      } else {
        // Accepting a loss: only the owner key can, only for witnesses whose own verified answer shows this copy lacks a head
        // they hold, and only those witnesses' findings are set aside; every other witness still applies to the write.
        const fileState = session.fileState();
        if (fileState === undefined) throw new IronTrellisError("INVALID_INPUT", false, "the history is empty");
        refreshSigner(fileState);
        requireOwnerKey(fileState, "accepting a remote witness's loss");
        let evidence: Awaited<ReturnType<typeof session.lossEvidence>>;
        try { evidence = await session.lossEvidence(keys); } catch (error) {
          if (error instanceof EngineError && error.code === "INVALID_INPUT") throw new IronTrellisError("INVALID_INPUT", false, error.message, error.detail);
          translate(error, "READ_UNAVAILABLE");
        }
        // The unbinding names the witnesses the history binds (a witness only the side file names is dropped from it below).
        const boundKeys = new Set(boundWitnessesOf(fileState).map((b) => b.verifierKey));
        const unbind = matches.filter((m) => boundKeys.has(m.verifierKey));
        acceptedLoss = Object.freeze({ reason: reason as string, heads: Object.freeze(evidence.map((e) => Object.freeze({ verifierKey: e.verifierKey, head: e.head }))) });
        const signedLoss: AcceptedLossRecord = Object.freeze({ reason: acceptedLoss.reason, heads: Object.freeze(acceptedLoss.heads.filter((h) => boundKeys.has(h.verifierKey))) });
        const saved = session.acceptLoss(keys);
        try {
          if (unbind.length > 0) eventId = (await bind("UNBIND", unbind, policyAfterUnbinding(fileState, unbind.map((m) => m.verifierKey)), signedLoss.heads.length === 0 ? undefined : signedLoss)).eventId;
        } catch (error) {
          session.restoreLoss(saved);
          throw error;
        }
        session.forgetWitnesses(keys);
      }
      const base = session.editablePolicy === undefined ? undefined : storedPolicyOf(session.editablePolicy);
      const remaining = (base?.witnesses ?? []).filter((w) => !keys.includes(w.verifierKey));
      session.setPolicy(remaining.length === 0 ? undefined : storedPolicyOf(normalizeWitnessPolicy({ ...base!, witnesses: remaining, quorum: Math.min(base!.quorum, remaining.length) })));
      session.reload();
      return Object.freeze({
        witness: matches[0]!, bound: false, ...(eventId === undefined ? {} : { eventId }), status: store.witnessStatus(), submitted: false,
        removed: Object.freeze(matches), ...(acceptedLoss === undefined ? {} : { acceptedLoss }),
      });
    },
    exportHistory() { return Object.freeze(current().events.slice()); },
    async flush() {
      const hadRecord = existsSync(pendingRotationPathFor(config.historyFile));
      try { await store.flush(); } catch (error) {
        // A signer that failed after the write (a pin attestation, a head statement): the events are recorded all the same.
        if ((error instanceof IronTrellisError || error instanceof EngineError) && (error.code === "SIGNER_FAILED" || error.code === "KEY_UNAVAILABLE")) {
          throw new IronTrellisError(error.code, false, `${error.message} (after the write: the recorded events are durable; the pinned head keeps its earlier attestation until irontrellis repin succeeds, and queued witness statements wait for the signer)`, error.detail);
        }
        if (error instanceof IronTrellisError || error instanceof EngineError) translate(error, "WRITE_UNCONFIRMED");
        throw new IronTrellisError("SIGNER_FAILED", false, "the owner signer failed to attest the pinned head; the recorded events are durable");
      } finally {
        // A prepared rotation the flush completed or discarded (docs/reference/witness-operations.md §7.1): its staged key files are settled now.
        if (hadRecord && (existsSync(pendingOwnerKeyPathFor(config.historyFile)) || existsSync(pendingNextOwnerKeyPathFor(config.historyFile)))) {
          if (config.signerSource === "option") settleNextKeyFilesLocked(store, config.historyFile);
          else { settleOwnerKeyFilesLocked(store, config.historyFile); try { refreshSigner(current()); } catch { /* the next write refreshes it */ } }
        }
      }
    },
    close() { store.close(); },
  };
  return Object.freeze(owner);
}

// ---------------------------------------------------------------- creation and reopening

const genesisData = (config: Config, adapterPolicyHash: ContentHash, signer: Signer | undefined, nextSigner: Signer | undefined): Readonly<Record<string, unknown>> => {
  const lineage = `lineage:${config.ids()}`, policySource = `policy:${config.ids()}`;
  const common = { domain: config.domain, adapterPolicyHash, canonicalLineageId: lineage, policyVersion: POLICY_VERSIONS[config.format],
    rootRecognitionPolicy: ROOT_RECOGNITION_POLICY, globalPolicySourceId: policySource, timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY" };
  if (config.format === LEGACY_FORMAT) return { ...common, versions: LEGACY_VERSIONS };
  requireCondition(signer !== undefined, "KEY_UNAVAILABLE");
  const format2 = config.format === TRELLIS2_FORMAT;
  // SPEC §5.1 (format 2): `capacity` carries `maxStateRecords` beside `maxEvents`; `checkpointPolicy` and `projection` are written only when given (absent keys stay absent in the `genesis` record, SPEC §7.2).
  const capacity = config.maxEvents === undefined && (!format2 || config.maxStateRecords === undefined) ? {}
    : { capacity: { maxEvents: config.maxEvents ?? null, ...(format2 && config.maxStateRecords !== undefined ? { maxStateRecords: config.maxStateRecords } : {}) } };
  return {
    ...common, versions: { ...(format2 ? FORMAT2_VERSIONS : TRELLIS_VERSIONS), signatureScheme: config.signatureScheme },
    ownerKeys: [{ keyId: signer.keyId, scheme: signer.scheme, credential: signer.credential }, ...(format2 ? config.coOwnerKeys ?? [] : [])],
    // Pre-rotation from the start: the genesis commits the owner keys to their next key (part of the history id).
    ...(nextSigner === undefined ? {} : { nextKeyDigests: [ownerKeyDigest(nextSigner)] }),
    ...capacity,
    ...(format2 && config.checkpointPolicy !== undefined ? { checkpointPolicy: { everyEvents: config.checkpointPolicy.everyEvents } } : {}),
    ...(format2 && config.projection !== undefined ? { projection: config.projection } : {}),
    ...(format2 && config.ownerPolicy !== undefined ? { ownerPolicy: config.ownerPolicy } : {}),
    // A-179.1: written only when given (absent stays absent; `null` is the explicit default).
    ...(format2 && config.sessionTimeHorizonMs !== undefined ? { sessionTimeHorizonMs: config.sessionTimeHorizonMs } : {}),
  };
};

/**
 * The format-1 owner key: the caller's signer, or a fresh key file. A key file
 * already there (planted, or left by an interrupted creation) is adopted only
 * with `reuseExistingKey`; otherwise KEY_EXISTS. `created` names a key file
 * made here, removed again if the history cannot be created.
 */
function creationSigner(config: Config): { signer: Signer | undefined; created: string | undefined } {
  if (config.format === LEGACY_FORMAT) return { signer: undefined, created: undefined };
  if (config.signer !== undefined) return { signer: config.signer, created: undefined };
  const path = ownerKeyPathFor(config.historyFile);
  if (existsSync(path) && !config.reuseExistingKey) {
    throw new IronTrellisError("KEY_EXISTS", false, `an owner key file already exists: ${path}; a leftover or planted key is never adopted silently (remove it, or pass reuseExistingKey to use it)`, { keyPath: path });
  }
  if (existsSync(path) && config.ownerKeyReference !== undefined) {
    // Reused only when it names the same key: a reference is never silently replaced by another key.
    let there: Signer;
    try { there = loadOwnerKeyFile(path); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    if (!sameKeyMaterial(there, { scheme: "ed25519", credential: config.ownerKeyReference.publicKey })) {
      throw new IronTrellisError("KEY_EXISTS", false, `the owner key file ${path} holds another key than ownerKeyReference; move it aside first`, { keyPath: path });
    }
    return { signer: there, created: undefined };
  }
  try {
    if (existsSync(path)) return { signer: loadOwnerKeyFile(path), created: undefined };
    if (config.ownerKeyReference !== undefined) return { signer: writeKeyReferenceFile(path, config.ownerKeyReference), created: path };
    return { signer: createOwnerKeyFile(path), created: path };
  } catch (error) { translate(error, "READ_UNAVAILABLE"); }
}

/**
 * The pre-committed next key of a new format-1 history (pre-rotation): the caller's `nextSigner`, or a fresh next-key
 * file at `<history>.owner-next-key.json`. A next-key file already there is adopted only with `reuseExistingKey`;
 * otherwise KEY_EXISTS. `created` names a file made here, removed again if the history cannot be created.
 */
function creationNextKey(config: Config, signer: Signer | undefined): { nextSigner: Signer | undefined; created: string | undefined } {
  if (config.format === LEGACY_FORMAT || !config.nextKey) return { nextSigner: undefined, created: undefined };
  if (config.nextSigner !== undefined) {
    // A public-key-only next key proposes the next free key id (the commitment covers the key, not its id).
    const nextSigner = config.nextSigner.custody?.holder === "public-key-only" && signer !== undefined
      ? publicKeySigner(config.nextSigner.credential, nextFreeOwnerKeyId(new Set([signer.keyId]))) : config.nextSigner;
    return { nextSigner, created: undefined };
  }
  const path = nextOwnerKeyPathFor(config.historyFile);
  if (config.nextKeyReference !== undefined) {
    if (existsSync(path)) throw new IronTrellisError("KEY_EXISTS", false, `a next-key file already exists: ${path}; move it aside, then create the history again`, { keyPath: path });
    try { return { nextSigner: writeKeyReferenceFile(path, config.nextKeyReference), created: path }; } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  }
  if (existsSync(path) && !config.reuseExistingKey) {
    throw new IronTrellisError("KEY_EXISTS", false, `a next-key file already exists: ${path}; a leftover or planted key is never adopted silently (remove it, or pass reuseExistingKey to commit to it)`, { keyPath: path });
  }
  try {
    return existsSync(path) ? { nextSigner: loadNextOwnerKeyFile(path), created: undefined }
      : { nextSigner: createNextOwnerKeyFile(path, nextFreeOwnerKeyId(new Set(signer === undefined ? [] : [signer.keyId]))), created: path };
  } catch (error) { translate(error, "READ_UNAVAILABLE"); }
}

async function createLocalOwnerWithPolicy(options: LocalOwnerOptions, adapterPolicyHash: ContentHash): Promise<LocalOwner> {
  const config = configuration(options);
  requireCondition(config.domain.protocol === (isTrellis(config.format) ? "irontrellis" : "continuity"));
  requireCondition(config.format === LEGACY_FORMAT || config.domain.version === (config.format === TRELLIS2_FORMAT ? "2" : "1"));
  requireCondition(!existsSync(config.historyFile), "HISTORY_EXISTS");
  const timestamp = config.now();
  const { signer, created } = creationSigner(config);
  // Key files made here go again when no history was written with them (a history on disk must keep its keys).
  let createdNext: string | undefined;
  const discardKeys = (): void => {
    if (existsSync(config.historyFile)) return;
    for (const path of [created, createdNext]) if (path !== undefined) { try { unlinkSync(path); } catch { /* best effort */ } }
  };
  try {
    const next = creationNextKey(config, signer);
    createdNext = next.created;
    return await createWithSigner(config, adapterPolicyHash, timestamp, signer, created !== undefined, next.nextSigner);
  } catch (error) {
    discardKeys();
    throw error;
  }
}

/**
 * Registers the genesis with every witness of a creation policy before the
 * history file exists: returns each witness with its signed REGISTERED receipt
 * (none when it could not be reached: the queue registers it later). A witness
 * that refuses the registration, serves another key or gives an invalid answer
 * fails the creation with WITNESS_REJECTED; nothing is written then.
 */
async function registerAtCreation(witnesses: readonly RemoteWitnessConfig[], genesis: CanonicalEvent, fetch: WitnessPolicy["fetch"]): Promise<readonly BindingWitness[]> {
  return Promise.all(witnesses.map(async (witness): Promise<BindingWitness> => {
    const stored = storedPolicyOf(normalizeWitnessPolicy({ witnesses: [witness] })).witnesses[0]!;
    const shown: BindingWitness = Object.freeze({
      url: stored.url, verifierKey: stored.verifierKey, ...(stored.name === undefined ? {} : { name: stored.name }), ...(stored.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}),
    });
    const client = remoteWitness(witness, fetch === undefined ? {} : { fetch });
    try {
      await client.info();
      const registered = await client.register(genesis);
      return Object.freeze({ ...shown, registration: registered.receipt });
    } catch (error) {
      if (error instanceof EngineError && error.code === "WITNESS_UNAVAILABLE") return shown;
      const code = error instanceof EngineError ? error.code : "WITNESS_UNAVAILABLE";
      throw new IronTrellisError("WITNESS_REJECTED", false,
        `witness ${witness.url} cannot witness the new history: ${error instanceof Error ? error.message : String(error)}; the history was not created (fix the witness policy: its URL, verifier key or registration token)`,
        { ...((error instanceof EngineError ? error.detail : undefined) as object | undefined), url: witness.url, cause: code });
    }
  }));
}

async function createWithSigner(config: Config, adapterPolicyHash: ContentHash, timestamp: number, signer: Signer | undefined, keyCreatedHere: boolean, nextSigner: Signer | undefined): Promise<LocalOwner> {
  if (nextSigner !== undefined && signer !== undefined && sameKeyMaterial(nextSigner, signer)) throw new IronTrellisError("INVALID_INPUT", false, "the next key must differ from the owner key");
  if ((config.coOwnerKeys !== undefined || config.ownerPolicy !== undefined) && config.format !== TRELLIS2_FORMAT) {
    throw new IronTrellisError("INVALID_INPUT", false, "coOwnerKeys and ownerPolicy need a format-2 history (A-91)");
  }
  const genesis = newEvent(config, "DEPLOYMENT_INITIALIZED", timestamp, genesisData(config, adapterPolicyHash, signer, nextSigner));
  const principal = newEvent(config, "PRINCIPAL_CREATED", timestamp, { principalId: config.owner });
  // Refuse an invalid setup before creating a file (an invalid ownerPolicy or coOwnerKeys: INVALID_INPUT with the engine's reason).
  const checkedGenesis = validateGenesis(genesis.data, config.format, genesis.timestamp);
  if (!checkedGenesis.ok && (config.coOwnerKeys !== undefined || config.ownerPolicy !== undefined)) throw new IronTrellisError("INVALID_INPUT", false, checkedGenesis.reason);
  requireCondition(checkedGenesis.ok && validateEvent(principal, config.format, 1).ok, "INVALID_HISTORY");
  // A-92: the creation's own control events are signed by the handle's key alone.
  if (config.ownerPolicy !== undefined && signer !== undefined) {
    const keys = genesis.data.ownerKeys as readonly OwnerKey[];
    for (const type of ["PRINCIPAL_CREATED", "WITNESSES_BOUND"] as const) {
      const required = effectiveThreshold(config.ownerPolicy, type);
      if (required > 1 || ownerKeyClass(config.ownerPolicy, keys, signer) === "AGENT") {
        throw new IronTrellisError("INVALID_INPUT", false, `ownerPolicy: the creation writes ${type} signed by ${signer.keyId} alone, but the policy needs ${required} owner signature(s)${required > 1 ? "" : " and that key is AGENT"}; create with a policy under which this key signs it alone (threshold 1${required > 1 ? "" : ", the key not AGENT"}) and raise it afterwards with rotateOwnerPolicy`, { reason: "POLICY_UNSATISFIABLE_AT_CREATION", type, required });
      }
    }
  }
  const initial = [genesis, principal];
  // Remote witnesses given at creation (and the out-of-band minimum): registered before the file exists, and bound in the
  // event right after the principal, written together with the genesis and the principal. No copy of the history (and no
  // pinned head) ever exists without the binding, so a copy cut back "to before the witness" does not exist.
  const creationPolicy = !isTrellis(config.format) || config.witness === false ? undefined : (() => {
    const minimum = (() => { try { return minimumWitnessPolicy(); } catch (error) { translate(error, "READ_UNAVAILABLE"); } })();
    const given = config.witness === undefined ? [] : normalizeWitnessPolicy(config.witness).witnesses;
    const all = [...given];
    for (const m of minimum?.witnesses ?? []) if (!all.some((w) => w.verifierKey === m.verifierKey)) all.push(m);
    return all.length === 0 ? undefined : all;
  })();
  if (isTrellis(config.format)) {
    const trial = createReplayState(config.format);
    requireCondition(applyEvent(trial, genesis).ok, "INVALID_HISTORY");
    requireCondition(signer !== undefined, "KEY_UNAVAILABLE");
    try { initial[1] = await signControlEvent(signer, principal, config.domain, trial.head, trial.hashAlgorithm); } catch (error) { throw signerFailure(error); }
    if (creationPolicy !== undefined) {
      const witnesses = await registerAtCreation(creationPolicy, genesis, config.witness === undefined || config.witness === false ? undefined : config.witness.fetch);
      requireCondition(applyEvent(trial, initial[1]!).ok, "INVALID_HISTORY");
      // The caller's policy minimum is signed with the binding (docs/reference/witness-policy.md §5.3): no side file can lower it later.
      const given = config.witness === undefined || config.witness === false ? undefined : normalizeWitnessPolicy(config.witness);
      const bound = witnessBindingEvent({ action: "BIND", witnesses, policy: bindingPolicyOf(given, witnesses.length) });
      const binding = newEvent(config, bound.type, timestamp, bound.data);
      try { assertCapacityTransition(trial, [binding]); } catch (error) { translate(error, "TRANSITION_REJECTED"); }
      let signed: CanonicalEvent;
      try { signed = await signControlEvent(signer, binding, config.domain, trial.head, trial.hashAlgorithm); } catch (error) { throw signerFailure(error); }
      requireCondition(applyEvent(trial, signed).ok, "INVALID_HISTORY");
      initial.push(signed);
    }
  }
  let store: HistoryStore;
  try {
    store = createHistoryStore(config.historyFile, initial, {
      reuseExistingKey: keyCreatedHere || config.reuseExistingKey, ...(signer === undefined ? {} : { signer }), ...(config.witness === undefined ? {} : { witness: config.witness }),
      // A caller that names format 1 or legacy asks for the earlier writer of that format (see `LocalOwnerOptions.format`).
      readOnlyFormats: !(config.formatGiven && config.format !== TRELLIS2_FORMAT), trust: config.trust,
    });
  } catch (error) {
    translate(error, "WRITE_UNCONFIRMED");
  }
  // An asynchronous (KMS) signer attests the first pin after the fact: wait for it, so the new history is never left
  // with events after genesis and a pin no reader accepts (PIN_UNATTESTED).
  if (isTrellis(config.format) && signer?.signHashSync === undefined) {
    try { await store.flush(); } catch (error) {
      // flush() also submits to remote witnesses (after the attestation was written): an unreachable witness does not fail the creation.
      if (error instanceof EngineError && (error.code === "WITNESS_UNAVAILABLE" || WITNESS_FAILURES.has(error.code))) { /* queued */ }
      else if (error instanceof IronTrellisError || error instanceof EngineError) translate(error, "WRITE_UNCONFIRMED");
      else throw new IronTrellisError("SIGNER_FAILED", false, "the owner signer failed to attest the new history's pinned head; the history was created, attest it with repin");
    }
  }
  const owner = attach(store, config);
  // Sync mode: the head (binding included) is submitted before the creation returns; an unreachable witness leaves it queued.
  // The next-key commitment is part of the genesis, so every witness that registers the history knows it.
  if (creationPolicy !== undefined) { const synced = witnessAfterWrite(store); if (synced !== undefined) await synced; }
  return owner;
}

/** Create a new, operator-owned local policy history (format 2 by default). No runtime keys or effects. */
export function createLocalOwner(options: LocalOwnerOptions): Promise<LocalOwner> {
  return createLocalOwnerWithPolicy(options, ADAPTER_POLICY_HASH);
}
/** Explicit E5 attempt-record history; existing histories are not migrated. */
export function createLocalAttemptOwner(options: LocalOwnerOptions): Promise<LocalOwner> {
  return createLocalOwnerWithPolicy(options, ADAPTER_POLICY_E5_HASH);
}
/** Explicit E6 opt-in for a new history; does not migrate or reinterpret E5 histories. */
export function createLocalReviewOwner(options: LocalOwnerOptions): Promise<LocalOwner> {
  return createLocalOwnerWithPolicy(options, ADAPTER_POLICY_E6_HASH);
}
/** Reopen only the explicitly selected local profile (format autodetected). Does not prove global freshness. */
export function openLocalOwner(options: LocalOwnerOptions): LocalOwner {
  const config = configuration(options);
  const keyPath = ownerKeyPathFor(config.historyFile);
  let signer = config.signer;
  // A missing or unreadable key file leaves the handle read-only for control events (KEY_UNAVAILABLE on write), never fails the open.
  if (signer === undefined && existsSync(keyPath)) { try { signer = loadOwnerKeyFile(keyPath); } catch { signer = undefined; } }
  const withKey: Config = Object.freeze({ ...config, signer, ...(signer === undefined || config.signer !== undefined ? {} : { signerSource: "key-file" as const }) });
  const store = openStore(withKey);
  // A rotation that crashed between recording its event and swapping the key files is completed here (see rotateOwnerKey).
  const settled = config.signer === undefined ? settleOwnerKeyFilesLocked(store, config.historyFile) : settleNextKeyFilesLocked(store, config.historyFile);
  if (settled?.signer !== undefined) {
    store.setSigner(settled.signer);
    return attach(store, Object.freeze({ ...withKey, signer: settled.signer, signerSource: "key-file" as const }));
  }
  return attach(store, withKey);
}

/** Fresh local namespace (format 2 by default, like `createLocalOwner`). Owner-signed formats carry no chain fields; legacy domains keep the chain/address placeholders. */
export function createLocalDomain(options: Readonly<{ format?: HistoryFormat; ids?: () => string }> = {}): AuthorizationDomain {
  const r = record({ ...(options.format === undefined ? {} : { format: options.format }) }, [], ["format"]);
  requireCondition(r.format === undefined || r.format === LEGACY_FORMAT || r.format === TRELLIS_FORMAT || r.format === TRELLIS2_FORMAT);
  const id = (options.ids ?? randomUUID)();
  if (r.format === LEGACY_FORMAT) {
    return Object.freeze({ protocol: "continuity", version: "0.2", deploymentId: `local:${id}`, chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000000" });
  }
  return Object.freeze({ protocol: "irontrellis", version: r.format === TRELLIS_FORMAT ? "1" : "2", deploymentId: `local:${id}` });
}

export type { PinnedHead, Signer };

export type VerifyHistoryOptions = Readonly<{
  /** Re-pin a history whose pin is behind, malformed or missing (a write: the pin records `rollbackAcceptedAt` and the previous pin). */
  acceptRollback?: boolean;
  /** A missing or unattested pin on a format-1 or format-2 history is a note instead of a failure. */
  allowUnpinned?: boolean;
  /** Anchor logs to consult besides `<history>.anchors` (each must implement `entries()`), e.g. `localAnchorLog(customLog)`. */
  anchorLogs?: readonly AnchorTarget[];
  /** Attests the re-pin of `acceptRollback` (formats 1 and 2). */
  signer?: Signer;
}>;

/**
 * Integrity check of any history file (chain, pinned head and its attestation,
 * anchors, witnesses, control signatures); needs no owner key or profile. Pin
 * and witness problems are reported (`ok: false`, `failures`), not thrown; a
 * file that is not a valid history throws INVALID_HISTORY. Read-only unless
 * `acceptRollback` is given.
 */
export function verifyHistory(historyFile: string, options: VerifyHistoryOptions = {}): OwnerVerification {
  const opened = openForVerify(historyFile, options);
  try { return reportOf(opened, options); } finally { closeQuietly(opened); }
}

/**
 * `verifyHistory` for an asynchronous signer (ssh-agent, command, KMS): with `acceptRollback`, the re-pin is attested
 * after the synchronous open, so the report is taken once that attestation was written (or failed: the report then
 * shows the pin without it). Same result as `verifyHistory` otherwise.
 */
export async function verifyHistoryAsync(historyFile: string, options: VerifyHistoryOptions = {}): Promise<OwnerVerification> {
  const opened = openForVerify(historyFile, options);
  try {
    if (opened !== undefined) await opened.attestationsSettled();
    return reportOf(opened, options);
  } finally { closeQuietly(opened); }
}
const closeQuietly = (store: HistoryStore | undefined): void => { try { store?.close(); } catch { /* closed */ } };
function openForVerify(historyFile: string, options: VerifyHistoryOptions): HistoryStore {
  requireCondition(typeof historyFile === "string" && historyFile.length > 0 && !historyFile.includes("\0"));
  requireCondition(options !== null && typeof options === "object" && (options.signer === undefined || isSigner(options.signer)));
  // Every witness must be able to list the heads it holds (a local log can; an http or rekor witness cannot).
  requireCondition(options.anchorLogs === undefined || (Array.isArray(options.anchorLogs) && options.anchorLogs.every((w) => w !== null && typeof w === "object" && typeof w.entries === "function")));
  const acceptRollback = options.acceptRollback === true, allowUnpinned = options.allowUnpinned === true;
  try {
    // acceptRollback re-pins on open; allowUnpinned there only keeps an unreadable anchor log from failing the open (verify() reports it).
    return openHistoryStore(historyFile, acceptRollback
      ? { acceptRollback, allowUnpinned: true, ...(options.signer === undefined ? {} : { signer: options.signer }) }
      : { inspect: true, allowUnpinned });
  } catch (error) { translate(error, "READ_UNAVAILABLE"); }
}
function reportOf(store: HistoryStore, options: VerifyHistoryOptions): OwnerVerification {
  let report: VerificationReport;
  try {
    report = store.verify({ allowUnpinned: options.allowUnpinned === true, ...(options.anchorLogs === undefined ? {} : { anchorLogs: options.anchorLogs }) });
  } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  return withRollback(report);
}

export type VerifyHistoryWithWitnessesOptions = Omit<VerifyHistoryOptions, "acceptRollback" | "signer"> & Readonly<{
  /** Remote witnesses to consult: default the history's (side file policy plus bindings); `false` skips them. */
  witness?: WitnessPolicy | false;
  /** A witness that cannot be reached is a note instead of a failure. */
  allowUnreachableWitness?: boolean;
}>;

/**
 * `verifyHistory` plus the remote witnesses (docs/WITNESS.md §5, §6.1): each
 * configured or bound witness is asked for its latest head of this history;
 * the receipt, the checkpoint signature and the checkpoint's consistency with
 * the one remembered in `<history>.witness.json` are verified, and the head
 * must be a prefix of the file. Failures: REMOTE_WITNESS_ROLLBACK,
 * REMOTE_WITNESS_SPLIT_VIEW, REMOTE_WITNESS_INVALID,
 * REMOTE_WITNESS_UNREACHABLE (unless `allowUnreachableWitness`); notes:
 * UNWITNESSED_TAIL n, REMOTE_WITNESS_UNREGISTERED,
 * REMOTE_WITNESS_EQUIVOCATION_RECORDED n (the owner key signed a head that
 * conflicts with one a witness holds; see `EQUIVOCATION_WARNING`). Read-only: nothing is
 * written, the side file included.
 */
export async function verifyHistoryWithWitnesses(historyFile: string, options: VerifyHistoryWithWitnessesOptions = {}): Promise<OwnerVerification> {
  requireCondition(typeof historyFile === "string" && historyFile.length > 0 && !historyFile.includes("\0"));
  requireCondition(options !== null && typeof options === "object");
  requireCondition(options.anchorLogs === undefined || (Array.isArray(options.anchorLogs) && options.anchorLogs.every((w) => w !== null && typeof w === "object" && typeof w.entries === "function")));
  const allowUnpinned = options.allowUnpinned === true;
  let report: VerificationReport;
  try {
    const store = openHistoryStore(historyFile, { inspect: true, allowUnpinned, ...(options.witness === undefined ? {} : { witness: options.witness }) });
    try {
      report = await store.verifyWithWitnesses({
        allowUnpinned, ...(options.anchorLogs === undefined ? {} : { anchorLogs: options.anchorLogs }), ...(options.allowUnreachableWitness === true ? { allowUnreachableWitness: true } : {}),
        ...(options.witness === false ? { remote: false } : {}),
      });
    } finally {
      store.close();
    }
  } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  return withRollback(report);
}
