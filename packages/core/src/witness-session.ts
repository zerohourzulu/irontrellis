/**
 * The witness session of one history store (docs/WITNESS.md §2, §5, §7): the
 * policy in force, what this process knows of each remote witness's latest
 * head, the submission queue and worker, the sticky alarms, and the remote part
 * of verification. The store owns one session per instance (formats 1
 * and 2) and calls its guards on every read and write.
 *
 * The security argument (docs/WITNESS.md §2) rests on two rules the session enforces:
 *  - W1 is the witness's: it accepts a head statement only when its `previous`
 *    is the witness's latest head for the history;
 *  - W2 is ours: a statement for head h with `previous = p` is signed only
 *    after `p` was obtained from the witness in this process (or is a head
 *    this process got accepted) AND found to be a prefix of the local history
 *    (`eventHistoryHashes[p.position] === p.hash`). A witness latest that is
 *    not a prefix puts the session into a sticky alarm: every later read and
 *    write of the store throws ROLLBACK_DETECTED (reason WITNESS_AHEAD or
 *    WITNESS_FORK), and no statement is ever signed for that branch. A 409
 *    EQUIVOCATION answer to one of our statements (docs/reference/witness-protocol.md §9.2 rule 4:
 *    the witness holds another head at that position) is the same finding, WITNESS_FORK: this
 *    handle's file left the witness chain. The witness itself stays open, so
 *    a copy that is on its chain (a restored backup) can be written again.
 *
 * W2 is evaluated under the store's writer lock against ONE replayed state
 * (docs/WITNESS.md §2): the prefix check of `previous`, the target head and
 * the signature all come from the state read under the lock, and that state
 * must still contain the head this handle last appended or verified under the
 * lock; a file that no longer does was changed under the writer (sticky
 * ROLLBACK_DETECTED, reason FILE_CHANGED_UNDER_WRITER; nothing is signed).
 *
 * Nothing on disk can relax this. The side file (`witness-state.ts`) only adds
 * findings; witnesses bound in the history itself (owner-signed
 * `WITNESSES_BOUND` / `WITNESSES_UNBOUND` control events, validated and applied
 * by replay) stay in force whatever the side file says, and so do the witnesses of
 * an out-of-band policy file named by `IRONTRELLIS_WITNESS_POLICY` (a minimum
 * the side file cannot lower). See witness-state.ts. A bound witness is pinned:
 * its URL, verifier key and `allowInsecureHttp` come from the binding only (the
 * side file may add a registration token), and the binding carries an
 * owner-signed policy minimum (quorum, requireOnOpen, maxUnwitnessedEvents).
 * Every check needs its answers from each trusted set on its own: the bound
 * witnesses (n - q + 1 with the bound quorum), the out-of-band minimum's, and
 * the whole policy; an answer from a witness only the side file names never
 * stands in for a bound witness's. The only way to drop a
 * witness that shows a rollback is an owner-signed unbinding that accepts the
 * loss (`acceptLoss`, docs/reference/witness-operations.md §6.2): the owner key, never a file.
 *
 * Two witness states refuse owner-keyed writes without being rollback
 * evidence: a witness that refused to register the history (WITNESS_REJECTED,
 * sticky until the policy for it changes), and a witness that answers "not
 * registered" although the history binds it with a REGISTERED receipt it
 * signed (a denial of its own signature: data loss at the witness or an
 * attacker in the path; verify fails REMOTE_WITNESS_INVALID).
 *
 * Statements are signed when they are submitted, never earlier, so the
 * `previous` they carry is always a verified, current witness answer; the
 * single exception is the statement for a rotation head (docs/WITNESS.md §7), signed inside
 * `rotateOwnerKey` while the old key is still held, and kept in the side file
 * until submitted (a crash before that is recovered from the archived key file).
 */
import { existsSync } from "node:fs";
import { EngineError } from "./errors.ts";
import { isTrellis } from "./events.ts";
import { MAX_UNWITNESSED_EXEMPT_TYPES } from "./types.ts";
import { loadOwnerKeyFile, ownerKeyPathFor, retiredOwnerKeyFilesFor, type Signer } from "./signer.ts";
import { verifyWitnessReceipt, type WitnessReceipt } from "./transparency/receipt.ts";
import { ownerKeyInForce, ownerKeyRotationCounts, ownerKeysAt } from "./owner-keys.ts";
import { HEAD_STATEMENT_VERSION, signHeadStatement, verifySignedHeadStatement, type SignedHeadStatement, type StatementHead } from "./transparency/statement.ts";
import type { BoundPolicy, CanonicalEvent, ContentHash, EventType, HistoryHead, OwnerKeyEpoch, ReplayState, U53 } from "./types.ts";
import {
  DEFAULT_MAX_UNWITNESSED_EVENTS, MAX_REMOTE_WITNESSES, normalizeWitnessConfig, normalizeWitnessPolicy, remoteWitness, type CheckpointTracker, type RemoteWitness,
  type RemoteWitnessConfig, type RemoteWitnessedHead, type ResolvedWitnessPolicy, type WitnessFetch, type WitnessHistoryInfo, type WitnessPolicy,
} from "./witness-client.ts";
import { judgePendingRotation, pendingRotationKeysMissing, pendingRotationPathFor, readPendingRotation, removePendingRotation, type PendingRotationRecord } from "./rotation-pending.ts";
import {
  cachedLatestIsSealed, minimumWitnessPolicy, readWitnessState, sealCachedLatest, sealCachedLatestAsync, storedPolicyOf, updateWitnessState, witnessConfigFingerprint, witnessStatePathFor,
  type CachedLatest, type MinimumWitnessPolicy, type SealedWitness, type PendingItem, type PendingStatement, type StoredPolicy, type StoredWitnessConfig, type WitnessStateDoc,
} from "./witness-state.ts";

/** Which binding event `witnessBindingEvent` builds: `BIND` → `WITNESSES_BOUND`, `UNBIND` → `WITNESSES_UNBOUND`. */
export type WitnessBindingAction = "BIND" | "UNBIND";

/** How the store lends itself to its session. `state()` syncs with the file and throws on file problems, never on witness findings. */
export type WitnessHost = Readonly<{
  path: string;
  state(): ReplayState | undefined;
  signer(): Signer | undefined;
  /**
   * Runs `critical` holding the store's writer lock (waiting briefly while another writer holds it), with the state
   * synced from the file under that lock. Head statements are signed only in here (docs/WITNESS.md §2).
   */
  locked<T>(critical: (state: ReplayState | undefined) => T | Promise<T>): Promise<T>;
  /**
   * Appends the OUTSTANDING prepared rotation `record` (docs/reference/witness-operations.md §7.1) under the writer lock, through the normal
   * validated append and without a new owner attestation of the pinned head, when the file's head is still its
   * `previousHead`; resolves to the new head, or `undefined` when the record is no longer OUTSTANDING there.
   */
  completePending(record: PendingRotationRecord): Promise<HistoryHead | undefined>;
  /** Inspect-only stores never guard, write or submit. */
  inspect: boolean;
}>;

/** One remote witness as `verify` judged it. */
export type RemoteWitnessReport = Readonly<{
  url: string;
  name: string;
  verifierKey: string;
  origin?: string;
  /** Bound in the history (an owner-signed binding), not only configured. */
  bound: boolean;
  status: "OK" | "ROLLBACK" | "SPLIT_VIEW" | "INVALID" | "UNREACHABLE" | "UNREGISTERED";
  /** `OK` because the witness's latest head is the head of the outstanding prepared rotation (docs/reference/witness-operations.md §7.1), not yet in the file. */
  rotationPending?: true;
  /** `INVALID` because the witness answered "not registered" although the history binds it with a REGISTERED receipt it signed. */
  registrationDenied?: boolean;
  latest?: StatementHead | null;
  /**
   * Conflicting owner-signed statements the witness recorded for this history
   * (EQUIVOCATION entries, docs/reference/witness-operations.md; evidence only, not a verify failure): the
   * owner key signed a head that conflicts with one the witness holds.
   */
  equivocations?: number;
  /** The newest of them: its leaf index, the position both heads claim, and when the witness received it. */
  lastEquivocation?: Readonly<{ index: number; position: number; receivedAt: number }>;
  /**
   * SUPERSEDED entries the witness recorded for this history (docs/reference/witness-operations.md §7.4): a pre-rotated rotation overrode
   * heads an owner key signed after the last good head (see `SUPERSEDE_WARNING`).
   */
  supersedes?: number;
  /** The newest of them: its leaf index, the position of the last good head it resumed from, and how many heads it overrode. */
  lastSupersede?: Readonly<{ index: number; from: number; heads: number; receivedAt: number }>;
  /** Positions of the history's owner key rotations (commitment-only ones included) this witness has not recorded. */
  pendingRotationPositions?: readonly number[];
  receiptVerified: boolean;
  consistent: boolean;
  checkpointSize?: number;
  unwitnessedTail?: number;
  error?: Readonly<{ code: string; message: string }>;
}>;
export type RemoteWitnessStatus = "OK" | "ROLLBACK" | "SPLIT_VIEW" | "INVALID" | "UNREACHABLE" | "NOT_CONSULTED";

/** What `REMOTE_WITNESS_EQUIVOCATION_RECORDED` means for the operator (the CLI prints it as a warning). */
export const EQUIVOCATION_WARNING = "the owner key signed a conflicting head; if you did not restore or roll back this history, treat the owner key as compromised and rotate it";
/** What `REMOTE_WITNESS_SUPERSEDED` means for the operator (docs/reference/witness-operations.md §7.4; the CLI prints it as a warning). */
export const SUPERSEDE_WARNING = "an owner key signed heads that a later pre-rotated rotation overrode; the old key was probably compromised";
/** The recommendation `verify` and `witness status` make while the owner keys in force have no next-key commitment (docs/SECURITY.md §2.1). */
export const NO_COMMITMENT_WARNING = "the owner keys in force have no next-key commitment: a leaked current key can still rotate, and a witness that has not recorded a rotation still accepts heads signed by the retired key; commit a next key (irontrellis owner commit-next-key, a rotation that keeps the owner keys) and keep it off this host";
export type RemoteFindings = Readonly<{ failures: readonly string[]; notes: readonly string[]; witnesses: readonly RemoteWitnessReport[]; status: RemoteWitnessStatus }>;

/** Local knowledge of the session, without network (`witness status`). */
export type WitnessStatusReport = Readonly<{
  statePath: string;
  historyId?: ContentHash;
  policy: StoredPolicy;
  /** The owner-signed bindings the history carries. */
  bound: readonly StoredWitnessConfig[];
  /** The owner-signed policy minimum of the newest binding (docs/reference/witness-policy.md §5.3), when the history carries one. */
  boundPolicy?: BoundPolicy;
  alarm?: Readonly<{ code: string; message: string; reason?: string }>;
  /**
   * A witness refused to register the history (401 UNAUTHORIZED, 400 INVALID_GENESIS / UNSUPPORTED_FORMAT, …):
   * owner-keyed writes refuse with WITNESS_REJECTED until the policy for that witness changes.
   */
  rejected?: Readonly<{ url: string; code: string; message: string }>;
  /** The out-of-band minimum policy file (`IRONTRELLIS_WITNESS_POLICY`), when one is in force. */
  minimumPolicyFile?: string;
  /**
   * The history's `OWNER_KEYS_ROTATED` events: those that changed the owner keys and the commitment-only ones. A witness
   * records each (a ROTATED leaf); each needs the retired key once per witness that has not recorded it.
   */
  keyRotations: number;
  commitmentRotations: number;
  /**
   * "Rotation incomplete" (docs/reference/witness-operations.md §7.1): a bound witness this process asked has not recorded an owner key rotation
   * the history holds, or a rotation is still queued for a witness. Until every witness records it, a witness that lacks
   * it still accepts head statements signed by the retired key.
   */
  rotationIncomplete: boolean;
  /** A prepared two-phase rotation (`<history>.rotation.pending.json`) is outstanding: writes wait until an owner process completes or discards it. */
  rotationPending?: Readonly<{ position: number; hash: ContentHash; eventId: string }>;
  /** `requireOnOpen` and not yet confirmed: reads throw WITNESS_UNAVAILABLE until `checkWitnesses()`. */
  checkRequired: boolean;
  /** This store can sign head statements (an owner key in force). */
  ownerKeyed: boolean;
  head?: HistoryHead;
  /** The highest position a quorum of witnesses is known to hold (0: registration only), `null` when unknown. */
  witnessedPosition: number | null;
  unwitnessedEvents: number;
  pending: readonly PendingItem[];
  witnesses: readonly Readonly<{
    url: string; name: string; verifierKey: string; origin?: string; bound: boolean; registered: boolean;
    latest?: StatementHead | null; source: "network" | "sealed-cache" | "unsealed-cache" | "none"; knownAt?: number;
    /** Equivocations the witness counted for this history when this process last asked it. */
    equivocations?: number;
    /**
     * Owner key rotations of the history (commitment-only ones included) this witness has not recorded yet, as this
     * process last learned (`null`: not asked in this process). Until it is 0 for every witness bound to the history,
     * keep the retired key files: the statement for each rotation head must be signed with the key that rotation retired.
     */
    pendingRotations: number | null;
    /** SUPERSEDED entries the witness counted for this history when this process last asked it. */
    supersedes?: number;
    /** The witness refused to register the history (sticky until the policy for it changes). */
    rejected?: Readonly<{ code: string; message: string }>;
    /** The witness answered "not registered" although the history binds it with a REGISTERED receipt it signed. */
    registrationDenied?: Readonly<{ code: string; message: string }>;
    /**
     * The history binds this witness without its signed REGISTERED receipt (bound while unreachable): its "not
     * registered" answers are unsigned and count as unreachable, and there is no sealed-cache shortcut for it. Run
     * `witness add` again while it is reachable to record the receipt.
     */
    bindingWithoutReceipt?: true;
    checkpointSize?: number; splitView?: string; lastError?: Readonly<{ code: string; message: string }>;
  }>[];
}>;
export type WitnessView = Readonly<{ consulted: number; required: number; witnesses: WitnessStatusReport["witnesses"] }>;

type Known = { head: StatementHead | null; at: number };
/** A head the witness held on its chain, with its verified HEAD receipt: the last good head (L) a supersede resumes from. */
type Held = Readonly<{ head: StatementHead; receipt: WitnessReceipt }>;
type Runtime = {
  config: RemoteWitnessConfig;
  client: RemoteWitness;
  /** Learned in this process from the witness (verified) or from our own accepted submissions. */
  known?: Known;
  epochs?: readonly OwnerKeyEpoch[];
  registered: boolean;
  /** The witness's equivocation count for this history, as last verified in this process. */
  equivocations?: number;
  /** The witness's supersede count for this history, as last verified in this process. */
  supersedes?: number;
  /** The newest head the witness was verified to hold that was a prefix of the local history (a candidate L for a supersede). */
  held?: Held;
  /** Why the last automatic supersede against this witness was not possible (named in the rollback alarm). */
  supersedeFailure?: string | undefined;
  lastError?: EngineError | undefined;
  /** WITNESS_REJECTED: the witness refused to register the history. Sticky for this runtime (a changed config makes a new one). */
  rejected?: EngineError;
  /** The witness's last answer denied a registration the history holds its signed receipt for (cleared by an answer that knows the history). */
  denied?: EngineError | undefined;
};
/** What `acceptLoss` removed, to put back when the unbinding write fails. */
export type AcceptedLoss = Readonly<{ keys: readonly string[]; alarms: readonly (readonly [string, EngineError])[]; runtimes: readonly Runtime[] }>;
/** A witness's evidence that this copy lacks a head it holds: what an accepted loss records. */
export type LossEvidence = Readonly<{ url: string; verifierKey: string; head: StatementHead; reason: "WITNESS_AHEAD" | "WITNESS_FORK" }>;

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const messageOf = (error: unknown): string => (error instanceof Error ? error.message : String(error));
const codeOf = (error: unknown): string => (error instanceof EngineError ? error.code : "WITNESS_UNAVAILABLE");
const errorView = (error: EngineError | undefined): Readonly<{ code: string; message: string }> | undefined =>
  error === undefined ? undefined : Object.freeze({ code: error.code, message: error.message });

const headAt = (state: ReplayState, position: number): StatementHead => Object.freeze({
  hash: state.eventHistoryHashes[position]!, position, canonicalTime: state.events[position]!.timestamp,
});
const isPrefix = (head: Readonly<{ hash: string; position: number }>, state: ReplayState): boolean =>
  head.position <= state.head.position && state.eventHistoryHashes[head.position] === head.hash;
const sameHead = (a: Readonly<{ hash: string; position: number }> | null | undefined, b: Readonly<{ hash: string; position: number }> | null | undefined): boolean =>
  (a === null || a === undefined) ? (b === null || b === undefined) : (b !== null && b !== undefined && a.hash === b.hash && a.position === b.position);
/**
 * The seal an entry already carries for exactly this answer (same head, same fetch time): kept when this process does not
 * seal it again (an asynchronous signer outside a submission round), so a reader never strips a writer's seal. A kept
 * seal is still checked by every reader against the witness it names (`cachedLatestIsSealed`).
 */
const keptSeal = (latest: CachedLatest | undefined, known: Readonly<{ head: StatementHead | null; at: number }>): Readonly<{ seal?: NonNullable<CachedLatest["seal"]> }> => {
  if (latest?.seal === undefined || latest.fetchedAt !== known.at) return {};
  const same = latest.head === null ? known.head === null : known.head !== null && sameHead(latest.head, known.head) && latest.head.canonicalTime === known.head.canonicalTime;
  return same ? { seal: latest.seal } : {};
};
const describeHead = (head: Readonly<{ position: number }> | null): string => (head === null ? "none" : `position ${head.position}`);

/**
 * The owner key rotations of a format-1 history in order (the only owner key events: a commitment-only rotation
 * included; epoch 0's commitment is part of the genesis, which every witness registers). The rotation at `r` opens the
 * epoch from `r + 1`; `rotationHead` is the head ending with it (the key-event route's `eventHead`).
 */
type LocalRotation = Readonly<{ r: number; event: CanonicalEvent; previousHead: Readonly<{ hash: ContentHash; position: U53 }>; rotationHead: Readonly<{ hash: ContentHash; position: U53 }> }>;
const localRotations = (state: ReplayState): readonly LocalRotation[] =>
  state.ownerKeyEpochs.slice(1).map((epoch) => {
    const r = epoch.fromPosition - 1;
    return Object.freeze({
      r, event: state.events[r]!, previousHead: Object.freeze({ hash: state.eventHistoryHashes[r - 1]!, position: r - 1 }),
      rotationHead: Object.freeze({ hash: state.eventHistoryHashes[r]!, position: r }),
    });
  });

/** Whether a witness with `epochs` has recorded the rotation at `r` (it knows the epoch from `r + 1`). */
const recordedBy = (epochs: readonly OwnerKeyEpoch[], rotation: LocalRotation): boolean => epochs.some((epoch) => epoch.fromPosition === rotation.r + 1);
/** The local epoch whose keys are in force at `position`. */
const epochAt = (state: ReplayState, position: number): OwnerKeyEpoch | undefined => {
  let found: OwnerKeyEpoch | undefined;
  for (const epoch of state.ownerKeyEpochs) if (epoch.fromPosition <= position) found = epoch;
  return found;
};

// ---------------------------------------------------------------- bindings recorded in the history

/** A witness as a binding names it; a BIND may carry the witness's signed REGISTERED receipt for this history. */
export type BindingWitness = StoredWitnessConfig & Readonly<{ registration?: WitnessReceipt }>;
/**
 * The policy minimum a binding records, signed by the owner with it (docs/reference/witness-policy.md §5.3): the newest binding event's
 * is in force. `quorum` applies to the bound witnesses (a check needs `bound - quorum + 1` of them); no side file, caller
 * option or out-of-band policy can lower it or make a bound witness optional.
 */
export type { BoundPolicy };

/** A binding's policy record, or `undefined` when it is not a valid one. */
const boundPolicyFrom = (value: unknown): BoundPolicy | undefined => {
  if (!isRecord(value)) return undefined;
  const { quorum, requireOnOpen, maxUnwitnessedEvents } = value;
  if (typeof quorum !== "number" || !Number.isSafeInteger(quorum) || quorum < 1 || quorum > MAX_REMOTE_WITNESSES) return undefined;
  if (typeof requireOnOpen !== "boolean") return undefined;
  if (typeof maxUnwitnessedEvents !== "number" || !Number.isSafeInteger(maxUnwitnessedEvents) || maxUnwitnessedEvents < 1) return undefined;
  return Object.freeze({ quorum, requireOnOpen, maxUnwitnessedEvents });
};

/** The policy minimum a binding records for a resolved policy: its quorum capped at the bound witnesses, its requireOnOpen and maxUnwitnessedEvents. */
export function bindingPolicyOf(policy: Readonly<{ quorum?: number; requireOnOpen?: boolean; maxUnwitnessedEvents?: number }> | undefined, boundCount: number): BoundPolicy {
  return Object.freeze({
    quorum: Math.max(1, Math.min(policy?.quorum ?? 1, Math.max(1, boundCount))),
    requireOnOpen: policy?.requireOnOpen === true,
    maxUnwitnessedEvents: policy?.maxUnwitnessedEvents ?? DEFAULT_MAX_UNWITNESSED_EVENTS,
  });
}
/** An UNBIND that accepts that the witnesses hold heads no surviving copy contains (docs/reference/witness-operations.md §6.2). */
export type AcceptedLossRecord = Readonly<{ reason: string; heads: readonly Readonly<{ verifierKey: string; head: StatementHead }>[] }>;

/**
 * The owner-signed control event that binds (`WITNESSES_BOUND`) or unbinds (`WITNESSES_UNBOUND`) remote witnesses,
 * unsigned. BIND: `{ witnesses: [{ url, verifierKey, name?, allowInsecureHttp?, registration? }], policy }`; UNBIND:
 * `{ verifierKeys, policy, acceptedLoss? }`. `policy` (`BoundPolicy`) is the owner-signed policy minimum in force after
 * the event. `registration` (BIND) is the witness's own signed receipt of the REGISTERED leaf of this history, so a later
 * "not registered" answer from it contradicts its signature; `acceptedLoss` (UNBIND) records the owner's reason and the
 * heads the removed witnesses hold that this copy lacks. Replay validates every field (a closed schema, the receipt
 * against the witness key and this genesis, the loss heads against the history, the quorum against the bound
 * witnesses), so a binding cannot be forged, edited or removed by editing files, and nothing else (an anchor receipt
 * in particular) can bind or unbind a witness.
 */
export function witnessBindingEvent(input: Readonly<{
  action: WitnessBindingAction; witnesses: readonly BindingWitness[]; policy: BoundPolicy; acceptedLoss?: AcceptedLossRecord;
}>): Readonly<{ type: EventType; data: Readonly<Record<string, unknown>> }> {
  const policy = boundPolicyFrom(input.policy);
  if (policy === undefined) throw new EngineError("INVALID_INPUT", "a binding policy is { quorum: 1..16, requireOnOpen: boolean, maxUnwitnessedEvents: >= 1 }");
  const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
  const signedPolicy = Object.freeze({ quorum: policy.quorum, requireOnOpen: policy.requireOnOpen, maxUnwitnessedEvents: policy.maxUnwitnessedEvents });
  if (input.action === "BIND") {
    if (input.acceptedLoss !== undefined) throw new EngineError("INVALID_INPUT", "only an unbinding records an accepted loss");
    return Object.freeze({
      type: "WITNESSES_BOUND" as const,
      data: Object.freeze({
        witnesses: Object.freeze(input.witnesses.map((w) => Object.freeze({
          url: w.url, verifierKey: w.verifierKey, ...(w.name === undefined ? {} : { name: w.name }), ...(w.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}),
          ...(w.registration === undefined ? {} : { registration: copy(w.registration) }),
        }))),
        policy: signedPolicy,
      }),
    });
  }
  return Object.freeze({
    type: "WITNESSES_UNBOUND" as const,
    data: Object.freeze({
      verifierKeys: Object.freeze(input.witnesses.map((w) => w.verifierKey)), policy: signedPolicy,
      ...(input.acceptedLoss === undefined ? {} : {
        acceptedLoss: Object.freeze({
          reason: input.acceptedLoss.reason,
          heads: Object.freeze(input.acceptedLoss.heads.map((h) => Object.freeze({ verifierKey: h.verifierKey, head: Object.freeze({ hash: h.head.hash, position: h.head.position, canonicalTime: h.head.canonicalTime }) }))),
        }),
      }),
    }),
  });
}

/** The owner-signed policy minimum in force: the policy of the newest binding event (`undefined`: the history binds none yet). */
export function boundPolicyOf(state: ReplayState): BoundPolicy | undefined {
  return state.boundPolicy;
}

/** The witnesses the history binds, in binding order (replay applies every WITNESSES_BOUND / WITNESSES_UNBOUND in turn). */
export function boundWitnessesOf(state: ReplayState): readonly StoredWitnessConfig[] {
  return Object.freeze(state.boundWitnesses.map((b) => Object.freeze({
    url: b.url, verifierKey: b.verifierKey, ...(b.name === undefined ? {} : { name: b.name }), ...(b.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}),
  })));
}

/**
 * The REGISTERED receipt the history holds for a witness it binds: the one in the binding in force for `verifierKey`
 * (replay verified it with that key against exactly this history's genesis). `undefined` when the witness is not
 * bound, or was bound without one (added while unreachable).
 */
export function boundRegistrationOf(state: ReplayState, verifierKey: string): Readonly<{ receipt: WitnessReceipt; index: number }> | undefined {
  if (!isTrellis(state.format)) return undefined;
  return state.boundWitnesses.find((b) => b.verifierKey === verifierKey)?.registration;
}

// ---------------------------------------------------------------- statements for a replayed history

/**
 * Signs the head statement for the current head of `state` with `previous`
 * (docs/WITNESS.md §2, §9.1), enforcing rule W2 first: `previous` is null or a
 * prefix of the history (`eventHistoryHashes[previous.position] === previous.hash`),
 * and the signer's key is an owner key in force at the head's position.
 * Throws INVALID_INPUT / KEY_UNAVAILABLE otherwise.
 */
export async function signStatement(signer: Signer, state: ReplayState, previous: Readonly<{ hash: ContentHash; position: U53 }> | null): Promise<SignedHeadStatement> {
  if (!isTrellis(state.format)) throw new EngineError("INVALID_INPUT", "head statements need a format-1 history");
  if (previous !== null && !isPrefix(previous, state)) throw new EngineError("INVALID_INPUT", `previous (position ${previous.position}) is not a prefix of this history: rule W2 forbids signing`);
  if (!ownerKeyInForce(state, state.head.position, signer)) throw new EngineError("KEY_UNAVAILABLE", `owner key ${signer.keyId} is not in force at position ${state.head.position}`);
  return signHeadStatement(signer, Object.freeze({
    version: HEAD_STATEMENT_VERSION, historyId: state.eventHistoryHashes[0]!, domain: state.genesis.domain as never, head: headAt(state, state.head.position),
    previous: previous === null ? null : Object.freeze({ hash: previous.hash, position: previous.position }),
  }));
}

/** True iff `signed` is a statement for this history, its head is a prefix of it, and it is signed by an owner key in force at the head's position. */
export function verifySignedStatement(signed: unknown, state: ReplayState): boolean {
  if (!isTrellis(state.format) || !verifySignedHeadStatement(signed, (position) => ownerKeysAt(state, position)).ok) return false;
  const statement = (signed as SignedHeadStatement).statement;
  return statement.historyId === state.eventHistoryHashes[0] && isPrefix(statement.head, state) && state.events[statement.head.position]?.timestamp === statement.head.canonicalTime;
}

// ---------------------------------------------------------------- errors

const rollback = (path: string, reason: "WITNESS_AHEAD" | "WITNESS_FORK" | "FILE_CHANGED_UNDER_WRITER", message: string, detail: Record<string, unknown>): EngineError =>
  new EngineError("ROLLBACK_DETECTED", `history ${path}: ${message}`, { reason, ...detail });

const unavailable = (message: string, detail: Record<string, unknown> = {}): EngineError => new EngineError("WITNESS_UNAVAILABLE", message, detail);

// ---------------------------------------------------------------- the session

/**
 * What this process learned from the witnesses, per history (side file path +
 * history id) and witness (verifier key): shared by every store instance of the
 * process, so a handle opened later (a per-call execution handle, a second
 * owner handle) starts from verified knowledge. Memory is trusted; the side
 * file is not.
 */
const PROCESS_VIEWS = new Map<string, Map<string, Known>>();
/** The key of the FILE_CHANGED_UNDER_WRITER alarm among the per-witness alarms (never a verifier key). */
const FILE_ALARM = "\u0000file";
/** Forgets what this process learned from the witnesses (tests that simulate a fresh process; not exported from the package root). */
export function resetWitnessViews(): void {
  PROCESS_VIEWS.clear();
}

export type SessionOptions = Readonly<{ explicit?: WitnessPolicy | false }>;

export class WitnessSession {
  readonly #host: WitnessHost;
  readonly #statePath: string;
  readonly #explicit: ResolvedWitnessPolicy | undefined;
  readonly #disabled: boolean;
  /** The out-of-band minimum (`IRONTRELLIS_WITNESS_POLICY`), read once at open. */
  readonly #minimum: MinimumWitnessPolicy | undefined;
  #policy: ResolvedWitnessPolicy | undefined;
  /** The policy without the out-of-band minimum: what `addWitness` / `removeWitness` edit in the side file. */
  #editable: ResolvedWitnessPolicy | undefined;
  #stored: StoredPolicy | undefined;
  #runtimes: Runtime[] = [];
  #doc: WitnessStateDoc | undefined;
  /**
   * Sticky, per witness (verifier key), in the order found: a verified witness showed a rollback, a fork or a split view
   * in this process. The first one is what reads and writes throw; `acceptLoss` removes only the accepted witnesses' entries.
   */
  readonly #alarms = new Map<string, EngineError>();
  /** Witnesses whose loss this handle accepted (`acceptLoss`): left out of the policy for its lifetime. */
  readonly #excluded = new Set<string>();
  /** `requireOnOpen` and not confirmed yet. */
  #pendingOpen: EngineError | undefined;
  #openChecked = false;
  /** A network view before the first owner write of this process was attempted. */
  #writeChecked = false;
  /**
   * The trusted sets a check needs answers from, each on its own (docs/reference/witness-policy.md §5.3): every witness of the policy
   * (`n - quorum + 1`), the bound witnesses (with the bound quorum) and the out-of-band minimum's witnesses (with its quorum).
   */
  #groups: readonly Readonly<{ name: "policy" | "bound" | "minimum"; keys: ReadonlySet<string>; quorum: number }>[] = [];
  #boundPolicy: BoundPolicy | undefined;
  /** The head this handle last appended, or verified under the writer lock: every later locked read must still contain it (docs/WITNESS.md §2). */
  #trusted: Readonly<{ hash: ContentHash; position: number }> | undefined;
  /** One locked section of this session at a time. */
  #lockChain: Promise<void> = Promise.resolve();
  /** Locked sections queued or running (each may hold the store's writer lock across an asynchronous signature). */
  #sections = 0;
  /** Old-key signers held from a rotation in this process (docs/WITNESS.md §7), newest last. */
  #retained: Signer[] = [];
  #sealing: Promise<void> = Promise.resolve();
  #round: Promise<void> = Promise.resolve();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #working = false;
  #dirty = false;
  #failures = 0;
  #lastError: EngineError | undefined;
  #fetch: WitnessFetch | undefined;
  #closed = false;
  /** `<history>.rotation.pending.json` (docs/reference/witness-operations.md §7.1). */
  readonly #pendingPath: string;
  /** Appends of the prepared rotation itself are in progress (its commit or its recovery): the ROTATION_PENDING guard lets them through. */
  #pendingAllowed = 0;
  /** Bound witnesses that accepted the prepared rotation in `deliverPreparedRotation`, learned once it is in the file. */
  #delivered: { runtime: Runtime; epochs: readonly OwnerKeyEpoch[]; latest: RemoteWitnessedHead }[] = [];
  /** Settles when this process's two-phase rotation has appended (or abandoned) its prepared rotation. */
  #preparing: Promise<void> | undefined;

  constructor(host: WitnessHost, options: SessionOptions) {
    this.#host = host;
    this.#statePath = witnessStatePathFor(host.path);
    this.#pendingPath = pendingRotationPathFor(host.path);
    this.#disabled = options.explicit === false;
    let explicit: ResolvedWitnessPolicy | undefined;
    if (options.explicit !== undefined && options.explicit !== false) explicit = normalizeWitnessPolicy(options.explicit);
    this.#explicit = explicit;
    this.#fetch = explicit?.fetch;
    // `witness: false` is the caller's own choice (inspection); every other open takes the operator's minimum.
    this.#minimum = this.#disabled ? undefined : minimumWitnessPolicy();
    this.#load();
  }

  /** The first alarm of this handle (what every read and write throws). */
  get #alarm(): EngineError | undefined {
    for (const alarm of this.#alarms.values()) return alarm;
    return undefined;
  }
  /** Records `error` as `runtime`'s alarm (the first one per witness stays) and returns the handle's first alarm. */
  #raise(runtime: Runtime, error: EngineError): EngineError {
    if (!this.#alarms.has(runtime.config.verifierKey)) this.#alarms.set(runtime.config.verifierKey, error);
    return this.#alarm!;
  }
  #isAlarm(error: unknown): boolean {
    return error instanceof EngineError && [...this.#alarms.values()].includes(error);
  }

  // ---- policy and knowledge

  /**
   * (Re)reads the side file and the history's bindings, merges the
   * out-of-band minimum, and keeps what this process learned for witnesses
   * that stay (a witness whose config changed, e.g. a new token, starts afresh).
   */
  #load(): void {
    const off = (): void => { this.#policy = undefined; this.#editable = undefined; this.#runtimes = []; this.#groups = []; this.#boundPolicy = undefined; };
    if (this.#disabled) { off(); return; }
    let state: ReplayState | undefined;
    try { state = this.#host.state(); } catch { state = undefined; }
    if (state !== undefined && !isTrellis(state.format)) { off(); return; }
    // A malformed side file fails the open (it may hide evidence); an absent one is empty.
    const doc = readWitnessState(this.#statePath);
    const historyId = state?.eventHistoryHashes[0];
    this.#doc = historyId !== undefined && doc.historyId !== undefined && doc.historyId !== historyId
      ? Object.freeze({ ...doc, witnesses: Object.freeze({}), pending: Object.freeze([]) }) : doc;
    const base = this.#explicit ?? (doc.policy === undefined ? undefined : normalizeWitnessPolicy(doc.policy));
    const fromCaller = this.#explicit !== undefined;
    const keep = (w: Readonly<{ verifierKey: string }>): boolean => !this.#excluded.has(w.verifierKey);
    const minimum = this.#minimum;
    const boundPolicy = state === undefined ? undefined : boundPolicyOf(state);
    // A bound witness is pinned (docs/reference/witness-policy.md §5.3): url, verifier key and allowInsecureHttp from the binding ONLY. The side
    // file may add a registration token (and a display name); the caller's own options also a timeout and a transport; the
    // operator's out-of-band minimum a token and a timeout. A binding no config can be made from is skipped (owner code never writes one).
    const pinned = new Map<string, RemoteWitnessConfig>();
    for (const b of state === undefined ? [] : boundWitnessesOf(state)) {
      if (!keep(b)) continue;
      const given = base?.witnesses.find((w) => w.verifierKey === b.verifierKey), operator = minimum?.witnesses.find((w) => w.verifierKey === b.verifierKey);
      const token = operator?.token ?? given?.token, name = b.name ?? given?.name, timeoutMs = operator?.timeoutMs ?? (fromCaller ? given?.timeoutMs : undefined);
      try {
        pinned.set(b.verifierKey, normalizeWitnessConfig({
          url: b.url, verifierKey: b.verifierKey, ...(b.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}), ...(name === undefined ? {} : { name }),
          ...(token === undefined ? {} : { token }), ...(timeoutMs === undefined ? {} : { timeoutMs }), ...(fromCaller && given?.fetch !== undefined ? { fetch: given.fetch } : {}),
        }));
      } catch { /* not a usable witness config */ }
    }
    const witnesses: RemoteWitnessConfig[] = [];
    for (const w of base?.witnesses ?? []) if (keep(w)) witnesses.push(pinned.get(w.verifierKey) ?? w);
    for (const [key, config] of pinned) if (!witnesses.some((w) => w.verifierKey === key)) witnesses.push(config);
    const transport = this.#fetch === undefined ? {} : { fetch: this.#fetch };
    const editable = witnesses.length === 0 ? undefined : normalizeWitnessPolicy({
      witnesses, quorum: Math.min(base?.quorum ?? 1, witnesses.length), mode: base?.mode ?? "async", maxUnwitnessedEvents: base?.maxUnwitnessedEvents,
      requireOnOpen: base?.requireOnOpen ?? false, cacheMs: base?.cacheMs, ...transport,
    });
    // The minimum adds its witnesses (its spelling of one the policy already has wins, except a bound one: pinned) and only raises requirements.
    const merged: RemoteWitnessConfig[] = [...witnesses];
    for (const m of minimum?.witnesses ?? []) {
      const at = merged.findIndex((w) => w.verifierKey === m.verifierKey);
      if (at < 0) merged.push(m);
      else if (!pinned.has(m.verifierKey)) merged[at] = m;
    }
    this.#editable = editable;
    this.#boundPolicy = boundPolicy;
    if (merged.length === 0) { this.#policy = undefined; this.#stored = undefined; this.#runtimes = []; this.#groups = []; return; }
    const lowest = (...values: (number | undefined)[]): number | undefined => {
      const given = values.filter((value): value is number => value !== undefined);
      return given.length === 0 ? undefined : Math.min(...given);
    };
    // The strictest of the binding, the out-of-band minimum, the side file and the caller's options. (A larger quorum is
    // stricter about what counts as witnessed; which answers a check needs is decided per trusted set, `#groups`.)
    const policy = normalizeWitnessPolicy({
      witnesses: merged, quorum: Math.min(Math.max(editable?.quorum ?? 1, minimum?.quorum ?? 1, boundPolicy?.quorum ?? 1), merged.length),
      mode: editable?.mode === "sync" || minimum?.mode === "sync" ? "sync" : "async",
      maxUnwitnessedEvents: lowest(editable?.maxUnwitnessedEvents, minimum?.maxUnwitnessedEvents, boundPolicy?.maxUnwitnessedEvents),
      requireOnOpen: editable?.requireOnOpen === true || minimum?.requireOnOpen === true || boundPolicy?.requireOnOpen === true,
      cacheMs: lowest(editable?.cacheMs, minimum?.cacheMs), ...transport,
    });
    this.#policy = policy;
    this.#stored = storedPolicyOf(policy);
    const groups: { name: "policy" | "bound" | "minimum"; keys: ReadonlySet<string>; quorum: number }[] = [
      { name: "policy", keys: new Set(merged.map((w) => w.verifierKey)), quorum: policy.quorum },
    ];
    if (pinned.size > 0) groups.push({ name: "bound", keys: new Set(pinned.keys()), quorum: Math.min(boundPolicy?.quorum ?? 1, pinned.size) });
    const operatorKeys = new Set((minimum?.witnesses ?? []).map((w) => w.verifierKey).filter((key) => merged.some((w) => w.verifierKey === key)));
    if (operatorKeys.size > 0) groups.push({ name: "minimum", keys: operatorKeys, quorum: Math.min(minimum?.quorum ?? 1, operatorKeys.size) });
    this.#groups = Object.freeze(groups.map((group) => Object.freeze(group)));
    const previous = this.#runtimes;
    this.#runtimes = policy.witnesses.map((config) => {
      const kept = previous.find((runtime) => runtime.config.verifierKey === config.verifierKey && runtime.config.url === config.url && runtime.config.token === config.token &&
        runtime.config.allowInsecureHttp === config.allowInsecureHttp);
      if (kept !== undefined) return kept;
      const seen = historyId === undefined ? undefined : PROCESS_VIEWS.get(`${this.#statePath}\n${historyId}`)?.get(config.verifierKey);
      return {
        config, client: remoteWitness(config, { tracker: this.#tracker(config), ...(policy.fetch === undefined ? {} : { fetch: policy.fetch }) }), registered: false,
        ...(seen === undefined ? {} : { known: { ...seen } }),
      };
    });
  }

  /** Checkpoints persisted per origin in the side file (best effort; the client keeps the largest in memory too). */
  #tracker(config: RemoteWitnessConfig): CheckpointTracker {
    return Object.freeze({
      get: (origin: string) => this.#readDoc()?.witnesses[origin]?.checkpoint,
      set: (origin: string, checkpoint: { size: number; rootB64: string; note: string }) => {
        this.#update((doc) => ({ ...doc, witnesses: { ...doc.witnesses, [origin]: { ...(doc.witnesses[origin] ?? { url: config.url, verifierKey: config.verifierKey, registered: false }), checkpoint } } }));
      },
    });
  }

  #viewKey(): string | undefined {
    const id = this.#historyId();
    return id === undefined ? undefined : `${this.#statePath}\n${id}`;
  }

  /** Records a verified answer (or our own accepted submission) for this session and the process. */
  #learn(runtime: Runtime, head: StatementHead | null): void {
    const known: Known = { head, at: Date.now() };
    runtime.known = known;
    const key = this.#viewKey();
    if (key === undefined) return;
    let views = PROCESS_VIEWS.get(key);
    if (views === undefined) { views = new Map(); PROCESS_VIEWS.set(key, views); }
    const previous = views.get(runtime.config.verifierKey);
    if (previous === undefined || previous.at <= known.at) views.set(runtime.config.verifierKey, known);
  }

  #historyId(): ContentHash | undefined {
    try { return this.#host.state()?.eventHistoryHashes[0]; } catch { return undefined; }
  }

  #readDoc(): WitnessStateDoc | undefined {
    try {
      const doc = readWitnessState(this.#statePath);
      const id = this.#historyId();
      return id !== undefined && doc.historyId !== undefined && doc.historyId !== id ? undefined : doc;
    } catch {
      return undefined;
    }
  }

  /** Side-file update, best effort (a failure is remembered, never fatal: nothing in the file is needed for safety). */
  #update(change: (doc: WitnessStateDoc) => WitnessStateDoc | undefined): void {
    if (this.#host.inspect) return;
    try {
      this.#doc = updateWitnessState(this.#statePath, this.#historyId(), change);
    } catch (error) {
      this.#lastError = error instanceof EngineError ? error : unavailable(`witness state file ${this.#statePath} could not be written: ${messageOf(error)}`);
    }
  }

  get active(): boolean {
    return this.#policy !== undefined && !this.#disabled;
  }
  get policy(): ResolvedWitnessPolicy | undefined {
    return this.#policy;
  }
  /** The policy the side file and the bindings make, without the out-of-band minimum (what the owner API edits). */
  get editablePolicy(): ResolvedWitnessPolicy | undefined {
    return this.#editable;
  }
  /** The out-of-band minimum policy in force (`IRONTRELLIS_WITNESS_POLICY`), if any. */
  get minimumPolicy(): MinimumWitnessPolicy | undefined {
    return this.#minimum;
  }

  /** Called once the store has adopted its file at open: the side-file findings, the persisted split views and the `requireOnOpen` gate. */
  opened(): void {
    if (!this.active || this.#host.inspect) return;
    const state = this.#state();
    if (state === undefined) return;
    if (this.#policy!.requireOnOpen && !this.#processCovers(state) && !this.#sealedCacheCovers(state)) {
      this.#pendingOpen = unavailable(
        `history ${this.#host.path} requires a remote witness check before it is read (requireOnOpen): await checkWitnesses() first, or use a fresh owner-sealed cache (cacheMs)`,
        { reason: "NOT_CHECKED", statePath: this.#statePath });
    } else {
      this.#openChecked = true;
    }
  }

  #state(): ReplayState | undefined {
    const state = this.#host.state();
    return state === undefined || !isTrellis(state.format) ? undefined : state;
  }

  #ownerKeyed(state: ReplayState): boolean {
    const signer = this.#host.signer();
    return signer !== undefined && ownerKeyInForce(state, state.head.position + 1, signer);
  }

  /** The runtime's origin: learned from a verified checkpoint, or the side file entry with the same verifier key. */
  #originOf(runtime: Runtime): string | undefined {
    if (runtime.client.origin !== undefined) return runtime.client.origin;
    const doc = this.#doc;
    if (doc === undefined) return undefined;
    return Object.entries(doc.witnesses).find(([, w]) => w.verifierKey === runtime.config.verifierKey)?.[0];
  }

  /**
   * `requireOnOpen` is met by answers this process verified within cacheMs
   * (another handle's check included; at least the last second, so a handle a
   * host opens right after its own check does not ask again).
   */
  #processCovers(state: ReplayState): boolean {
    const now = Date.now(), cacheMs = Math.max(this.#policy!.cacheMs, 1000);
    const fresh = (runtime: Runtime): boolean => runtime.known !== undefined && now - runtime.known.at <= cacheMs;
    if (this.#runtimes.some((runtime) => fresh(runtime) && runtime.known!.head !== null && !isPrefix(runtime.known!.head, state))) return false;
    return this.#coverage(fresh).ok;
  }

  /**
   * Whether the witnesses `answered` accepts are enough for a check: from every trusted set (`#groups`: the whole policy,
   * the bound witnesses, the out-of-band minimum's) `size - quorum + 1` of its own witnesses (docs/reference/witness-policy.md §5.3), so a
   * witness only the side file names never stands in for a bound one. `required`: the policy-wide number; `short`: the set
   * that fell short.
   */
  #coverage(answered: (runtime: Runtime) => boolean): Readonly<{ ok: boolean; consulted: number; required: number; short?: string }> {
    const keys = new Set(this.#runtimes.filter(answered).map((runtime) => runtime.config.verifierKey));
    let required = 0, short: string | undefined;
    for (const group of this.#groups) {
      const size = group.keys.size;
      const need = size === 0 ? 0 : Math.max(1, size - Math.min(group.quorum, size) + 1);
      const got = [...group.keys].filter((key) => keys.has(key)).length;
      if (group.name === "policy") required = need;
      if (got >= need || short !== undefined) continue;
      short = group.name === "policy" ? `${got} of the ${need} witness answers the policy needs`
        : group.name === "bound" ? `${got} of the ${need} answers needed from the witnesses the history binds (quorum ${group.quorum} of ${size}; no other witness can stand in for them)`
        : `${got} of the ${need} answers needed from the witnesses of the out-of-band minimum policy (quorum ${group.quorum} of ${size})`;
    }
    return Object.freeze({ ok: short === undefined, consulted: keys.size, required, ...(short === undefined ? {} : { short }) });
  }

  /**
   * The identity an owner seal over this witness's cached answer is made for and checked against (docs/WITNESS.md §3):
   * only a witness the history binds, with its origin from the binding's verified REGISTERED receipt (never from the
   * side file; a binding without a receipt gets no sealed-cache shortcut at all), or a witness of the out-of-band
   * minimum (its URL and key come from the operator's file). A witness only the side file adds is never sealed. The
   * seal signs the origin, the verifier key and the pinned URL, so it cannot be credited to another witness.
   */
  #sealIdentity(runtime: Runtime, state: ReplayState): SealedWitness | undefined {
    const key = runtime.config.verifierKey;
    let origin: string | undefined;
    if (this.#groups.some((group) => group.name === "bound" && group.keys.has(key))) {
      const registration = boundRegistrationOf(state, key);
      if (registration === undefined) return undefined;
      origin = registration.receipt.witness.origin;
      if (runtime.client.origin !== undefined && runtime.client.origin !== origin) return undefined;
    } else if (this.#groups.some((group) => group.name === "minimum" && group.keys.has(key))) {
      origin = this.#originOf(runtime);
    }
    if (origin === undefined) return undefined;
    return Object.freeze({ historyId: state.eventHistoryHashes[0]!, origin, verifierKey: key, url: runtime.config.url });
  }

  /** The runtime's cached answer in the side file when it carries a valid owner seal made for exactly this witness. */
  #sealedCached(runtime: Runtime, state: ReplayState, doc: WitnessStateDoc | undefined = this.#doc): CachedLatest | undefined {
    const identity = this.#sealIdentity(runtime, state);
    const cached = identity === undefined ? undefined : doc?.witnesses[identity.origin]?.latest;
    return cached !== undefined && cachedLatestIsSealed(state, identity!, cached) ? cached : undefined;
  }

  /** `requireOnOpen` may skip the network when enough witnesses have a fresh, owner-sealed cached answer that is a prefix. */
  #sealedCacheCovers(state: ReplayState): boolean {
    const now = Date.now(), cacheMs = this.#policy!.cacheMs;
    const covered = new Set<Runtime>();
    for (const runtime of this.#runtimes) {
      const cached = this.#sealedCached(runtime, state);
      if (cached === undefined || cached.fetchedAt > now || now - cached.fetchedAt > cacheMs) continue;
      if (cached.head !== null && !isPrefix(cached.head, state)) return false;
      covered.add(runtime);
    }
    return this.#coverage((runtime) => covered.has(runtime)).ok;
  }

  /** Evidence from the side file (unauthenticated): a cached latest that is not a prefix, or a recorded split view. */
  #fileProblem(state: ReplayState): EngineError | undefined {
    for (const runtime of this.#runtimes) {
      const origin = this.#originOf(runtime);
      const entry = origin === undefined ? undefined : this.#doc?.witnesses[origin];
      if (entry?.splitView !== undefined) {
        return new EngineError("WITNESS_SPLIT_VIEW", `witness ${runtime.config.url} was found showing inconsistent logs (split view) at ${new Date(entry.splitView.detectedAt).toISOString()}: ${entry.splitView.message}`,
          { url: runtime.config.url, origin, recorded: true });
      }
      const cached = entry?.latest;
      if (cached?.head !== null && cached?.head !== undefined && !isPrefix(cached.head, state)) {
        return this.#rollbackError(runtime, cached.head, state, "recorded");
      }
    }
    return undefined;
  }

  #rollbackError(runtime: Runtime, head: StatementHead, state: ReplayState, source: "network" | "recorded"): EngineError {
    const ahead = head.position > state.head.position;
    const supersede = source === "network" ? runtime.supersedeFailure : undefined;
    return rollback(this.#host.path, ahead ? "WITNESS_AHEAD" : "WITNESS_FORK",
      `remote witness ${runtime.config.url} ${source === "recorded" ? "was recorded holding" : "holds"} an owner-signed head at position ${head.position} that ${ahead ? "is past the end of" : "is not a prefix of"} this history (head position ${state.head.position}): events were removed or replaced${supersede === undefined ? "" : ` (no supersede: ${supersede})`}`,
      { witness: runtime.config.url, origin: this.#originOf(runtime), witnessedHead: head, observedHead: state.head, source, ...(supersede === undefined ? {} : { supersede }) });
  }

  /** Every head this process learned must stay a prefix (the file may be rolled back under a live process). */
  #assertKnown(state: ReplayState): void {
    for (const runtime of this.#runtimes) {
      const head = runtime.known?.head;
      if (head !== null && head !== undefined && !isPrefix(head, state)) {
        // Re-read first: another writer may have appended after our last look (it appends before it submits).
        const fresh = this.#state() ?? state;
        if (!isPrefix(head, fresh)) this.#raise(runtime, this.#rollbackError(runtime, head, fresh, "network"));
      }
    }
    if (this.#alarm !== undefined) throw this.#alarm;
  }

  /**
   * Reads: the alarm, what this process learned, the `requireOnOpen` gate, and
   * the side file's evidence (a remembered witness head the file does not
   * contain, a recorded split view). The side-file evidence refuses reads like
   * a local anchor log that holds a later head does (`ANCHOR_LOG_ROLLBACK`): it
   * can only make things stricter. Without `requireOnOpen`, a reader does not
   * ask the network, so a copy restored together with an older side file is
   * read until a writer, `checkWitnesses()` or verification asks the witnesses.
   */
  guardRead(state: ReplayState | undefined): void {
    if (!this.active || this.#host.inspect || state === undefined || !isTrellis(state.format)) return;
    if (this.#alarm !== undefined) throw this.#alarm;
    this.#assertKnown(state);
    const problem = this.#fileProblem(state);
    if (problem !== undefined) throw problem;
    if (this.#pendingOpen !== undefined) throw this.#pendingOpen;
  }

  /**
   * Writes: everything a read checks; for owner-keyed writers also a witness
   * that refused to register the history or denies a registration it signed
   * (`#refused`), and the unwitnessed-events bound. `types`: the event types of the batch; a batch made only of
   * `MAX_UNWITNESSED_EXEMPT_TYPES` (power-reducing events and checkpoints, A-24.1 as amended by A-176.2) is not refused by
   * the bound.
   */
  guardWrite(state: ReplayState | undefined, types: readonly EventType[] = []): void {
    if (!this.active || this.#host.inspect || state === undefined || !isTrellis(state.format)) return;
    this.guardRead(state);
    if (this.#pendingAllowed === 0) {
      // docs/reference/witness-operations.md §7.1: a witness may already hold the prepared rotation's head; any other append on top of its
      // previous head would fork that witness. Writes wait until an owner process completes or discards it.
      const pending = this.#outstanding(state);
      if (pending !== undefined) {
        throw unavailable(`history ${this.#host.path}: a prepared owner key rotation (position ${pending.head.position}, ${this.#pendingPath}) is outstanding: a bound witness may already hold its head, so no other event is appended on top of position ${pending.previousHead.position} until an owner process completes it (a witness holds its head) or discards it (every bound witness answered without it); run irontrellis witness sync or any owner command`,
          { reason: "ROTATION_PENDING", position: pending.head.position, pendingPath: this.#pendingPath });
      }
    }
    if (!this.#ownerKeyed(state)) return;
    const refused = this.#refused();
    if (refused !== undefined) throw refused;
    const unwitnessed = this.#unwitnessed(state);
    if (unwitnessed >= this.#policy!.maxUnwitnessedEvents && !(types.length > 0 && types.every((type) => MAX_UNWITNESSED_EXEMPT_TYPES.has(type)))) {
      // "Queued" only when a head statement is actually waiting; runtime events (session writes) queue none.
      const queued = (this.#doc?.pending ?? []).some((item) => item.kind === "statement");
      const until = queued ? "until the witnesses accept the queued head statements" : "until a remote witness accepts a statement for the current head (none has yet)";
      throw unavailable(`history ${this.#host.path}: ${unwitnessed} events are not yet witnessed by ${this.#policy!.quorum} remote witness(es) (maxUnwitnessedEvents ${this.#policy!.maxUnwitnessedEvents}); writes are refused ${until} (reads continue); run irontrellis witness sync when a witness is reachable`,
        { reason: "MAX_UNWITNESSED", unwitnessed, maxUnwitnessedEvents: this.#policy!.maxUnwitnessedEvents, lastError: errorView(this.#lastError) });
    }
  }

  /** The first witness that refused to register the history (WITNESS_REJECTED) or denies a registration it signed. */
  #refused(): EngineError | undefined {
    for (const runtime of this.#runtimes) if (runtime.rejected !== undefined) return runtime.rejected;
    for (const runtime of this.#runtimes) if (runtime.denied !== undefined) return runtime.denied;
    return undefined;
  }

  /** The position a trusted source says the witness holds: this process's knowledge, else an owner-sealed cached answer. */
  #trustedPosition(runtime: Runtime, state: ReplayState): number | undefined {
    if (runtime.known !== undefined) return runtime.known.head?.position ?? 0;
    const cached = this.#sealedCached(runtime, state);
    if (cached === undefined) return undefined;
    if (cached.head !== null && !isPrefix(cached.head, state)) return undefined;
    return cached.head?.position ?? 0;
  }

  /**
   * The highest position that counts as witnessed (0 when unknown: the genesis is covered by registration): held by
   * `quorum` witnesses of the policy AND by the bound quorum of the bound witnesses (and the minimum's quorum of its own).
   */
  #witnessedPosition(state: ReplayState): number {
    let witnessed = Number.POSITIVE_INFINITY;
    for (const group of this.#groups) {
      const positions = this.#runtimes.filter((runtime) => group.keys.has(runtime.config.verifierKey)).map((runtime) => this.#trustedPosition(runtime, state) ?? 0).sort((a, b) => b - a);
      if (positions.length === 0) continue;
      witnessed = Math.min(witnessed, positions[Math.min(group.quorum, positions.length) - 1] ?? 0);
    }
    return Number.isFinite(witnessed) ? witnessed : 0;
  }

  #unwitnessed(state: ReplayState): number {
    return Math.max(0, state.head.position - this.#witnessedPosition(state));
  }

  // ---- lifecycle hooks the store calls

  /**
   * After a successful append: records the policy on creation and, for an
   * owner-keyed writer, a coalesced marker for the new head; async mode wakes
   * the worker (sync mode: the async owner API submits before it returns).
   */
  afterAppend(created: boolean): void {
    if (!this.active || this.#host.inspect) return;
    let state: ReplayState | undefined;
    try { state = this.#state(); } catch { return; }
    if (state === undefined) return;
    // Called under the writer lock right after this handle's append: its own head is what later locked reads must contain.
    this.#trusted = Object.freeze({ hash: state.head.hash, position: state.head.position });
    if (created) {
      // The history id is known now: a side file left by another history at this path loses its witness state (its policy stays: stricter).
      if (this.#explicit !== undefined) this.#update((doc) => ({ ...doc, policy: storedPolicyOf(this.#explicit!) }));
      this.#load();
    }
    if (!this.#ownerKeyed(state)) return;
    const head = state.head;
    this.#update((doc) => ({ ...doc, pending: [...doc.pending.filter((item) => item.kind !== "statement" || item.statements !== undefined), { kind: "statement", head: Object.freeze({ hash: head.hash, position: head.position, canonicalTime: head.canonicalTime }) }] }));
    if (this.#policy!.mode === "async") this.#schedule(0);
  }

  // ---- network view

  /**
   * Asks every witness (in parallel) for its latest head of this history,
   * verifies the answers and compares them with the file. Answers younger than
   * `cacheMs` from this process are reused unless `force`. Throws the alarm on
   * rollback / split view evidence from ANY witness, and
   * WITNESS_UNAVAILABLE when fewer than `n - quorum + 1` witnesses answered.
   * Success lifts the `requireOnOpen` gate.
   */
  async check(options: Readonly<{ force?: boolean }> = {}): Promise<WitnessView> {
    if (!this.active) return Object.freeze({ consulted: 0, required: 0, witnesses: Object.freeze([]) });
    if (this.#alarm !== undefined) throw this.#alarm;
    const state = this.#state();
    if (state === undefined) return Object.freeze({ consulted: 0, required: 0, witnesses: Object.freeze([]) });
    const now = Date.now(), cacheMs = this.#policy!.cacheMs;
    await Promise.all(this.#runtimes.map((runtime) =>
      options.force !== true && runtime.known !== undefined && now - runtime.known.at < cacheMs ? Promise.resolve() : this.#refresh(runtime)));
    if (this.#alarm !== undefined) { this.#persistKnowledge(); throw this.#alarm; }
    this.#assertKnown(this.#state() ?? state);
    this.#persistKnowledge();
    // A witness that denies a registration it signed (or refused one) cannot confirm anything: the check fails with that
    // finding, whatever the quorum (the `requireOnOpen` gate stays closed, owner writes refuse).
    const refused = this.#refused();
    if (refused !== undefined) throw refused;
    // Answers from this call, or from this process within cacheMs (a witness that fails now does not erase what it said a moment ago).
    const coverage = this.#coverage((runtime) => runtime.known !== undefined && runtime.known.at >= now - cacheMs);
    const { consulted, required } = coverage;
    if (!coverage.ok) {
      const errors = this.#runtimes.map((runtime) => runtime.lastError).filter((error) => error !== undefined);
      // An answer that does not verify (a missing or wrong signed latest note: possibly a replayed older answer,
      // docs/reference/witness-protocol.md §9.8) is named as the cause before plain unavailability: owner writes refuse on it.
      const cause = errors.find((error) => error.code === "WITNESS_INVALID_RESPONSE") ?? errors[0];
      const invalid = cause?.code === "WITNESS_INVALID_RESPONSE";
      throw unavailable(`${invalid ? "the remote witnesses a check needs did not give a verifiable answer (an answer that does not verify may be an older one replayed to hide a rollback)" : "the remote witnesses a check needs did not answer"}: ${coverage.short} (${errors.map((error) => error.message).join("; ") || "no answer"})`,
        { reason: invalid ? "INVALID_ANSWER" : "UNREACHABLE", consulted, required, errors: errors.map(errorView), ...(cause === undefined ? {} : { cause: cause.code }) });
    }
    this.#pendingOpen = undefined;
    this.#openChecked = true;
    return Object.freeze({ consulted, required, witnesses: this.status().witnesses });
  }

  /**
   * Ask one witness; on success `known`/`epochs` are current. When the witness
   * does not know the history: a witness the history binds with its own signed
   * REGISTERED receipt is contradicting its signature (`denied`, never
   * re-registered: that would hide the loss); otherwise the genesis is
   * registered when this store can sign.
   */
  async #refresh(runtime: Runtime): Promise<void> {
    const state = this.#state();
    if (state === undefined) return;
    const historyId = state.eventHistoryHashes[0]!;
    try {
      if (runtime.rejected !== undefined) throw runtime.rejected;
      if (runtime.client.origin === undefined) await runtime.client.checkpoint();
      const info = await runtime.client.history(historyId);
      if (info === undefined) {
        if (boundRegistrationOf(state, runtime.config.verifierKey) !== undefined) {
          // A 404 is unsigned: first see whether the witness now shows a log that is not an extension of the one it showed
          // before (a split view, sticky), then take the denial as what it is.
          await runtime.client.checkpoint();
          this.#assertNotDenied(runtime, state);
        }
        const ownerKeyed = this.#ownerKeyed(state);
        if (!ownerKeyed && this.#isBound(runtime, state)) {
          // A bound witness without a registration receipt in its binding (bound while unreachable): its 404 is unsigned
          // and cannot be told from a forged one, so for a reader it is no answer at all (the availability policy applies).
          // An owner-keyed process registers instead, and the registration's signed latest note is the answer.
          throw this.#unsignedNotRegistered(runtime);
        }
        let held: Readonly<{ hash: ContentHash; position: number }> | null = null;
        if (ownerKeyed) held = await this.#registerGenesis(runtime, state);
        if (held !== null) {
          // The 404 is unsigned; the registration answer's signed latest note (over our nonce) names a head: ask again and
          // judge that answer (a witness that keeps denying a history it signed a head for gives no usable answer).
          const again = await runtime.client.history(historyId);
          if (again === undefined) {
            throw new EngineError("WITNESS_INVALID_RESPONSE", `witness ${runtime.config.url} answers that it does not know history ${historyId}, but its signed latest note holds a head at position ${held.position} for it`,
              { url: runtime.config.url, reason: "LATEST_NOTE_MISMATCH" });
          }
          this.#adopt(runtime, again);
          return;
        }
        runtime.epochs = Object.freeze([Object.freeze({ fromPosition: 0, keys: ownerKeysAt(state, 0) })]);
        this.#learn(runtime, null);
        runtime.lastError = undefined;
        return;
      }
      this.#adopt(runtime, await this.#reconciled(runtime, info));
    } catch (error) {
      this.#failed(runtime, error);
    }
  }

  /** A bound witness's unsigned "not registered" answer, which a reader cannot count (docs/reference/witness-operations.md §6.1). */
  #unsignedNotRegistered(runtime: Runtime): EngineError {
    return unavailable(`witness ${runtime.config.url} answers "not registered" (an unsigned answer) for a history that binds it without its signed registration receipt; that cannot be told from a forged answer, so it does not count as an answer: run irontrellis witness add ${runtime.config.url} --verifier-key <key> again while the witness is reachable to record the receipt`,
      { url: runtime.config.url, reason: "UNSIGNED_NOT_REGISTERED" });
  }

  /** A verified history answer: the runtime's registration, epochs and equivocation count; its latest judged against the file, then learned. */
  #adopt(runtime: Runtime, info: WitnessHistoryInfo): void {
    runtime.denied = undefined;
    runtime.registered = true;
    this.#recordRejection(runtime, undefined);
    // Recorded equivocations are evidence about the owner key (verify notes them), not about this file: the prefix check decides.
    runtime.equivocations = info.equivocations;
    runtime.supersedes = info.supersedes;
    runtime.epochs = info.epochs;
    this.#judge(runtime, info.latest?.head ?? null);
    this.#learn(runtime, info.latest?.head ?? null);
    this.#hold(runtime, info.latest);
    runtime.lastError = undefined;
  }

  /** Remembers a verified head the witness holds that is a prefix of the file: the last good head (L) of a later supersede. */
  #hold(runtime: Runtime, witnessed: RemoteWitnessedHead | null | undefined): void {
    if (witnessed === null || witnessed === undefined) return;
    const state = this.#state();
    if (state === undefined || !isPrefix(witnessed.head, state)) return;
    if (runtime.held === undefined || runtime.held.head.position <= witnessed.head.position) runtime.held = Object.freeze({ head: witnessed.head, receipt: witnessed.receipt });
  }

  /**
   * A verified witness answer whose latest head is not a prefix of the file, before it is judged (docs/reference/witness-operations.md §7.1,
   * §7.4): when it is exactly the head of the OUTSTANDING prepared rotation, that rotation is completed (appended) instead
   * of raising a rollback alarm; when the history holds a pre-rotated rotation the witness has not recorded, the witness's
   * chain is superseded from the last good head. Either way the witness is asked again. Otherwise the answer is returned
   * as it is (and judged: the alarm).
   */
  async #reconciled(runtime: Runtime, info: WitnessHistoryInfo): Promise<WitnessHistoryInfo> {
    const head = info.latest?.head;
    if (head === undefined) return info;
    // This process's own two-phase rotation may be about to append the head the witness already holds: wait for it.
    if (this.#preparing !== undefined && !isPrefix(head, this.#state() ?? info as never)) await this.#preparing;
    const state = this.#state();
    if (state === undefined || isPrefix(head, state)) return info;
    runtime.epochs = info.epochs;
    if (!(await this.#reconcile(runtime, head))) return info;
    return (await runtime.client.history(state.eventHistoryHashes[0]!)) ?? info;
  }

  /** See `#reconciled`: true when the file or the witness changed so that `head` should now be judged again. */
  async #reconcile(runtime: Runtime, head: StatementHead): Promise<boolean> {
    if (this.#host.inspect) return false;
    const state = this.#state();
    if (state === undefined) return false;
    const record = this.#outstanding(state);
    if (record !== undefined && sameHead(record.head, head) && record.head.canonicalTime === head.canonicalTime) {
      // Its staged keys must still be there: a record replayed after its rotation was aborted never rotates to a lost key.
      const missing = pendingRotationKeysMissing(this.#host.path, record);
      if (missing !== undefined) {
        runtime.supersedeFailure = `the witness holds the head of the prepared rotation ${this.#pendingPath}, but ${missing}; it is not appended (a rotation to a key nobody holds). Restore the staged key files, or remove the witness with --accept-loss`;
        return false;
      }
      const recorded = await this.#host.completePending(record);
      if (recorded === undefined) return false;
      this.#completedPending(record);
      return true;
    }
    return this.#supersede(runtime, head);
  }

  /** The prepared rotation record when it is OUTSTANDING against `state` (docs/reference/witness-operations.md §7.1), else `undefined`. */
  #outstanding(state: ReplayState): PendingRotationRecord | undefined {
    if (!existsSync(this.#pendingPath)) return undefined;
    const record = readPendingRotation(this.#pendingPath);
    if (record === undefined || record === null) return undefined;
    return judgePendingRotation(state, record).status === "OUTSTANDING" ? record : undefined;
  }

  /** After a recovered prepared rotation was appended: its old-key statement for head r (previous r - 1) is queued for every witness. */
  #completedPending(record: PendingRotationRecord): void {
    const statements: Record<string, SignedHeadStatement> = {};
    for (const runtime of this.#runtimes) {
      const origin = this.#originOf(runtime);
      if (origin !== undefined) statements[origin] = record.statement;
    }
    const head = Object.freeze({ hash: record.head.hash, position: record.head.position, canonicalTime: record.head.canonicalTime });
    this.#update((doc) => ({
      ...doc, pending: [...doc.pending.filter((item) => item.kind !== "statement" || item.statements !== undefined), { kind: "statement", head, ...(Object.keys(statements).length === 0 ? {} : { statements }) }],
    }));
  }

  /**
   * docs/reference/witness-operations.md §7.4, the client side: the witness's latest head `head` is not a prefix of the file, and the history
   * holds a pre-rotated rotation at r the witness has not recorded. The last head L this history knows the witness held
   * on its chain (a verified receipt from this process or the side file, a prefix of the file, before r) and the
   * rotation's old-key statement for r with `previous = L` (the chain, signed under the writer lock) go to the witness,
   * which supersedes every head it holds after L. Anything short of that (no such rotation, not pre-rotated, L unknown, a
   * refusal) returns false: the caller fails closed.
   */
  async #supersede(runtime: Runtime, head: StatementHead): Promise<boolean> {
    const fail = (why: string): false => { runtime.supersedeFailure = why; return false; };
    const state = this.#state();
    if (state === undefined) return false;
    const historyId = state.eventHistoryHashes[0]!;
    const rotation = this.#pendingRotationsOf(runtime, state)[0];
    if (rotation === undefined) return fail("the history holds no owner key rotation this witness has not recorded");
    if (epochAt(state, rotation.r)?.nextKeyDigests === undefined) {
      return fail(`the rotation at position ${rotation.r} is not pre-rotated (the owner keys it replaced had no next-key commitment), so it cannot override heads the old key signed`);
    }
    const last = this.#lastGood(runtime, state, rotation.r - 1);
    if (last === undefined) return fail("this history knows no head the witness held on its chain before the rotation (no verified receipt in this process or the side file)");
    const chain = await this.#underLock(async (locked) => {
      if (!isPrefix(last.head, locked) || locked.head.position < rotation.r || locked.eventHistoryHashes[rotation.r] !== rotation.rotationHead.hash) return undefined;
      const signer = this.#signerAt(locked, rotation.r);
      if (signer === undefined) return null;
      return signHeadStatement(signer, Object.freeze({
        version: HEAD_STATEMENT_VERSION, historyId, domain: locked.genesis.domain as never, head: headAt(locked, rotation.r),
        previous: Object.freeze({ hash: last.head.hash, position: last.head.position }),
      }));
    });
    if (chain === undefined) return fail("the history changed while the supersede was prepared");
    if (chain === null) return fail(`no owner key in force at position ${rotation.r} is available to sign the chain statement (keep the retired key file <history>.owner-key.<keyId>.retired.json beside the history)`);
    const result = await runtime.client.keyEvent(historyId, { event: rotation.event, previousHead: rotation.previousHead, eventHead: rotation.rotationHead, chain });
    if (result.kind !== "ACCEPTED") return fail(`the witness refused the supersede: ${result.kind === "REJECTED" ? `${result.code}: ${result.message}` : result.kind}`);
    runtime.epochs = result.epochs;
    runtime.supersedeFailure = undefined;
    return true;
  }

  /** The last good head L for a supersede: the newest verified head the witness held that is a prefix of `state` at or before `before`. */
  #lastGood(runtime: Runtime, state: ReplayState, before: number): Held | undefined {
    const candidates: Held[] = [];
    if (runtime.held !== undefined) candidates.push(runtime.held);
    const stored = this.#storedHeld(runtime, state);
    if (stored !== undefined) candidates.push(stored);
    return candidates
      .filter((candidate) => candidate.head.position <= before && isPrefix(candidate.head, state) && state.events[candidate.head.position]?.timestamp === candidate.head.canonicalTime)
      .sort((a, b) => b.head.position - a.head.position)[0];
  }

  /** The side file's HEAD receipt for this witness, when it verifies with the configured key and names a head of this history. */
  #storedHeld(runtime: Runtime, state: ReplayState): Held | undefined {
    const origin = this.#originOf(runtime);
    const receipt = origin === undefined ? undefined : (this.#readDoc() ?? this.#doc)?.witnesses[origin]?.held;
    if (receipt === undefined || !verifyWitnessReceipt(receipt, [runtime.config.verifierKey]).ok) return undefined;
    if (runtime.client.origin !== undefined && receipt.witness.origin !== runtime.client.origin) return undefined;
    const entry = receipt.entry as unknown as Record<string, unknown>;
    if (entry.kind !== "HEAD" || entry.historyId !== state.eventHistoryHashes[0]) return undefined;
    const head = (entry.signedStatement as SignedHeadStatement).statement.head;
    return Object.freeze({ head: Object.freeze({ hash: head.hash, position: head.position, canonicalTime: head.canonicalTime }), receipt });
  }

  /** Local rotations a witness has not recorded (by what this process knows of its epochs), in history order. */
  #pendingRotationsOf(runtime: Runtime, state: ReplayState): readonly LocalRotation[] {
    const epochs = runtime.epochs ?? [];
    return localRotations(state).filter((rotation) => !recordedBy(epochs, rotation));
  }

  /**
   * A "not registered" answer from a witness the history binds with a REGISTERED
   * receipt signed by that witness's key contradicts signed evidence: data loss at
   * the witness (a data directory restored from before the registration, or lost)
   * or an attacker in the path answering for it. Throws the denial (kept on the
   * runtime until the witness answers with the history again).
   */
  #assertNotDenied(runtime: Runtime, state: ReplayState): void {
    const registration = boundRegistrationOf(state, runtime.config.verifierKey);
    if (registration === undefined) return;
    runtime.denied = new EngineError("WITNESS_INVALID_RESPONSE",
      `witness ${runtime.config.url} denies a registration it signed: it answers that it does not know history ${state.eventHistoryHashes[0]}, but the history binds it with its own signed REGISTERED receipt (leaf ${registration.index}). Either the witness lost data (its data directory was restored from before the registration, or lost) or an attacker in the path is answering for it; it cannot vouch for this history until that is resolved`,
      { url: runtime.config.url, reason: "REGISTRATION_DENIED", registrationIndex: registration.index });
    throw runtime.denied;
  }

  /**
   * Registers the genesis. A refusal (4xx: UNAUTHORIZED, INVALID_GENESIS,
   * UNSUPPORTED_FORMAT, …) is permanent for this configuration: kept as the
   * runtime's `rejected` state (owner-keyed writes refuse WITNESS_REJECTED until
   * the policy for the witness changes). Unavailability (5xx, including 503
   * HISTORY_LIMIT_REACHED, 408, 429, network) stays transient.
   */
  async #registerGenesis(runtime: Runtime, state: ReplayState): Promise<Readonly<{ hash: ContentHash; position: number }> | null> {
    if (runtime.rejected !== undefined) throw runtime.rejected;
    let held: Readonly<{ hash: ContentHash; position: number }> | null;
    try {
      held = (await runtime.client.register(state.events[0])).latest;
    } catch (error) {
      if (error instanceof EngineError && error.code === "WITNESS_REJECTED") {
        const detail = (error.detail ?? {}) as { code?: unknown; status?: unknown };
        const rejected = new EngineError("WITNESS_REJECTED",
          `${error.message}. The witness refused to register this history, so it can never witness it; owner writes are refused until the policy for this witness changes (give its registration token: irontrellis witness add <url> --verifier-key <key> --token <token>, or remove it)`,
          { url: runtime.config.url, reason: "REGISTRATION_REFUSED", ...(typeof detail.code === "string" ? { code: detail.code } : {}), ...(typeof detail.status === "number" ? { status: detail.status } : {}) });
        runtime.rejected = rejected;
        this.#recordRejection(runtime, rejected);
        throw rejected;
      }
      throw error;
    }
    runtime.registered = true;
    this.#recordRejection(runtime, undefined);
    return held;
  }

  /** The side file's display record of a refused registration (for `witness status` in other processes); cleared by a registration. */
  #recordRejection(runtime: Runtime, rejected: EngineError | undefined): void {
    const origin = this.#originOf(runtime);
    if (origin === undefined) return;
    if (rejected === undefined && this.#doc?.witnesses[origin]?.rejected === undefined) return;
    this.#update((doc) => {
      const entry = doc.witnesses[origin] ?? { url: runtime.config.url, verifierKey: runtime.config.verifierKey, registered: runtime.registered };
      const { rejected: _old, ...rest } = entry;
      const code = (rejected?.detail as { code?: unknown } | undefined)?.code;
      return { ...doc, witnesses: { ...doc.witnesses, [origin]: rejected === undefined ? rest : {
        ...rest, rejected: { code: typeof code === "string" ? code : rejected.code, message: rejected.message, detectedAt: Date.now(), config: witnessConfigFingerprint(runtime.config) },
      } } };
    });
  }

  /** A refused registration: this process's finding, else the side file's record for exactly this witness config. */
  #rejectionOf(runtime: Runtime, entry: WitnessStateDoc["witnesses"][string] | undefined): Readonly<{ code: string; message: string }> | undefined {
    if (runtime.rejected !== undefined) return errorView(runtime.rejected);
    const recorded = entry?.rejected;
    if (recorded === undefined || recorded.config !== witnessConfigFingerprint(runtime.config)) return undefined;
    return Object.freeze({ code: "WITNESS_REJECTED", message: `recorded at ${new Date(recorded.detectedAt).toISOString()} (${recorded.code}): ${recorded.message}` });
  }

  #failed(runtime: Runtime, error: unknown): void {
    const engine = error instanceof EngineError ? error : unavailable(`witness ${runtime.config.url}: ${messageOf(error)}`);
    runtime.lastError = engine;
    this.#lastError = engine;
    if (engine.code === "WITNESS_SPLIT_VIEW") {
      this.#raise(runtime, engine);
      const origin = this.#originOf(runtime);
      if (origin !== undefined) {
        this.#update((doc) => ({ ...doc, witnesses: { ...doc.witnesses, [origin]: { ...(doc.witnesses[origin] ?? { url: runtime.config.url, verifierKey: runtime.config.verifierKey, registered: runtime.registered }), splitView: { detectedAt: Date.now(), message: engine.message } } } }));
      }
    }
  }

  /** A verified witness answer against the (re-read) file: not a prefix → the sticky alarm. */
  #judge(runtime: Runtime, head: StatementHead | null): void {
    if (head === null) return;
    let state = this.#state();
    if (state === undefined) return;
    if (!isPrefix(head, state)) {
      state = this.#state() ?? state;
      if (!isPrefix(head, state)) {
        throw this.#raise(runtime, this.#rollbackError(runtime, head, state, "network"));
      }
    }
  }

  /**
   * What this process learned, into the side file (sealed by the owner key when this store holds one), and the queue pruned.
   * An asynchronous signer (ssh-agent, command, KMS) seals only when `sealAsync` (a submission round or a rotation's
   * delivery: an owner write or flush is under way): a read (`check`, a verify) never asks it for a signature, which
   * could be a person's approval or a hardware touch for every hook call.
   */
  #persistKnowledge(options: Readonly<{ sealAsync?: boolean }> = {}): void {
    let state: ReplayState | undefined;
    try { state = this.#state(); } catch { return; }
    if (state === undefined) return;
    const signer = this.#ownerKeyed(state) ? this.#host.signer() : undefined;
    const entries: [string, Runtime][] = [];
    for (const runtime of this.#runtimes) {
      const origin = this.#originOf(runtime);
      if (origin !== undefined && runtime.known !== undefined) entries.push([origin, runtime]);
    }
    const minimum = this.#runtimes.every((runtime) => runtime.known !== undefined) ? Math.min(...this.#runtimes.map((runtime) => runtime.known!.head?.position ?? 0)) : -1;
    const rotated = (item: PendingItem): boolean => item.kind === "rotation" &&
      this.#runtimes.every((runtime) => runtime.epochs?.some((epoch) => epoch.fromPosition === item.rotationHead.position + 1) === true);
    // An asynchronous signer (ssh-agent, command, KMS) seals after this update: queued here, written by #sealLater.
    const later: { origin: string; identity: SealedWitness; head: StatementHead | null; at: number }[] = [];
    // The last good head a witness held (docs/reference/witness-operations.md §7.4) is kept for the supersede of a later emergency rotation.
    this.#update((doc) => {
      const witnesses = { ...doc.witnesses };
      for (const [origin, runtime] of entries) {
        const known = runtime.known!;
        // Sealed only for a bound or out-of-band-minimum witness, under the identity it is checked against (#sealIdentity).
        const identity = signer === undefined ? undefined : this.#sealIdentity(runtime, state!);
        const sealable = identity !== undefined && identity.origin === origin;
        const seal = !sealable ? undefined : signer!.signHashSync === undefined ? undefined : sealCachedLatest(signer!, identity, known.head, known.at);
        if (sealable && signer!.signHashSync === undefined && options.sealAsync === true) later.push({ origin, identity, head: known.head, at: known.at });
        witnesses[origin] = {
          ...(witnesses[origin] ?? {}), url: runtime.config.url, verifierKey: runtime.config.verifierKey, registered: runtime.registered || witnesses[origin]?.registered === true,
          latest: { head: known.head, fetchedAt: known.at, ...(seal === undefined ? keptSeal(witnesses[origin]?.latest, known) : { seal }) },
          // The last good head's receipt (docs/reference/witness-operations.md §7.4): witness-signed, so the file cannot forge one, only drop or age it.
          ...(runtime.held === undefined ? {} : { held: runtime.held.receipt }),
        };
      }
      const pending = doc.pending.filter((item) => item.kind === "statement" ? item.head.position > minimum : !rotated(item));
      return { ...doc, witnesses, pending };
    });
    if (later.length > 0 && signer !== undefined) this.#sealLater(signer, later);
  }

  /**
   * Seals cached answers with an asynchronous signer (docs/CUSTODY.md): each seal is signed after the side file was updated
   * and written only while the entry still holds exactly that answer unsealed (under the side-file lock). A signer that
   * fails leaves the answer unsealed (a `requireOnOpen` reader then asks the network). `sealsSettled()` waits for them;
   * the owner API does so before a write returns.
   */
  #sealLater(signer: Signer, jobs: readonly Readonly<{ origin: string; identity: SealedWitness; head: StatementHead | null; at: number }>[]): void {
    this.#sealing = this.#sealing.then(async () => {
      for (const job of jobs) {
        const seal = await sealCachedLatestAsync(signer, job.identity, job.head, job.at);
        if (seal === undefined) continue;
        this.#update((doc) => {
          const entry = doc.witnesses[job.origin];
          const latest = entry?.latest;
          if (entry === undefined || latest === undefined || latest.seal !== undefined || latest.fetchedAt !== job.at ||
              (latest.head === null ? job.head !== null : job.head === null || !sameHead(latest.head, job.head) || latest.head.canonicalTime !== job.head.canonicalTime)) return undefined;
          return { ...doc, witnesses: { ...doc.witnesses, [job.origin]: { ...entry, latest: { ...latest, seal } } } };
        });
      }
    }).catch(() => undefined);
  }
  /** Resolves once the seals an asynchronous signer was asked for are written (or failed). Never rejects. */
  sealsSettled(): Promise<void> {
    return this.#sealing;
  }

  // ---- submission

  /** Serialised rounds: one at a time per session. */
  submit(): Promise<void> {
    const run = this.#round.then(() => this.#submitRound(), () => this.#submitRound());
    this.#round = run.catch(() => undefined);
    return run;
  }

  /**
   * One round: make sure enough witnesses were heard in this process, then
   * bring each of them up to the current head (rotations first, docs/WITNESS.md §7). Throws
   * the alarm, or WITNESS_UNAVAILABLE / WITNESS_REJECTED when a quorum does not
   * hold the head afterwards.
   */
  async #submitRound(): Promise<void> {
    if (!this.active || this.#host.inspect) return;
    if (this.#alarm !== undefined) throw this.#alarm;
    const state = this.#state();
    if (state === undefined || (!this.#ownerKeyed(state) && !this.#hasPresigned())) return;
    const startPosition = state.head.position;
    // Every round starts from fresh answers: another process (or a restored copy) may have moved the witness since this process
    // last looked, and a statement signed against an outdated latest could land on a head the witness already holds (docs/reference/witness-protocol.md §9.2 rule 4
    // records that as equivocation evidence). A witness that does not answer now keeps what this process last verified.
    const started = Date.now();
    await Promise.all(this.#runtimes.map((runtime) => this.#refresh(runtime)));
    if (this.#alarm !== undefined) { this.#persistKnowledge({ sealAsync: true }); throw this.#alarm; }
    const isHeard = (runtime: Runtime): boolean => runtime.known !== undefined && runtime.known.at >= started;
    const heard = this.#runtimes.filter(isHeard);
    const coverage = this.#coverage(isHeard);
    if (!coverage.ok) {
      this.#persistKnowledge({ sealAsync: true });
      const errors = this.#runtimes.map((runtime) => runtime.lastError).filter((error) => error !== undefined);
      throw unavailable(`the remote witnesses needed before signing did not answer: ${coverage.short}; the head statement stays queued (${errors.map((error) => error.message).join("; ") || "no answer"})`,
        { reason: "UNREACHABLE", consulted: heard.length, required: coverage.required, errors: errors.map(errorView), ...(errors[0] === undefined ? {} : { cause: errors[0].code }) });
    }
    this.#pendingOpen = undefined;
    this.#openChecked = true;
    await Promise.all(heard.map(async (runtime) => {
      try {
        await this.#bringUp(runtime);
        runtime.lastError = undefined;
      } catch (error) {
        if (this.#isAlarm(error)) return;
        this.#failed(runtime, error);
      }
    }));
    this.#persistKnowledge({ sealAsync: true });
    if (this.#alarm !== undefined) throw this.#alarm;
    const after = this.#state();
    if (after === undefined) return;
    // The head this round started from must be held by a quorum (later appends are the next round's).
    if ((this.#ownerKeyed(after) && this.#witnessedPosition(after) < startPosition) || this.#pendingRotations(after)) {
      const errors = this.#runtimes.map((runtime) => runtime.lastError).filter((error) => error !== undefined);
      throw errors[0] ?? unavailable(`the head at position ${after.head.position} is not yet held by ${this.#policy!.quorum} witness(es)`, { reason: "NOT_WITNESSED" });
    }
  }

  #hasPresigned(): boolean {
    return (this.#doc?.pending ?? []).some((item) => item.kind === "statement" && item.statements !== undefined);
  }

  /** A local key event (an owner key rotation) some reachable witness does not know yet. */
  #pendingRotations(state: ReplayState): boolean {
    return this.#runtimes.some((runtime) => runtime.known !== undefined && this.#pendingRotationsOf(runtime, state).length > 0);
  }

  /**
   * Runs `critical` under the store's writer lock against the state read under it (docs/WITNESS.md §2), one locked
   * section of this session at a time. That state must still contain the head this handle last appended or verified
   * under the lock: a file that no longer does was changed under the writer, which is tampering (sticky
   * ROLLBACK_DETECTED, reason FILE_CHANGED_UNDER_WRITER; nothing is signed). The state becomes the new trusted head.
   */
  #underLock<T>(critical: (state: ReplayState) => T | Promise<T>): Promise<T | undefined> {
    this.#sections += 1;
    const run = this.#lockChain.then(() => this.#host.locked(async (raw) => {
      if (this.#alarm !== undefined) throw this.#alarm;
      const state = raw === undefined || !isTrellis(raw.format) ? undefined : raw;
      if (state === undefined) return undefined;
      this.#assertTrusted(state);
      this.#trusted = Object.freeze({ hash: state.head.hash, position: state.head.position });
      return critical(state);
    })).finally(() => { this.#sections -= 1; });
    this.#lockChain = run.then(() => undefined, () => undefined);
    return run;
  }

  /**
   * Settles once the locked sections this session has queued so far are done; `undefined` when none is queued or
   * running. An owner write on the same store waits for it instead of failing on the writer lock this session holds
   * while an asynchronous signer signs a head statement (the owner's own `withExclusiveWriter` callbacks never wait).
   */
  lockedSectionsSettled(): Promise<void> | undefined {
    return this.#sections === 0 ? undefined : this.#lockChain;
  }

  /** The trusted head (what this handle appended or verified under the lock) must be a prefix of `state`; else the sticky FILE_CHANGED_UNDER_WRITER alarm. */
  #assertTrusted(state: ReplayState): void {
    const trusted = this.#trusted;
    if (trusted === undefined || isPrefix(trusted, state)) return;
    const error = rollback(this.#host.path, "FILE_CHANGED_UNDER_WRITER",
      `the history file changed under this writer: it no longer contains the head at position ${trusted.position} that this handle appended or verified under the writer lock (file head position ${state.head.position}); the file was replaced or rolled back behind the writer's back, so no head statement is signed for it`,
      { expectedHead: trusted, observedHead: state.head, source: "file" });
    if (!this.#alarms.has(FILE_ALARM)) this.#alarms.set(FILE_ALARM, error);
    throw this.#alarm!;
  }

  /** Every head this process learned from a witness must be a prefix of `state` (read under the lock); else the witness's sticky alarm. */
  #assertKnownIn(state: ReplayState): void {
    for (const runtime of this.#runtimes) {
      const head = runtime.known?.head;
      if (head !== null && head !== undefined && !isPrefix(head, state)) this.#raise(runtime, this.#rollbackError(runtime, head, state, "network"));
    }
    if (this.#alarm !== undefined) throw this.#alarm;
  }

  /**
   * Brings one witness up to the local head: statement(s), key events (owner key rotations) in order, each
   * delivered together with the statement for its head when the witness does not hold it yet (POST …/key-events,
   * docs/reference/witness-operations.md §7.3), re-signing on STALE_PREVIOUS. What to send is decided, and a statement signed, under the
   * writer lock against one state (rule W2, docs/WITNESS.md §2); the network calls happen after the lock is released.
   * A witness latest that is not a prefix of the file is first reconciled (a prepared rotation it holds is completed, a
   * pre-rotated rotation supersedes its chain), then judged.
   */
  async #bringUp(runtime: Runtime): Promise<void> {
    for (let attempt = 0; attempt < 24; attempt += 1) {
      if (this.#alarm !== undefined) throw this.#alarm;
      const latest = runtime.known?.head ?? null;
      const step = await this.#underLock(async (state) => {
        const historyId = state.eventHistoryHashes[0]!;
        // W2, on the state read under the lock: every witness head this process knows, and `previous` itself, are prefixes of it.
        this.#assertKnownIn(state);
        if (latest !== null && !isPrefix(latest, state)) throw this.#raise(runtime, this.#rollbackError(runtime, latest, state, "network"));
        const next = this.#pendingRotationsOf(runtime, state)[0];
        if (next !== undefined && latest !== null && latest.position >= next.r) {
          // Statement r is held (or the witness moved past r under a key the rotation kept): deliver the key event alone.
          return { kind: "deliver" as const, state, historyId, next, signed: undefined };
        }
        const target = next === undefined ? headAt(state, state.head.position) : headAt(state, next.r);
        if (target.position === 0 || (latest !== null && latest.position >= target.position)) return { kind: "done" as const };
        const signed = await this.#statement(runtime, state, target, latest);
        return next === undefined ? { kind: "submit" as const, state, historyId, target, signed } : { kind: "deliver" as const, state, historyId, next, signed };
      });
      if (step === undefined || step.kind === "done") return;
      const { state, historyId } = step;
      if (step.kind === "deliver") {
        const { next, signed } = step;
        const what = "owner key rotation";
        const result = await runtime.client.keyEvent(historyId, { event: next.event, previousHead: next.previousHead, eventHead: next.rotationHead, ...(signed === undefined ? {} : { statement: signed }) });
        switch (result.kind) {
          case "ACCEPTED":
            runtime.epochs = result.epochs;
            if (result.latest !== null) {
              this.#judge(runtime, result.latest.head);
              this.#learn(runtime, result.latest.head);
              this.#hold(runtime, result.latest);
            }
            runtime.registered = true;
            continue;
          case "NOT_REGISTERED":
            await this.#register(runtime, state);
            this.#learn(runtime, null);
            continue;
          case "STALE_PREVIOUS": {
            const answer = result.latest?.head ?? null;
            if (answer !== null && !isPrefix(answer, this.#state() ?? state) && await this.#reconcile(runtime, answer)) {
              const info = await runtime.client.history(historyId);
              if (info !== undefined) this.#adopt(runtime, info);
              continue;
            }
            this.#judge(runtime, answer);
            if (sameHead(answer, latest)) throw new EngineError("WITNESS_INVALID_RESPONSE", `witness ${runtime.config.url} answered STALE_PREVIOUS but names the previous head the statement carried (${describeHead(latest)})`, { url: runtime.config.url });
            this.#learn(runtime, answer);
            continue;
          }
          case "REJECTED":
            throw new EngineError("WITNESS_REJECTED", `witness ${runtime.config.url} refused the ${what} at position ${next.r}: ${result.code}: ${result.message}`,
              { url: runtime.config.url, code: result.code, status: result.status, ...(result.hint === undefined ? {} : { hint: result.hint }) });
        }
      }
      if (step.kind !== "submit") continue;
      const { target, signed } = step;
      const result = await runtime.client.submit(signed);
      switch (result.kind) {
        case "ACCEPTED":
          this.#judge(runtime, result.latest.head);
          this.#learn(runtime, result.latest.head);
          this.#hold(runtime, result.latest);
          runtime.registered = true;
          continue;
        case "STALE_PREVIOUS":
        case "SUPERSEDED": {
          const answer = result.latest?.head ?? null;
          if (answer !== null && !isPrefix(answer, this.#state() ?? state) && await this.#reconcile(runtime, answer)) {
            const info = await runtime.client.history(historyId);
            if (info !== undefined) this.#adopt(runtime, info);
            continue;
          }
          this.#judge(runtime, answer);
          if (sameHead(answer, latest)) throw new EngineError("WITNESS_INVALID_RESPONSE", `witness ${runtime.config.url} answered ${result.kind} but names the previous head the statement carried (${describeHead(latest)})`, { url: runtime.config.url });
          this.#learn(runtime, answer);
          continue;
        }
        case "EQUIVOCATION": {
          // The witness holds another head at this position (docs/reference/witness-protocol.md §9.2 rule 4), so this file is not on the witness chain:
          // exactly a failed prefix check (sticky; this handle never signs again). The witness recorded evidence and stays open.
          const entry = result.receipt.entry;
          const witnessLatest = result.latest?.head ?? null;
          if (witnessLatest !== null && !isPrefix(witnessLatest, this.#state() ?? state) && await this.#reconcile(runtime, witnessLatest)) {
            const info = await runtime.client.history(historyId);
            if (info !== undefined) this.#adopt(runtime, info);
            continue;
          }
          if (result.evidence === "OTHER" || entry.kind !== "EQUIVOCATION") {
            // The per-history evidence cap was reached: the entry is about another position. The fresh, signed latest decides.
            this.#judge(runtime, witnessLatest);
            throw new EngineError("WITNESS_INVALID_RESPONSE", `witness ${runtime.config.url} answered EQUIVOCATION for position ${target.position} without evidence about it, and its latest head is a prefix of this history`, { url: runtime.config.url });
          }
          const held = entry.first.statement.head;
          throw this.#raise(runtime, rollback(this.#host.path, "WITNESS_FORK",
            `remote witness ${runtime.config.url} holds a different owner-signed head at position ${target.position} than this history: the file is not on the witness chain (events were replaced; the witness recorded the conflicting statement${result.evidence === "SUBMITTED" ? "" : " signed at that position"} as evidence, leaf ${result.index})`,
            { witness: runtime.config.url, origin: runtime.client.origin, witnessedHead: held, observedHead: state.head, source: "network", equivocationIndex: result.index,
              ...(result.latest === null ? {} : { witnessLatest: result.latest.head }) }));
        }
        case "NOT_REGISTERED":
          await this.#register(runtime, state);
          this.#learn(runtime, null);
          continue;
        case "REJECTED":
          if (result.code === "SIGNATURE_INVALID" && result.hint === "ROTATION_REQUIRED") {
            const info = await runtime.client.history(historyId);
            if (info !== undefined) runtime.epochs = info.epochs;
            if (localRotations(state).some((rotation) => !(runtime.epochs ?? []).some((epoch) => epoch.fromPosition === rotation.r + 1))) continue;
          }
          throw new EngineError("WITNESS_REJECTED", `witness ${runtime.config.url} refused the head statement for position ${target.position}: ${result.code}: ${result.message}`,
            { url: runtime.config.url, code: result.code, status: result.status, ...(result.hint === undefined ? {} : { hint: result.hint }) });
      }
    }
    throw unavailable(`witness ${runtime.config.url}: no progress after repeated submissions (the latest head keeps moving)`, { url: runtime.config.url, reason: "NO_PROGRESS" });
  }

  async #register(runtime: Runtime, state: ReplayState): Promise<void> {
    this.#assertNotDenied(runtime, state);
    const held = await this.#registerGenesis(runtime, state);
    if (held !== null) {
      throw new EngineError("WITNESS_INVALID_RESPONSE", `witness ${runtime.config.url} answered "not registered", but its signed latest note holds a head at position ${held.position} for this history`,
        { url: runtime.config.url, reason: "LATEST_NOTE_MISMATCH" });
    }
    runtime.epochs = Object.freeze([Object.freeze({ fromPosition: 0, keys: ownerKeysAt(state, 0) })]);
  }

  /**
   * The signed statement for `target` with `previous = latest` (rule W2: the
   * caller judged `latest` a prefix in this process; `target` is a head of the
   * file). A statement pre-signed at rotation time is used when it matches;
   * otherwise the key in force at `target` signs: the store's signer, an
   * old-key signer held from a rotation, or the archived key file.
   */
  async #statement(runtime: Runtime, state: ReplayState, target: StatementHead, latest: StatementHead | null): Promise<SignedHeadStatement> {
    const previous = latest === null ? null : Object.freeze({ hash: latest.hash, position: latest.position });
    const keysAt = (position: number) => ownerKeysAt(state, position);
    const origin = this.#originOf(runtime);
    const doc = this.#readDoc() ?? this.#doc;
    for (const item of doc?.pending ?? []) {
      if (item.kind !== "statement" || item.statements === undefined || !sameHead(item.head, target) || origin === undefined) continue;
      const presigned = item.statements[origin];
      if (presigned !== undefined && sameHead(presigned.statement.previous, previous) && presigned.statement.head.canonicalTime === target.canonicalTime &&
        verifySignedHeadStatement(presigned, keysAt).ok) return presigned;
    }
    const signer = this.#signerAt(state, target.position);
    if (signer === undefined) {
      throw new EngineError("KEY_UNAVAILABLE", `no owner key in force at position ${target.position} is available to sign its head statement (keys: ${keysAt(target.position).map((key) => key.keyId).join(", ")}); keep the retired key file, or submit from the process that rotated`,
        { position: target.position });
    }
    return signHeadStatement(signer, Object.freeze({
      version: HEAD_STATEMENT_VERSION, historyId: state.eventHistoryHashes[0]!, domain: state.genesis.domain as never, head: target, previous,
    }));
  }

  /**
   * A signer for a key in force at `position`: the store's, one held from a
   * rotation in this process, or a key file beside the history. Archived key
   * files may carry a clash suffix (`<history>.owner-key.<id>-2.retired.json`),
   * so every `<history>.owner-key.*.retired.json` is a candidate and a file is
   * used only when the key it holds matches a key in force there by key id,
   * scheme AND public key, never by its name.
   */
  #signerAt(state: ReplayState, position: number): Signer | undefined {
    const current = this.#host.signer();
    if (current !== undefined && ownerKeyInForce(state, position, current)) return current;
    for (const held of [...this.#retained].reverse()) if (ownerKeyInForce(state, position, held)) return held;
    for (const path of [...retiredOwnerKeyFilesFor(this.#host.path), ownerKeyPathFor(this.#host.path)]) {
      let loaded: Signer;
      try { loaded = loadOwnerKeyFile(path); } catch { continue; }
      if (ownerKeyInForce(state, position, loaded)) return loaded;
    }
    return undefined;
  }

  /**
   * The heads whose statements a witness still needs and that no available key
   * can sign: each rotation head `r` the witness has not recorded (its `epochs`
   * lack the epoch from `r + 1`) and does not hold yet (`latest` before `r`),
   * signed only by the key that rotation retired; and the current head.
   * `epochs` / `latest` `undefined`: the witness is unknown (every rotation head counts).
   */
  headsWithoutSigner(state: ReplayState, witness: Readonly<{ epochs?: readonly OwnerKeyEpoch[]; latest?: Readonly<{ position: number }> | null }> = {}): readonly number[] {
    const missing: number[] = [];
    const recorded = new Set((witness.epochs ?? []).map((epoch) => epoch.fromPosition));
    for (const rotation of localRotations(state)) {
      if (recorded.has(rotation.r + 1)) continue;
      if (witness.latest !== undefined && witness.latest !== null && witness.latest.position >= rotation.r) continue;
      if (this.#signerAt(state, rotation.r) === undefined) missing.push(rotation.r);
    }
    const head = state.head.position;
    const held = witness.latest !== undefined && witness.latest !== null && witness.latest.position >= head;
    if (head > 0 && !held && !missing.includes(head) && this.#signerAt(state, head) === undefined) missing.push(head);
    return Object.freeze(missing);
  }

  // ---- owner integration

  /**
   * Before the first owner-keyed write of this process: a network view (never
   * the side file's word). Rollback evidence throws; unreachable witnesses do
   * not (the statements queue). `undefined` when there is nothing to wait for,
   * so a write that needs no network stays synchronous up to the store lock.
   * At the unwitnessed-events bound it flushes first, as `irontrellis witness sync` does: runtime events (refusals, effects,
   * intents) count toward the bound but queue no statement, so without the flush the next owner write would be refused.
   * Rollback evidence and invalid answers throw as before; an unreachable witness falls through to guardWrite.
   */
  beforeOwnerWrite(): Promise<void> | undefined {
    if (!this.active || this.#host.inspect) return undefined;
    if (this.#alarm !== undefined) throw this.#alarm;
    const state = this.#state();
    if (state === undefined || !this.#ownerKeyed(state)) return undefined;
    // A prepared rotation left by an interrupted rotation (docs/reference/witness-operations.md §7.1) is resolved before any owner write.
    const pending = existsSync(this.#pendingPath);
    const atLimit = this.#unwitnessed(state) >= this.#policy!.maxUnwitnessedEvents;
    if (this.#writeChecked && this.#openChecked && !pending && !atLimit) return undefined;
    this.#writeChecked = true;
    const started = Date.now();
    const checked = this.check({ force: true }).then(() => { if (pending) this.#settlePending(started); });
    return (atLimit ? checked.then(() => this.flush()) : checked).then(undefined, (error: unknown) => {
      if (this.#isAlarm(error) || (error instanceof EngineError && (error.code === "ROLLBACK_DETECTED" || error.code === "WITNESS_SPLIT_VIEW"))) throw error;
      // A witness that refused the registration, or denies one it signed: the write is refused (guardWrite would refuse it too).
      if (error instanceof EngineError && error === this.#refused()) throw error;
      // Not enough verifiable answers and one of them did not verify (a missing or wrong signed latest note, a tampered
      // receipt: possibly an older answer replayed to hide a rollback, docs/reference/witness-protocol.md §9.8): that is not unavailability, the
      // write is refused (nothing is appended to a copy no witness vouched for). The next write asks again.
      if (error instanceof EngineError && error.code === "WITNESS_UNAVAILABLE" && (error.detail as { cause?: unknown } | undefined)?.cause === "WITNESS_INVALID_RESPONSE") {
        this.#writeChecked = false;
        throw unavailable(`history ${this.#host.path}: owner writes are refused: ${error.message}`, { ...(error.detail as Record<string, unknown>), reason: "INVALID_ANSWER" });
      }
      // Unreachable: the write proceeds and its statement waits for a verified view (never signed before one); at the bound,
      // guardWrite then refuses it under the lock (MAX_UNWITNESSED, naming this error).
      if (atLimit && error instanceof EngineError) this.#lastError = error;
      if (this.#pendingOpen !== undefined && this.#policy!.requireOnOpen) throw this.#pendingOpen;
    });
  }

  /** After an owner write: sync mode submits now (rollback evidence throws; an unreachable witness leaves the statement queued). */
  afterOwnerWrite(): Promise<void> | undefined {
    if (!this.active || this.#host.inspect || this.#policy!.mode !== "sync") return undefined;
    return this.submit().then(() => undefined, (error: unknown) => {
      if (this.#isAlarm(error) || (error instanceof EngineError && (error.code === "ROLLBACK_DETECTED" || error.code === "WITNESS_SPLIT_VIEW"))) throw error;
      this.#lastError = error instanceof EngineError ? error : unavailable(messageOf(error));
    });
  }

  // ---- two-phase rotation (docs/reference/witness-operations.md §7.1)

  /** The verifier keys of the witnesses the history binds (the ones a two-phase rotation needs). */
  #boundKeys(): ReadonlySet<string> {
    return this.#groups.find((group) => group.name === "bound")?.keys ?? new Set<string>();
  }

  /** True when the history binds remote witnesses (the two-phase rotation is the default then). */
  get hasBoundWitnesses(): boolean {
    return this.active && this.#boundKeys().size > 0;
  }

  /** The URLs of the bound witnesses this process has not verified at exactly `head` since `since` (a flush brings them there). */
  boundNotAt(head: Readonly<{ hash: string; position: number }>, since: number): readonly string[] {
    const bound = this.#boundKeys();
    return Object.freeze(this.#runtimes.filter((runtime) => bound.has(runtime.config.verifierKey) &&
      !(runtime.known !== undefined && runtime.known.at >= since && sameHead(runtime.known.head, head))).map((runtime) => runtime.config.url));
  }

  /**
   * Hands the prepared rotation (with its old-key statement for head r, `previous` = r - 1) to every bound witness in one
   * `POST …/key-events` each, without the writer lock of this session (the caller, `rotateOwnerKey`, holds the store's).
   * A witness whose answer is lost is asked again. Nothing is learned yet: `commitDelivered` does it once head r is in the
   * file. `accepted`: witnesses that now hold head r; `refused`: answered without recording it; `unknown`: no answer.
   */
  async deliverPreparedRotation(record: PendingRotationRecord): Promise<Readonly<{ accepted: readonly string[]; refused: readonly Readonly<{ url: string; code: string; message: string }>[]; unknown: readonly Readonly<{ url: string; message: string }>[] }>> {
    const bound = this.#boundKeys();
    const at = (head: HistoryHead) => Object.freeze({ hash: head.hash, position: head.position });
    const accepted: string[] = [], refused: { url: string; code: string; message: string }[] = [], unknown: { url: string; message: string }[] = [];
    this.#delivered = [];
    await Promise.all(this.#runtimes.filter((runtime) => bound.has(runtime.config.verifierKey)).map(async (runtime) => {
      const url = runtime.config.url;
      const holds = (latest: RemoteWitnessedHead | null | undefined): boolean => latest !== null && latest !== undefined && sameHead(latest.head, record.head) && latest.head.canonicalTime === record.head.canonicalTime;
      try {
        const result = await runtime.client.keyEvent(record.historyId, { event: record.event, previousHead: at(record.previousHead), eventHead: at(record.head), statement: record.statement });
        if (result.kind === "ACCEPTED" && holds(result.latest)) {
          this.#delivered.push({ runtime, epochs: result.epochs, latest: result.latest! });
          accepted.push(url);
          return;
        }
        refused.push({ url, code: result.kind === "REJECTED" ? result.code : result.kind, message: "message" in result ? result.message : result.kind === "ACCEPTED" ? "the witness recorded the rotation but its latest head is another one" : "the history is not registered" });
      } catch (error) {
        this.#failed(runtime, error);
        if (error instanceof EngineError && (error.code === "WITNESS_REJECTED" || error.code === "WITNESS_SPLIT_VIEW")) {
          refused.push({ url, code: error.code, message: error.message });
          return;
        }
        // The answer was lost (or did not verify): whether the witness recorded the rotation is asked again.
        try {
          const info = await runtime.client.history(record.historyId);
          if (holds(info?.latest)) {
            this.#delivered.push({ runtime, epochs: info!.epochs, latest: info!.latest! });
            accepted.push(url);
          } else if (info !== undefined && info.latest !== null && sameHead(info.latest.head, record.previousHead)) {
            refused.push({ url, code: codeOf(error), message: messageOf(error) });
          } else unknown.push({ url, message: messageOf(error) });
        } catch (again) {
          unknown.push({ url, message: `${messageOf(error)}; asked again: ${messageOf(again)}` });
        }
      }
    }));
    return Object.freeze({ accepted: Object.freeze(accepted), refused: Object.freeze(refused), unknown: Object.freeze(unknown) });
  }

  /** Once the prepared rotation is in the file: what the accepting witnesses answered (their epochs, their latest head r) is learned. */
  commitDelivered(): void {
    for (const { runtime, epochs, latest } of this.#delivered) {
      runtime.epochs = epochs;
      this.#learn(runtime, latest.head);
      this.#hold(runtime, latest);
      runtime.registered = true;
      runtime.lastError = undefined;
    }
    this.#delivered = [];
    this.#persistKnowledge({ sealAsync: true });
  }

  /** Runs `append` (the prepared rotation's own append) past the ROTATION_PENDING guard. */
  allowingPending<T>(append: () => T): T {
    this.#pendingAllowed += 1;
    try { return append(); } finally { this.#pendingAllowed -= 1; }
  }

  /** While a two-phase rotation of this process is between delivery and its local append, a witness answer holding head r waits for it. */
  beginPreparedRotation(): () => void {
    let end!: () => void;
    const done = new Promise<void>((resolve) => { end = resolve; });
    this.#preparing = done;
    return () => { if (this.#preparing === done) this.#preparing = undefined; end(); };
  }

  /**
   * Resolves an interrupted prepared rotation (docs/reference/witness-operations.md §7.1): every witness is asked; one that holds its head
   * makes the store append it (`COMPLETED`); when every bound witness answered and none holds it, the record is removed
   * (`DISCARDED`). `RECORDED` / `OBSOLETE`: the record is left over (the owner removes it and settles the key files);
   * `UNRESOLVED`: some bound witness did not answer. Rollback evidence throws.
   */
  async resolvePending(): Promise<"NONE" | "RECORDED" | "OBSOLETE" | "COMPLETED" | "DISCARDED" | "UNRESOLVED"> {
    if (!existsSync(this.#pendingPath)) return "NONE";
    const record = readPendingRotation(this.#pendingPath);
    if (record === undefined) return "NONE";
    const state = this.#state();
    if (record === null || state === undefined) return "OBSOLETE";
    const before = judgePendingRotation(state, record).status;
    if (before !== "OUTSTANDING") return before;
    if (this.#disabled || this.#host.inspect) return "UNRESOLVED";
    const started = Date.now();
    if (this.active) {
      await Promise.all(this.#runtimes.map((runtime) => this.#refresh(runtime)));
      this.#persistKnowledge();
      if (this.#alarm !== undefined) throw this.#alarm;
    }
    const after = this.#state();
    if (after !== undefined && judgePendingRotation(after, record).status === "RECORDED") return "COMPLETED";
    return this.#settlePending(started) ? "DISCARDED" : "UNRESOLVED";
  }

  /** Removes an OUTSTANDING record when every bound witness answered since `since` and none holds its head. */
  #settlePending(since: number): boolean {
    const state = this.#state();
    const record = state === undefined ? undefined : this.#outstanding(state);
    if (record === undefined) return false;
    const bound = this.#boundKeys();
    const runtimes = this.#runtimes.filter((runtime) => bound.has(runtime.config.verifierKey));
    if (runtimes.some((runtime) => runtime.known === undefined || runtime.known.at < since || sameHead(runtime.known.head, record.head))) return false;
    removePendingRotation(this.#pendingPath);
    return true;
  }

  /**
   * The last good head L for the key-event bundle of the rotation at `r` (docs/reference/witness-operations.md §7.3, §7.4): the newest head a
   * bound witness that has not recorded the rotation (as far as this process knows; else any bound witness) held on its
   * chain before r, from this process or the side file's receipts. `undefined` when none is known.
   */
  chainFrom(state: ReplayState, r: number): StatementHead | undefined {
    const bound = this.#boundKeys();
    const runtimes = this.#runtimes.filter((runtime) => bound.has(runtime.config.verifierKey));
    const lacking = runtimes.filter((runtime) => runtime.epochs === undefined || !runtime.epochs.some((epoch) => epoch.fromPosition === r + 1));
    for (const group of [lacking, runtimes]) {
      for (const runtime of group) {
        const last = this.#lastGood(runtime, state, r - 1);
        if (last !== undefined) return last.head;
      }
    }
    return undefined;
  }

  /**
   * After an owner key rotation (docs/WITNESS.md §7): the rotation is pushed to every witness right away, in async mode
   * too (not left to the worker): until a witness records it, that witness still accepts head statements signed by the
   * retired key. Rollback evidence throws; an unreachable witness leaves the rotation first in the queue (the worker and
   * every later submission post it before any later head) and `witness status` shows it pending.
   */
  afterRotation(): Promise<void> | undefined {
    if (!this.active || this.#host.inspect) return undefined;
    return this.submit().then(() => undefined, (error: unknown) => {
      if (this.#isAlarm(error) || (error instanceof EngineError && (error.code === "ROLLBACK_DETECTED" || error.code === "WITNESS_SPLIT_VIEW"))) throw error;
      this.#lastError = error instanceof EngineError ? error : unavailable(messageOf(error));
      if (this.#policy!.mode === "async") this.#schedule(1000);
    });
  }

  /**
   * docs/WITNESS.md §7 step 1, called by `rotateOwnerKey` right after the rotation was appended and
   * before the key files are swapped, while the old signer is held: signs the
   * statement for the rotation head `r` with the old key for every witness
   * whose latest this process verified, and persists it with the rotation
   * (previousHead = head r-1, rotationHead = head r) in the side file.
   */
  async recordRotation(input: Readonly<{ rotation: CanonicalEvent; previousHead: HistoryHead; rotationHead: HistoryHead; oldSigner: Signer }>): Promise<void> {
    if (!this.active || this.#host.inspect) return;
    this.#retained.push(input.oldSigner);
    const state = this.#state();
    if (state === undefined) return;
    // Runs under rotateOwnerKey's writer lock, right after this handle appended the rotation (its trusted head): sign only
    // against a file that still contains it (docs/WITNESS.md §2).
    this.#assertTrusted(state);
    this.#trusted = Object.freeze({ hash: state.head.hash, position: state.head.position });
    const target = headAt(state, input.rotationHead.position);
    const statements: Record<string, SignedHeadStatement> = {};
    if (this.#alarm === undefined && ownerKeyInForce(state, target.position, input.oldSigner)) {
      for (const runtime of this.#runtimes) {
        const origin = this.#originOf(runtime), latest = runtime.known?.head;
        if (origin === undefined || latest === undefined || (latest !== null && (!isPrefix(latest, state) || latest.position >= target.position))) continue;
        try {
          statements[origin] = await signHeadStatement(input.oldSigner, Object.freeze({
            version: HEAD_STATEMENT_VERSION, historyId: state.eventHistoryHashes[0]!, domain: state.genesis.domain as never, head: target,
            previous: latest === null ? null : Object.freeze({ hash: latest.hash, position: latest.position }),
          }));
        } catch { /* the archived key file signs it later */ }
      }
    }
    const statementItem: PendingStatement = Object.freeze({ kind: "statement", head: target, ...(Object.keys(statements).length === 0 ? {} : { statements: Object.freeze(statements) }) });
    this.#update((doc) => ({
      ...doc,
      pending: [...doc.pending.filter((item) => item.kind !== "statement" || item.statements !== undefined), statementItem, {
        kind: "rotation", rotation: JSON.parse(JSON.stringify(input.rotation)) as Record<string, unknown>,
        previousHead: { hash: input.previousHead.hash, position: input.previousHead.position }, rotationHead: { hash: input.rotationHead.hash, position: input.rotationHead.position },
      }],
    }));
    if (this.#policy!.mode === "async") this.#schedule(0);
  }

  /** Waits until a quorum holds the current head and every rotation was posted; rejects with the alarm or the last witness error. */
  async flush(): Promise<void> {
    if (!this.active || this.#host.inspect) return;
    if (this.#alarm !== undefined) throw this.#alarm;
    if (existsSync(this.#pendingPath)) await this.resolvePending();
    const state = this.#state();
    if (state === undefined || (!this.#ownerKeyed(state) && !this.#hasPresigned())) return;
    await this.submit();
  }

  /** Replaces the side-file policy (owner `addWitness` / `removeWitness` / CLI) and reloads. */
  setPolicy(policy: StoredPolicy | undefined, options: Readonly<{ clearSplitView?: readonly string[] }> = {}): void {
    this.#update((doc) => {
      const witnesses = { ...doc.witnesses };
      for (const [origin, entry] of Object.entries(witnesses)) {
        if (entry.splitView !== undefined && options.clearSplitView?.includes(entry.verifierKey)) { const { splitView: _dropped, ...rest } = entry; witnesses[origin] = rest; }
      }
      const { policy: _old, ...rest } = doc;
      return { ...rest, witnesses, ...(policy === undefined ? {} : { policy }) };
    });
    this.#load();
  }

  /** Re-reads bindings and the side file (after a binding event was appended). */
  reload(): void {
    this.#load();
  }

  // ---- accepting a loss (docs/reference/witness-operations.md §6.2)

  /** The history as the file holds it, without the witness guards (file problems still throw). */
  fileState(): ReplayState | undefined {
    return this.#state();
  }

  /**
   * For each witness (by verifier key): its verified, network-backed evidence
   * that this copy lacks a head it holds (the witness is asked again unless this
   * handle already holds such an alarm for it). Nothing on disk counts (a side
   * file could be forged to make an owner drop a healthy witness). Throws
   * INVALID_INPUT for a witness that is not in the policy, shows no rollback of
   * this copy (its latest is a prefix), cannot be reached, or shows a split view.
   */
  async lossEvidence(verifierKeys: readonly string[]): Promise<readonly LossEvidence[]> {
    const state = this.#state();
    if (!this.active || state === undefined) throw new EngineError("INVALID_INPUT", "this history has no remote witness");
    const evidence: LossEvidence[] = [];
    for (const key of verifierKeys) {
      const runtime = this.#runtimes.find((candidate) => candidate.config.verifierKey === key);
      if (runtime === undefined) throw new EngineError("INVALID_INPUT", `${key} is not a remote witness of this history`);
      let found = this.#lossOf(runtime);
      if (found === undefined) {
        await this.#refresh(runtime);
        found = this.#lossOf(runtime);
      }
      if (found === undefined) {
        const why = this.#alarms.get(key)?.code === "WITNESS_SPLIT_VIEW" ? "it shows a split view, not a head this copy lacks"
          : runtime.lastError !== undefined ? `it could not confirm one (${runtime.lastError.code}: ${runtime.lastError.message})`
          : "its latest head is a prefix of this copy";
        throw new EngineError("INVALID_INPUT", `witness ${runtime.config.url} shows no rollback of this copy to accept: ${why}. Accepting a loss needs the witness's own verified answer; remove it without accepting a loss, or restore a copy that contains its latest head`,
          { url: runtime.config.url, reason: "NO_LOSS" });
      }
      evidence.push(found);
    }
    return Object.freeze(evidence);
  }

  /** This handle's verified rollback alarm for `runtime`, as loss evidence. */
  #lossOf(runtime: Runtime): LossEvidence | undefined {
    const alarm = this.#alarms.get(runtime.config.verifierKey);
    if (alarm?.code !== "ROLLBACK_DETECTED") return undefined;
    const detail = alarm.detail as { reason?: unknown; witnessedHead?: unknown; source?: unknown } | undefined;
    const head = detail?.witnessedHead as StatementHead | undefined;
    if (detail?.source !== "network" || head === undefined || (detail.reason !== "WITNESS_AHEAD" && detail.reason !== "WITNESS_FORK")) return undefined;
    return Object.freeze({
      url: runtime.config.url, verifierKey: runtime.config.verifierKey, reason: detail.reason,
      head: Object.freeze({ hash: head.hash, position: head.position, canonicalTime: head.canonicalTime }),
    });
  }

  /**
   * Leaves the witnesses `verifierKeys` out of this handle (their alarms and
   * runtimes; the other witnesses' alarms stay), so that the owner-signed
   * unbinding that accepts their loss can be written. The next owner write asks
   * the remaining witnesses again. Returns what `restoreLoss` puts back when
   * that write fails.
   */
  acceptLoss(verifierKeys: readonly string[]): AcceptedLoss {
    return this.setAside(verifierKeys, { dropAlarms: true });
  }

  /**
   * Leaves the witnesses `verifierKeys` out of this handle for the write that
   * removes them. With `dropAlarms` (an accepted loss) their alarms go too;
   * without it an alarm of theirs still refuses the write (a witness showing a
   * rollback is not removed by a plain removal), and only a refusal
   * (WITNESS_REJECTED, a denied registration) stops blocking.
   */
  setAside(verifierKeys: readonly string[], options: Readonly<{ dropAlarms: boolean }>): AcceptedLoss {
    const keys = [...new Set(verifierKeys)];
    const saved: AcceptedLoss = Object.freeze({
      keys: Object.freeze(keys),
      alarms: Object.freeze(keys.flatMap((key) => (this.#alarms.has(key) ? [Object.freeze([key, this.#alarms.get(key)!] as const)] : []))),
      runtimes: Object.freeze(this.#runtimes.filter((runtime) => keys.includes(runtime.config.verifierKey))),
    });
    for (const key of keys) {
      if (options.dropAlarms) this.#alarms.delete(key);
      this.#excluded.add(key);
    }
    this.#writeChecked = false;
    this.#load();
    return saved;
  }

  /** The refusal (WITNESS_REJECTED, or a denied registration) this handle holds for a witness, if any. */
  refusalOf(verifierKey: string): EngineError | undefined {
    const runtime = this.#runtimes.find((candidate) => candidate.config.verifierKey === verifierKey);
    return runtime?.rejected ?? runtime?.denied;
  }

  /** Undoes `acceptLoss` (the unbinding was not written). */
  restoreLoss(saved: AcceptedLoss): void {
    for (const key of saved.keys) this.#excluded.delete(key);
    for (const [key, alarm] of saved.alarms) if (!this.#alarms.has(key)) this.#alarms.set(key, alarm);
    this.#load();
    this.#runtimes = this.#runtimes.map((runtime) => saved.runtimes.find((kept) => kept.config.verifierKey === runtime.config.verifierKey && kept.config.url === runtime.config.url) ?? runtime);
  }

  /** After an accepted loss was recorded: the side file forgets what it remembered of those witnesses. */
  forgetWitnesses(verifierKeys: readonly string[]): void {
    this.#update((doc) => ({ ...doc, witnesses: Object.fromEntries(Object.entries(doc.witnesses).filter(([, entry]) => !verifierKeys.includes(entry.verifierKey))) }));
    this.#load();
  }

  // ---- worker

  #schedule(delay: number): void {
    if (this.#alarm !== undefined || this.#closed) return;
    if (this.#timer !== undefined || this.#working) { this.#dirty = true; return; }
    this.#timer = setTimeout(() => { this.#timer = undefined; this.#work(); }, delay);
    this.#timer.unref?.();
  }

  #work(): void {
    this.#working = true;
    this.#dirty = false;
    this.submit().then(() => { this.#failures = 0; }, () => { this.#failures += 1; }).finally(() => {
      this.#working = false;
      if (this.#alarm !== undefined) return;
      if (this.#failures > 0 && this.#failures <= 20) {
        // Exponential backoff with jitter, bounded at 30 s; gives up after 20 failures until the next write or flush.
        const base = Math.min(30_000, 250 * 2 ** Math.min(this.#failures, 7));
        this.#schedule(Math.floor(base / 2 + Math.random() * (base / 2)));
      } else if (this.#dirty) this.#schedule(0);
    });
  }

  /** Stops the worker (the store is closing). Queued items stay in the side file. */
  close(): void {
    this.#closed = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
  }

  // ---- reports

  #isBound(runtime: Runtime, state: ReplayState | undefined): boolean {
    return state !== undefined && boundWitnessesOf(state).some((b) => b.verifierKey === runtime.config.verifierKey);
  }

  status(): WitnessStatusReport {
    const policy = this.#stored!;
    let state: ReplayState | undefined;
    try { state = this.#state(); } catch { state = undefined; }
    const doc = this.#readDoc() ?? this.#doc;
    if (doc !== undefined) this.#doc = doc;
    const witnesses = this.#runtimes.map((runtime) => {
      const origin = this.#originOf(runtime), entry = origin === undefined ? undefined : doc?.witnesses[origin];
      const cached = entry?.latest;
      const sealed = state !== undefined && cached !== undefined && this.#sealedCached(runtime, state, doc) === cached;
      const source = runtime.known !== undefined ? "network" as const : cached === undefined ? "none" as const : sealed ? "sealed-cache" as const : "unsealed-cache" as const;
      const latest = runtime.known !== undefined ? runtime.known.head : cached?.head;
      return Object.freeze({
        url: runtime.config.url, name: runtime.client.name, verifierKey: runtime.config.verifierKey, ...(origin === undefined ? {} : { origin }), bound: this.#isBound(runtime, state),
        ...(state !== undefined && this.#isBound(runtime, state) && boundRegistrationOf(state, runtime.config.verifierKey) === undefined ? { bindingWithoutReceipt: true } : {}),
        registered: runtime.registered || entry?.registered === true, ...(latest === undefined ? {} : { latest }), source,
        ...(runtime.known !== undefined ? { knownAt: runtime.known.at } : cached !== undefined ? { knownAt: cached.fetchedAt } : {}),
        ...(runtime.equivocations === undefined ? {} : { equivocations: runtime.equivocations }),
        ...(runtime.supersedes === undefined ? {} : { supersedes: runtime.supersedes }),
        pendingRotations: state === undefined || runtime.epochs === undefined ? null : this.#pendingRotationsOf(runtime, state).length,
        ...(this.#rejectionOf(runtime, entry) === undefined ? {} : { rejected: this.#rejectionOf(runtime, entry)! }), ...(runtime.denied === undefined ? {} : { registrationDenied: errorView(runtime.denied)! }),
        ...(entry?.checkpoint === undefined ? {} : { checkpointSize: entry.checkpoint.size }), ...(entry?.splitView === undefined ? {} : { splitView: entry.splitView.message }),
        ...(runtime.lastError === undefined ? {} : { lastError: errorView(runtime.lastError)! }),
      });
    });
    const alarm = this.#alarm ?? (state === undefined ? undefined : this.#fileProblem(state));
    const rejected = witnesses.find((w) => w.rejected !== undefined);
    const pendingRecord = state === undefined ? undefined : this.#outstanding(state);
    // Known to lack a rotation, or a rotation still queued (the queue drops it once every witness shows it recorded).
    const rotationIncomplete = witnesses.some((w) => w.bound && w.pendingRotations !== null && w.pendingRotations > 0) ||
      (state !== undefined && localRotations(state).length > 0 && (doc?.pending ?? []).some((item) => item.kind === "rotation"));
    return Object.freeze({
      statePath: this.#statePath, ...(state === undefined ? {} : { historyId: state.eventHistoryHashes[0]! }), policy,
      bound: state === undefined ? Object.freeze([]) : boundWitnessesOf(state), ...(this.#boundPolicy === undefined ? {} : { boundPolicy: this.#boundPolicy }),
      ...(alarm === undefined ? {} : { alarm: Object.freeze({ code: alarm.code, message: alarm.message, ...(typeof (alarm.detail as { reason?: unknown } | undefined)?.reason === "string" ? { reason: (alarm.detail as { reason: string }).reason } : {}) }) }),
      ...(rejected === undefined ? {} : { rejected: Object.freeze({ url: rejected.url, code: rejected.rejected!.code, message: rejected.rejected!.message }) }),
      ...(this.#minimum === undefined ? {} : { minimumPolicyFile: this.#minimum.path }),
      ...(state === undefined ? { keyRotations: 0, commitmentRotations: 0 } : ownerKeyRotationCounts(state)), rotationIncomplete,
      ...(pendingRecord === undefined ? {} : { rotationPending: Object.freeze({ position: pendingRecord.head.position, hash: pendingRecord.head.hash, eventId: pendingRecord.event.id }) }),
      checkRequired: this.#pendingOpen !== undefined, ownerKeyed: state !== undefined && this.#ownerKeyed(state), ...(state === undefined ? {} : { head: state.head }),
      witnessedPosition: state === undefined ? null : this.#witnessedPosition(state), unwitnessedEvents: state === undefined ? 0 : this.#unwitnessed(state),
      pending: Object.freeze([...(doc?.pending ?? [])]), witnesses: Object.freeze(witnesses),
    });
  }

  /** Findings for the synchronous `verify()`: this process's alarm and the side file's evidence; a note that the witnesses were not asked. */
  cachedFindings(state: ReplayState | undefined): RemoteFindings {
    if (!this.active || state === undefined || !isTrellis(state.format)) return Object.freeze({ failures: [], notes: [], witnesses: [], status: "NOT_CONSULTED" });
    const failures: string[] = [], notes: string[] = [];
    let status: RemoteWitnessStatus = "NOT_CONSULTED";
    const problem = this.#alarm ?? this.#fileProblem(state);
    if (problem !== undefined) {
      if (problem.code === "WITNESS_SPLIT_VIEW") { failures.push(`REMOTE_WITNESS_SPLIT_VIEW: ${problem.message}`); status = "SPLIT_VIEW"; }
      else { failures.push(`REMOTE_WITNESS_ROLLBACK: ${problem.message}`); status = "ROLLBACK"; }
    }
    notes.push(...this.#receiptlessNotes(state));
    notes.push(`REMOTE_WITNESS_NOT_CONSULTED: ${this.#runtimes.length} remote witness(es) are configured for this history but were not asked by this synchronous check; verify with the witnesses (irontrellis verify, verifyWithWitnesses) to rule out a restored older copy`);
    return Object.freeze({ failures, notes, witnesses: [], status });
  }

  /** Bound witnesses whose binding carries no signed REGISTERED receipt (bound while unreachable). */
  #receiptless(state: ReplayState): readonly Runtime[] {
    return this.#runtimes.filter((runtime) => this.#isBound(runtime, state) && boundRegistrationOf(state, runtime.config.verifierKey) === undefined);
  }

  #receiptlessNotes(state: ReplayState): string[] {
    return this.#receiptless(state).map((runtime) =>
      `REMOTE_WITNESS_BINDING_WITHOUT_RECEIPT: remote witness ${runtime.config.url} is bound without its signed registration receipt (it was bound while unreachable): its "not registered" answers are unsigned and count as unreachable, and readers get no sealed-cache shortcut for it; run irontrellis witness add ${runtime.config.url} --verifier-key ${runtime.config.verifierKey} again while it is reachable to record the receipt`);
  }

  /**
   * The remote part of verification: every witness is asked for its latest
   * head (receipt and checkpoint verified, checkpoint consistency checked) and
   * the answer compared with the file. Rollback, split view or an invalid
   * answer from ANY witness fails (a "not registered" answer from a witness the
   * history binds with its signed REGISTERED receipt is invalid); equivocations
   * a witness recorded for the history are a note (REMOTE_WITNESS_EQUIVOCATION_RECORDED n,
   * docs/reference/witness-operations.md); fewer than `n - quorum + 1` valid
   * answers fails as REMOTE_WITNESS_UNREACHABLE unless `allowUnreachable`.
   */
  async remoteFindings(state: ReplayState, options: Readonly<{ allowUnreachable?: boolean }> = {}): Promise<RemoteFindings> {
    if (!this.active || !isTrellis(state.format)) return Object.freeze({ failures: [], notes: [], witnesses: [], status: "NOT_CONSULTED" });
    const historyId = state.eventHistoryHashes[0]!;
    const reports = await Promise.all(this.#runtimes.map(async (runtime): Promise<RemoteWitnessReport> => {
      const base = { url: runtime.config.url, name: runtime.client.name, verifierKey: runtime.config.verifierKey, bound: this.#isBound(runtime, state) };
      try {
        if (runtime.client.origin === undefined) await runtime.client.checkpoint();
        const info = await runtime.client.history(historyId);
        const origin = runtime.client.origin;
        const where = { ...base, ...(origin === undefined ? {} : { origin }), receiptVerified: true, consistent: true };
        if (info === undefined) {
          // A witness the history binds with its own signed REGISTERED receipt cannot unknow the history: its denial is invalid
          // (after a look at its current checkpoint: a split view is the stronger finding).
          if (boundRegistrationOf(state, runtime.config.verifierKey) !== undefined) await runtime.client.checkpoint();
          try { this.#assertNotDenied(runtime, state); } catch (denial) {
            return Object.freeze({ ...where, status: "INVALID" as const, registrationDenied: true, receiptVerified: false, error: Object.freeze({ code: codeOf(denial), message: messageOf(denial) }) });
          }
          // A bound witness bound without its receipt: an unsigned 404 is no answer (it never counts toward the bound set).
          if (base.bound) {
            const unsigned = this.#unsignedNotRegistered(runtime);
            runtime.lastError = unsigned;
            return Object.freeze({ ...where, status: "UNREACHABLE" as const, receiptVerified: false, error: Object.freeze({ code: unsigned.code, message: unsigned.message }) });
          }
          return Object.freeze({ ...where, status: "UNREGISTERED" as const, latest: null, unwitnessedTail: state.head.position });
        }
        runtime.denied = undefined;
        const latest = info.latest?.head ?? null;
        const checkpointSize = info.latest?.checkpoint.size;
        runtime.epochs = info.epochs;
        runtime.equivocations = info.equivocations;
        runtime.supersedes = info.supersedes;
        const evidence = info.lastEquivocation?.receipt.entry;
        const supersede = info.lastSupersede?.receipt.entry;
        const pendingRotationPositions = this.#pendingRotationsOf(runtime, state).map((rotation) => rotation.r);
        const found = {
          ...where, latest, ...(checkpointSize === undefined ? {} : { checkpointSize }),
          ...(info.equivocations === 0 ? {} : { equivocations: info.equivocations }),
          ...(info.lastEquivocation === undefined || evidence?.kind !== "EQUIVOCATION" ? {} : {
            lastEquivocation: Object.freeze({ index: info.lastEquivocation.index, position: evidence.second.statement.head.position, receivedAt: evidence.receivedAt }),
          }),
          ...(info.supersedes === 0 ? {} : { supersedes: info.supersedes }),
          ...(info.lastSupersede === undefined || supersede?.kind !== "SUPERSEDED" ? {} : {
            lastSupersede: Object.freeze({ index: info.lastSupersede.index, from: supersede.chain.statement.previous?.position ?? 0, heads: supersede.supersededCount, receivedAt: supersede.receivedAt }),
          }),
          ...(pendingRotationPositions.length === 0 ? {} : { pendingRotationPositions: Object.freeze(pendingRotationPositions) }),
        };
        if (latest !== null && !isPrefix(latest, state)) {
          // The head of the prepared rotation this history has not appended yet (a crash between the witness's acceptance and
          // the local append): not a rollback; the next owner command completes it (docs/reference/witness-operations.md §7.1).
          const record = this.#outstanding(state);
          if (record !== undefined && sameHead(record.head, latest) && record.head.canonicalTime === latest.canonicalTime) {
            return Object.freeze({ ...found, status: "OK" as const, rotationPending: true, unwitnessedTail: 0 });
          }
          return Object.freeze({ ...found, status: "ROLLBACK" as const });
        }
        this.#learn(runtime, latest);
        return Object.freeze({ ...found, status: "OK" as const, unwitnessedTail: state.head.position - (latest?.position ?? 0) });
      } catch (error) {
        const code = codeOf(error);
        this.#failed(runtime, error);
        const status = code === "WITNESS_SPLIT_VIEW" ? "SPLIT_VIEW" as const : code === "WITNESS_INVALID_RESPONSE" ? "INVALID" as const : "UNREACHABLE" as const;
        return Object.freeze({
          ...base, ...(runtime.client.origin === undefined ? {} : { origin: runtime.client.origin }), status, receiptVerified: status !== "INVALID", consistent: status !== "SPLIT_VIEW",
          error: Object.freeze({ code, message: messageOf(error) }),
        });
      }
    }));
    this.#persistKnowledge();
    // A split view recorded in the side file stays a finding (the file only adds findings, like the store's read guard):
    // after one, the witness may answer consistently with the checkpoint remembered BEFORE it, so asking again proves nothing.
    const doc = this.#readDoc() ?? this.#doc;
    for (const [index, report] of reports.entries()) {
      const recorded = Object.values(doc?.witnesses ?? {}).find((entry) => entry.verifierKey === report.verifierKey && entry.splitView !== undefined)?.splitView;
      if (recorded === undefined || report.status === "SPLIT_VIEW") continue;
      reports[index] = Object.freeze({
        ...report, status: "SPLIT_VIEW" as const, consistent: false,
        error: Object.freeze({ code: "WITNESS_SPLIT_VIEW", message: `recorded at ${new Date(recorded.detectedAt).toISOString()}: ${recorded.message}` }),
      });
    }
    const failures: string[] = [], notes: string[] = [];
    for (const report of reports) {
      const who = `remote witness ${report.url}${report.origin === undefined ? "" : ` (${report.origin})`}`;
      switch (report.status) {
        case "ROLLBACK": {
          const head = report.latest!;
          failures.push(`REMOTE_WITNESS_ROLLBACK: ${who} holds an owner-signed head at position ${head.position} that ${head.position > state.head.position ? `is past the end of this history (head position ${state.head.position}): events were removed` : "is not a prefix of this history: the history was rewritten or replaced"}`);
          break;
        }
        case "SPLIT_VIEW": failures.push(`REMOTE_WITNESS_SPLIT_VIEW: ${who} could not prove its log consistent with the checkpoint seen earlier: ${report.error?.message ?? ""}`); break;
        case "INVALID":
          failures.push(report.registrationDenied === true
            ? `REMOTE_WITNESS_INVALID: ${who} denies a registration it signed: ${report.error?.message ?? ""}`
            : `REMOTE_WITNESS_INVALID: ${who} gave an answer that does not verify with its configured verifier key: ${report.error?.message ?? ""}`);
          break;
        case "UNREGISTERED":
          notes.push(`REMOTE_WITNESS_UNREGISTERED: ${who} does not know this history yet (nothing was submitted to it; the history holds no REGISTERED receipt from it${report.bound ? ", it was bound without one" : ", it is configured, not bound"})`);
          break;
        default: break;
      }
      if (report.rotationPending === true) {
        notes.push(`REMOTE_WITNESS_ROTATION_PENDING: ${who} holds the head of a prepared owner key rotation (${this.#pendingPath}) that this file does not hold yet: the rotation was accepted but not appended (an interrupted rotation); the next owner command appends it`);
      }
      if (report.supersedes !== undefined && report.supersedes > 0) {
        const last = report.lastSupersede;
        notes.push(`REMOTE_WITNESS_SUPERSEDED ${report.supersedes}: ${who} recorded ${report.supersedes === 1 ? "1 supersede" : `${report.supersedes} supersedes`} of heads an owner key signed after the last good head${last === undefined ? "" : ` (the latest resumed from position ${last.from} and overrode ${last.heads} head(s), leaf ${last.index})`}: ${SUPERSEDE_WARNING}`);
      }
      const missing = report.pendingRotationPositions ?? [];
      if (missing.length > 0 && (report.status === "OK" || report.status === "ROLLBACK")) {
        notes.push(`REMOTE_WITNESS_ROTATION_INCOMPLETE: ${who} has not recorded the owner key rotation${missing.length === 1 ? "" : "s"} at position ${missing.join(", ")}: until it does, it accepts head statements signed by the retired key (irontrellis witness sync delivers it; irontrellis owner export-key-events hands it over offline)`);
      }
      if (report.equivocations !== undefined && report.equivocations > 0) {
        const last = report.lastEquivocation;
        notes.push(`REMOTE_WITNESS_EQUIVOCATION_RECORDED ${report.equivocations}: ${who} recorded ${report.equivocations === 1 ? "1 owner-signed head statement" : `${report.equivocations} owner-signed head statements`} conflicting with heads it holds${last === undefined ? "" : ` (the latest at position ${last.position}, leaf ${last.index})`}: ${EQUIVOCATION_WARNING}`);
      }
    }
    notes.push(...this.#receiptlessNotes(state));
    if (state.ownerKeyEpochs.at(-1)?.nextKeyDigests === undefined) notes.push(`NO_NEXT_KEY_COMMITMENT: ${NO_COMMITMENT_WARNING}`);
    const answeredKeys = new Set(reports.filter((report) => report.status === "OK" || report.status === "ROLLBACK" || report.status === "UNREGISTERED").map((report) => report.verifierKey));
    const coverage = this.#coverage((runtime) => answeredKeys.has(runtime.config.verifierKey));
    const answered = answeredKeys.size, required = coverage.required;
    const unreachable = reports.filter((report) => report.status === "UNREACHABLE");
    if (unreachable.length > 0 || !coverage.ok) {
      const line = `REMOTE_WITNESS_UNREACHABLE: ${unreachable.map((report) => `${report.url} (${report.error?.message ?? "no answer"})`).join("; ") || "no answer"}; ${coverage.ok ? `${answered} of the ${required} witness answers a check needs were obtained` : coverage.short}`;
      if (coverage.ok) notes.push(line);
      else if (options.allowUnreachable === true) notes.push(`${line} (accepted: allowUnreachableWitness)`);
      else failures.push(`${line}: a restored older copy cannot be ruled out`);
    }
    const positions = reports.filter((report) => report.status === "OK" || report.status === "UNREGISTERED").map((report) => report.latest?.position ?? 0).sort((a, b) => b - a);
    if (positions.length > 0) {
      const witnessed = positions[Math.min(this.#policy!.quorum, positions.length) - 1] ?? 0;
      const tail = state.head.position - witnessed;
      if (tail > 0) notes.push(`UNWITNESSED_TAIL ${tail}: the last ${tail} event(s) (positions ${witnessed + 1}..${state.head.position}) are not yet held by ${this.#policy!.quorum} remote witness(es)`);
    }
    const order: RemoteWitnessStatus[] = ["SPLIT_VIEW", "ROLLBACK", "INVALID"];
    const status: RemoteWitnessStatus = order.find((s) => reports.some((report) => report.status === s))
      ?? (coverage.ok ? "OK" : "UNREACHABLE");
    return Object.freeze({ failures: Object.freeze(failures), notes: Object.freeze(notes), witnesses: Object.freeze(reports), status });
  }
}

/** Opens the session for a store (inactive when there is no policy and no binding). */
export function openWitnessSession(host: WitnessHost, explicit: WitnessPolicy | false | undefined): WitnessSession {
  return new WitnessSession(host, explicit === undefined ? {} : { explicit });
}
