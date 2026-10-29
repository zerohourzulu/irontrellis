/**
 * How the command reaches a history: read commands open the store directly
 * (any profile, any format, no owner key), write commands open a `LocalOwner`
 * whose profile (domain, owner, controller) is read from the file itself. Also
 * the small value parsers shared by the commands (times, amounts).
 */
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import {
  EngineError, IronTrellisError, capacityOf, observeState, openHistoryStore, openLocalOwner, publicQueryDisclosure, replay, responsibleState, whyState,
  type Action, type ActionRequest, type CapacityReport, type ConsequentialBinding, type Signer, type HistoryStore, type LocalOwner, type Observation, type ReplayState, type ResponsibleQueryResult,
  type WhyQueryResult,
} from "@ramex-labs/irontrellis";
import { InputError, UsageError } from "./args.ts";
import { WRITE_RETRIES } from "./messages.ts";

/** A command-level failure with a stable code; the message is the plain sentence, `context` the machine-readable detail. */
export class CliError extends Error {
  readonly code: string;
  readonly context: unknown;
  constructor(code: string, message?: string, context?: unknown) {
    super(message ?? code);
    this.name = "CliError";
    this.code = code;
    this.context = context;
  }
}

/** The code, engine message and engine `detail` (as `context`) of any failure the command can meet. */
export function codeOf(error: unknown): { code: string; detail: string; context?: unknown } {
  if (error instanceof IronTrellisError || error instanceof EngineError) {
    return { code: error.code, detail: error.message, ...(error.detail === undefined ? {} : { context: error.detail }) };
  }
  if (error instanceof CliError) return { code: error.code, detail: error.message, ...(error.context === undefined ? {} : { context: error.context }) };
  if (error instanceof UsageError || error instanceof InputError) return { code: error.code, detail: error.message };
  if (error instanceof Error) return { code: "FAILED", detail: error.message };
  return { code: "FAILED", detail: String(error) };
}

export type Global = Readonly<{ history: string | undefined; owner?: string; controller?: string; at?: number; json: boolean }>;

export const historyPath = (g: Global): string => {
  const path = g.history ?? process.env.IRONTRELLIS_HISTORY;
  if (path === undefined || path === "") throw new CliError("HISTORY_REQUIRED");
  return resolve(path);
};

export type Reader = Readonly<{ path: string; store: HistoryStore; state: ReplayState }>;

/** How long a command that opens the store itself (anchor, repin) waits for another writer's lock. */
export const LOCK_WAIT_MS = 1500;

/**
 * Open for reading: works for every profile and both formats; needs no owner
 * key. A pin problem (rollback, missing or malformed pin, a pin without a valid
 * owner attestation of a prefix of the file) or an anchor-log head the file lacks
 * fails the open with ROLLBACK_DETECTED (`detail.reason` names it); an
 * unreadable anchor log with ANCHOR_LOG_UNREADABLE. A file that is not a valid history (a torn last record,
 * bad UTF-8, a broken chain) is INVALID_HISTORY with the store's reason;
 * HISTORY_EMPTY is only for a file that holds no bytes at all.
 */
export async function openReader(g: Global, options: Readonly<{ signer?: Signer; lockTimeoutMs?: number }> = {}): Promise<Reader> {
  const path = historyPath(g);
  if (!existsSync(path)) throw new CliError("HISTORY_NOT_FOUND", `no history at ${path}`);
  // Legacy, format-1 and fenced (migrated) files open read only (SPEC §16.1): every question works, every write is FORMAT_READ_ONLY.
  const store = openHistoryStore(path, { ...(options.signer === undefined ? {} : { signer: options.signer }), ...(options.lockTimeoutMs === undefined ? {} : { lockTimeoutMs: options.lockTimeoutMs }) });
  // A history whose witness policy says requireOnOpen is read only after the remote witnesses confirmed it (ROLLBACK_DETECTED otherwise).
  if (store.witnessStatus()?.checkRequired === true) await store.checkWitnesses();
  // head() surfaces the store's parse error (INVALID_HISTORY) before an absent format could be mistaken for an empty file.
  if (store.head() === undefined) throw new CliError("HISTORY_EMPTY", `history ${path} has no events`);
  return Object.freeze({ path, store, state: store.state() });
}

/**
 * Commands that write (or sign the pin) check first that the file is format 2 and not fenced: a legacy or format-1
 * history, or one already migrated, is FORMAT_READ_ONLY with the store's reason (LEGACY, FORMAT_1, MIGRATED).
 */
export function writableFormat(store: HistoryStore, what: string): void {
  const reason = store.readOnlyReason();
  if (reason === undefined) return;
  const why = reason === "MIGRATED" ? "was migrated to format 2 and is kept as a read-only archive" : `is ${reason === "LEGACY" ? "a legacy (Continuity 0.2)" : "a format-1"} history, which this release reads but does not write`;
  throw new CliError("FORMAT_READ_ONLY", `${what}: ${store.path} ${why}; migrate it (irontrellis migrate) and use the target`, { reason });
}

/** The evaluation time: `--at` when given, else the host clock (docs/API.md §1). */
export const evaluationTime = (g: Global): number => g.at ?? Date.now();

export const observe = (r: Reader, g: Global): Observation => observeState(r.state, { at: evaluationTime(g) });
export const capacity = (r: Reader): CapacityReport => capacityOf(r.state);

const actionRequest = (a: Action, at: number): ActionRequest => Object.freeze({
  actorId: a.actor, action: a.action, resource: a.resource, claimedAt: at,
  ...(a.amount === undefined ? {} : { amount: a.amount }), ...(a.counterparty === undefined ? {} : { counterpartyId: a.counterparty }),
  ...(a.termsCommitment === undefined ? {} : { termsCommitment: a.termsCommitment }),
});

export type Query = Readonly<{ at: number; request?: Action; why(a: Action): WhyQueryResult; responsible(a: Action): ResponsibleQueryResult }>;

const actionOf = (request: ActionRequest): Action => Object.freeze({
  actor: request.actorId, action: request.action, resource: request.resource,
  ...(request.amount === undefined ? {} : { amount: request.amount }), ...(request.counterpartyId === undefined ? {} : { counterparty: request.counterpartyId }),
  ...(request.termsCommitment === undefined ? {} : { termsCommitment: request.termsCommitment }),
});

/**
 * WHY / RESPONSIBLE at the current head; with `position`, evaluated on the
 * history's prefix up to that position while the whole history is observed;
 * with `intent`, evaluated exactly as the recorded admission of that intent
 * was (its prefix, time, request and runtime binding), which is how "who is
 * responsible now for what was admitted then" is answered — the observed
 * history contributes the duties and assignments that followed.
 * Without `--at`, a prefix evaluation uses the prefix head time.
 */
export function queryAt(r: Reader, g: Global, position: number | undefined, intent?: string): Query {
  if (position === undefined && intent === undefined) {
    const at = evaluationTime(g), view = observe(r, g);
    return Object.freeze({ at, why: (a: Action) => view.why(a), responsible: (a: Action) => view.responsible(a) });
  }
  if (position !== undefined && intent !== undefined) throw new UsageError("--position and --intent exclude each other");
  let binding: Record<string, unknown> | undefined, request: Action | undefined, recorded: ActionRequest | undefined, at: number, prefixLength: number;
  if (intent !== undefined) {
    const admission = r.state.intentAdmissions.get(intent);
    if (admission === undefined) throw new CliError("INVALID_INPUT", `the history records no admission of intent "${intent}"`);
    const migrated = r.state.genesis.migratedFrom;
    if (migrated !== undefined && admission.admissionEventPosition <= migrated.position) {
      throw new CliError("MIGRATED_INTENT", `intent "${intent}" was admitted at position ${admission.admissionEventPosition}, before this history was migrated (position ${migrated.position}); its runtime signature binds the legacy domain, so ask the legacy source archive: irontrellis --history <source.jsonl> ... --intent ${intent}`);
    }
    const data = r.state.events[admission.admissionEventPosition]!.data as { authorizationProof: { request: ActionRequest } & Record<string, unknown>; runtimeSignature?: unknown; evaluationTime: number };
    const proof = data.authorizationProof;
    recorded = proof.request;
    request = actionOf(recorded);
    at = g.at ?? data.evaluationTime;
    prefixLength = admission.admissionEventPosition;
    binding = {
      runtimeSessionId: admission.runtimeSessionId, credentialKeyId: admission.credentialKeyId, controlEpoch: admission.controlEpoch, roleId: admission.roleId,
      roleTenureId: admission.roleTenureId, intentId: intent, nonce: admission.nonce, ...(data.runtimeSignature === undefined ? {} : { runtimeSignature: data.runtimeSignature }),
    };
  } else {
    if (position! > r.state.head.position) throw new UsageError(`--position ${position} is past the head (position ${r.state.head.position})`);
    prefixLength = position! + 1;
    at = 0;
  }
  const prefix = replay(r.state.events.slice(0, prefixLength));
  if (prefix.status !== "ACCEPTED") throw new CliError("INVALID_HISTORY", `the prefix of ${prefixLength} events does not replay: ${prefix.code}`);
  if (intent === undefined) at = g.at ?? prefix.state.head.canonicalTime;
  const input = (a: Action) => ({
    // The recorded request is used verbatim (its claimedAt is part of the signed challenge).
    authorizationDomain: r.state.genesis.domain, evaluationTime: at, request: recorded ?? actionRequest(a, at),
    ...(binding === undefined ? {} : { consequentialBinding: binding as ConsequentialBinding }),
  });
  return Object.freeze({
    at, ...(request === undefined ? {} : { request }),
    why: (a: Action) => whyState(prefix.state, r.state, { ...input(a), disclosure: publicQueryDisclosure("WHY", r.state.format) }),
    responsible: (a: Action) => responsibleState(prefix.state, r.state, { ...input(a), disclosure: publicQueryDisclosure("RESPONSIBLE", r.state.format) }),
  });
}

/** The owner id recorded at position 1 and the controller the history's agents were created under. */
export function profileOf(state: ReplayState): { owner: string; controller: string | undefined } {
  const principal = state.events[1];
  const owner = principal?.type === "PRINCIPAL_CREATED" ? String(principal.data.principalId) : undefined;
  if (owner === undefined) throw new CliError("INVALID_HISTORY", "the history has no principal at position 1");
  const created = state.events.find((event) => event.type === "AGENT_CREATED");
  return { owner, controller: created === undefined ? undefined : String(created.data.controllerId) };
}

/**
 * Open for writing: the profile comes from the file (`--owner`/`--controller`
 * override it; the controller of a history without agents defaults to the
 * owner). The owner key file next to the history signs control events.
 */
export type Writer = { owner: LocalOwner; reader: Reader; ownerId: string; controllerId: string };
export async function openWriter(g: Global): Promise<Writer> {
  const reader = await openReader(g);
  const profile = profileOf(reader.state);
  const ownerId = g.owner ?? profile.owner;
  const controllerId = g.controller ?? process.env.IRONTRELLIS_CONTROLLER ?? profile.controller ?? ownerId;
  // No format is named: a legacy, format-1 or fenced file opens read only and every write is FORMAT_READ_ONLY (SPEC §16.1).
  const owner = openLocalOwner({ historyFile: reader.path, domain: reader.state.genesis.domain, owner: ownerId, controller: controllerId, now: () => Date.now() });
  return { owner, reader, ownerId, controllerId };
}

/** Another writer held the lock or moved the head: nothing was written, so the whole write may run again on a fresh read. */
const retryable = (error: unknown): boolean =>
  (error instanceof IronTrellisError && error.code === "HISTORY_CONFLICT") || (error instanceof EngineError && (error.code === "STORE_BUSY" || error.code === "STORE_CONFLICT"));
const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
/** Backoff before retry `n` (0-based): 50, 100, 200, 400, 800 ms, each plus up to 50 ms of jitter. */
const BACKOFF_MS = 50;

/**
 * Runs a write, and runs it again (up to `WRITE_RETRIES` times, with
 * exponential backoff) while it fails with HISTORY_CONFLICT or STORE_BUSY:
 * parallel writers take turns instead of failing. Every attempt
 * re-reads the history. When the retries run out, the last failure is reported
 * with its lock path, when a lock was held.
 */
export async function withRetry<T>(write: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await write();
    } catch (error) {
      if (!retryable(error)) throw error;
      if (attempt >= WRITE_RETRIES) {
        const { code, detail, context } = codeOf(error);
        throw new CliError(code === "STORE_CONFLICT" ? "HISTORY_CONFLICT" : code, `${detail} (gave up after ${WRITE_RETRIES} retries)`, context);
      }
      await pause(BACKOFF_MS * 2 ** attempt + Math.floor(Math.random() * BACKOFF_MS));
    }
  }
}

/**
 * Open the writer and run one owner-API write, retried as `withRetry`
 * describes. With remote witnesses, the command then submits the head
 * statement before it exits (the async worker of a short-lived process would
 * not get the chance): rollback or split-view evidence fails the command; an
 * unreachable witness leaves the statement queued in `<history>.witness.json`
 * (`irontrellis witness sync` submits it later).
 */
export const write = <T>(g: Global, run: (w: Writer) => Promise<T>): Promise<T> => withRetry(async () => {
  const w = await openWriter(g);
  const result = await run(w);
  try {
    await submitQueued(w.owner);
  } catch (error) {
    throw writtenUnattested(error, result) ?? error;
  }
  return result;
});

/**
 * The write landed; only the signature after it failed (SIGNER_FAILED, KEY_UNAVAILABLE): a code, context and exit status
 * of its own (WRITTEN_UNATTESTED, exit 4), so that no script mistakes a recorded event for one that was not written.
 * `undefined` for any other error. Used by `write()` and by the commands that append without it (init, anchor,
 * witness remove --accept-loss).
 */
export function writtenUnattested(error: unknown, result: unknown): CliError | undefined {
  // The owner API raises IronTrellisError; the store (anchor's locked append) raises EngineError, a separate class.
  if (!((error instanceof IronTrellisError || error instanceof EngineError) && (error.code === "SIGNER_FAILED" || error.code === "KEY_UNAVAILABLE"))) return undefined;
  const written = result as { eventId?: unknown; head?: unknown } | undefined;
  return new CliError("WRITTEN_UNATTESTED", error.message, {
    written: true, ...(typeof written?.eventId === "string" ? { eventId: written.eventId } : {}), ...(written?.head === undefined ? {} : { head: written.head }),
    cause: { code: error.code, ...(error.detail !== null && typeof error.detail === "object" ? { detail: error.detail } : {}) },
  });
}

/**
 * Before the command exits: the pinned-head attestation an asynchronous signer (ssh-agent, command, KMS) still owes, and a
 * best-effort submission of queued head statements. Witness evidence (rollback, equivocation, split view) is an error, and so
 * is a signer that failed to attest (SIGNER_FAILED / KEY_UNAVAILABLE: the event is recorded, the pin keeps its earlier
 * attestation until `irontrellis repin`); an unreachable witness is not.
 */
export async function submitQueued(owner: LocalOwner): Promise<void> {
  try {
    await owner.flush();
  } catch (error) {
    if (error instanceof IronTrellisError && ["ROLLBACK_DETECTED", "WITNESS_SPLIT_VIEW", "SIGNER_FAILED", "KEY_UNAVAILABLE"].includes(error.code)) throw error;
  }
}

// ---------------------------------------------------------------- value parsers

const DURATION = /^\+(\d+)(ms|s|m|h|d)$/;
const UNIT_MS: Readonly<Record<string, number>> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

/** Milliseconds, an ISO-8601 date, or a duration from now (`+30m`, `+7d`). */
export function parseTime(text: string, name: string): number {
  if (/^\d+$/.test(text)) {
    const value = Number(text);
    if (!Number.isSafeInteger(value)) throw new UsageError(`--${name}: ${text} is not a safe integer`);
    return value;
  }
  const duration = DURATION.exec(text);
  if (duration !== null) return Date.now() + Number(duration[1]) * UNIT_MS[duration[2]!]!;
  const parsed = Date.parse(text);
  if (Number.isNaN(parsed)) throw new UsageError(`--${name}: "${text}" is not milliseconds, an ISO-8601 date or a duration like +30m`);
  return parsed;
}

/** A non-negative decimal integer of any size, in the application's smallest unit. */
export function parseAmount(text: string, name: string): bigint {
  if (!/^\d+$/.test(text)) throw new UsageError(`--${name}: "${text}" is not a non-negative decimal integer`);
  const value = BigInt(text);
  if (value >= 1n << 256n) throw new InputError(`--${name} is ${text.length} digits long; amounts are limited to 2^256 - 1`);
  return value;
}

export const optionalTime = (text: string | undefined, name: string): { [k: string]: number } => (text === undefined ? {} : { [name]: parseTime(text, name) });
