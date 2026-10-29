/**
 * `<history>.witness.json`: the witness side file (mode 0600, written
 * atomically under a short lock `<history>.witness.json.lock`).
 *
 *   { version: "irontrellis-witness-state/1",
 *     historyId,                                   // the history the state belongs to
 *     policy: { witnesses: [{url, verifierKey, name?, timeoutMs?, token?, allowInsecureHttp?}], quorum, mode, maxUnwitnessedEvents, requireOnOpen, cacheMs },
 *     witnesses: { [origin]: { url, verifierKey, registered, checkpoint?: {size, rootB64, note},
 *                              latest?: {head | null, fetchedAt, seal?: {keyId, scheme, signature}}, held?: <HEAD receipt>, splitView?: {detectedAt, message},
 *                              rejected?: {code, message, detectedAt, config} } },
 *     pending: [ {kind:"statement", head, statements?: {[origin]: signedStatement}}
 *              | {kind:"rotation", rotation, previousHead, rotationHead} ] }
 *
 * THE FILE IS ATTACKER-WRITABLE (anyone who can write the history can write
 * it) AND MAY ONLY EVER MAKE THINGS STRICTER. The remote witness is the
 * authority. Concretely:
 *  - a deleted, emptied or rolled-back file never lets a rollback pass: every
 *    writer asks the witnesses over the network before its first statement,
 *    and verification always asks them; a `latest` or `checkpoint` in the file
 *    can only add findings (a cached latest that is not a prefix of the history
 *    is a rollback; a checkpoint the witness cannot prove consistent is a split view);
 *  - the policy in the file can add witnesses, never remove one the history
 *    itself binds (owner-signed `WITNESSES_BOUND` / `WITNESSES_UNBOUND` events, see
 *    witness-session.ts); passing `witness` explicitly overrides the file;
 *  - a cached `latest` may let a reader skip a network call (`cacheMs`) only
 *    when it carries an owner-key seal over `{historyId, origin, verifierKey,
 *    url, head, fetchedAt}` (the attacker holds no owner key, a seal names the
 *    one witness it was made for, and replaying an older seal replays an older
 *    `fetchedAt`); unsealed entries only ever add findings. Seals are written
 *    and accepted only for bound witnesses (origin from the binding's signed
 *    registration receipt) and those of the out-of-band minimum.
 *    Writers never skip the network on the file's word;
 *  - pending items are hints: everything the queue holds can be re-derived
 *    from the history and the witnesses, except the old-key statement of a
 *    rotation head, which is also recoverable from the archived key file;
 *  - a file that cannot be parsed fails the open (WITNESS_UNREADABLE) instead
 *    of being ignored;
 *  - `rejected` (a witness refused to register the history) is display only
 *    (`witness status` in processes that do not register): owner processes
 *    find out again by registering. It holds for the witness config it names
 *    (`config`: a hash of url, verifier key and token), so a changed policy clears it.
 *
 * An operator who wants a witness policy the agent host cannot edit at all
 * points `IRONTRELLIS_WITNESS_POLICY` at a JSON policy file outside the
 * agent's writable area (`minimumWitnessPolicy`): it is merged into every
 * policy as a minimum (it adds witnesses and raises requirements, never
 * removes or lowers them).
 */
import { closeSync, fstatSync, fsyncSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { isFullyQualifiedPath, isWindowsTransientError, ownerOnlyModeEnforced, replaceFileSync, syncDirectorySync } from "./platform.ts";
import { isContentHash, isU53, jsonParseWithBigints, jsonStringifyWithBigints } from "./canonical.ts";
import { suiteFor } from "./crypto/suites.ts";
import { EngineError } from "./errors.ts";
import { hashCanonical } from "./hash.ts";
import { ownerKeysAt } from "./owner-keys.ts";
import type { Signer } from "./signer.ts";
import type { SignedHeadStatement, StatementHead } from "./transparency/statement.ts";
import type { WitnessReceipt } from "./transparency/receipt.ts";
import type { ContentHash, HexSignature, ReplayState, SignatureScheme, U53 } from "./types.ts";
import { normalizeWitnessPolicy, type RemoteWitnessConfig, type ResolvedWitnessPolicy, type StoredCheckpoint, type WitnessMode } from "./witness-client.ts";

export const WITNESS_STATE_VERSION = "irontrellis-witness-state/1";
export const WITNESS_CACHE_SEAL_VERSION = "irontrellis-witness-cache/1";

export function witnessStatePathFor(historyFile: string): string {
  return `${historyFile}.witness.json`;
}

export type StoredWitnessConfig = Readonly<{ url: string; verifierKey: string; name?: string; timeoutMs?: number; token?: string; allowInsecureHttp?: boolean }>;
export type StoredPolicy = Readonly<{
  witnesses: readonly StoredWitnessConfig[]; quorum: number; mode: WitnessMode; maxUnwitnessedEvents: number; requireOnOpen: boolean; cacheMs: number;
}>;
export type CacheSeal = Readonly<{ keyId: string; scheme: SignatureScheme; signature: HexSignature }>;
export type CachedLatest = Readonly<{ head: StatementHead | null; fetchedAt: U53; seal?: CacheSeal }>;
export type RecordedRejection = Readonly<{ code: string; message: string; detectedAt: U53; config: ContentHash }>;
export type SideWitness = Readonly<{
  url: string; verifierKey: string; registered: boolean; checkpoint?: StoredCheckpoint; latest?: CachedLatest; splitView?: Readonly<{ detectedAt: U53; message: string }>;
  rejected?: RecordedRejection;
  /**
   * The witness-signed HEAD receipt of the newest head this history knew the witness held on its chain (the last
   * good head a supersede resumes from, docs/reference/witness-operations.md §7.4). Verified with the witness key before use; only ever a hint.
   */
  held?: WitnessReceipt;
}>;
/** The config fingerprint a recorded rejection holds for: url, verifier key and token. */
export const witnessConfigFingerprint = (config: Pick<RemoteWitnessConfig, "url" | "verifierKey" | "token">): ContentHash =>
  hashCanonical({ url: config.url, verifierKey: config.verifierKey, token: config.token ?? null }, "sha256");
export type PendingStatement = Readonly<{ kind: "statement"; head: StatementHead; statements?: Readonly<Record<string, SignedHeadStatement>> }>;
export type PendingRotation = Readonly<{
  kind: "rotation"; rotation: Readonly<Record<string, unknown>>; previousHead: Readonly<{ hash: ContentHash; position: U53 }>; rotationHead: Readonly<{ hash: ContentHash; position: U53 }>;
}>;
export type PendingItem = PendingStatement | PendingRotation;
export type WitnessStateDoc = Readonly<{
  version: typeof WITNESS_STATE_VERSION;
  historyId?: ContentHash;
  policy?: StoredPolicy;
  witnesses: Readonly<Record<string, SideWitness>>;
  pending: readonly PendingItem[];
}>;

export const EMPTY_WITNESS_STATE: WitnessStateDoc = Object.freeze({ version: WITNESS_STATE_VERSION, witnesses: Object.freeze({}), pending: Object.freeze([]) });

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const errnoOf = (error: unknown): string | undefined => (error as { code?: unknown } | null)?.code as string | undefined;
const messageOf = (error: unknown): string => (error instanceof Error ? error.message : String(error));
const isHead = (value: unknown): value is StatementHead => isRecord(value) && isContentHash(value.hash) && isU53(value.position) && isU53(value.canonicalTime);
const isPosition = (value: unknown): value is { hash: ContentHash; position: U53 } => isRecord(value) && isContentHash(value.hash) && isU53(value.position);

/** A policy as the side file keeps it (no transports). */
export function storedPolicyOf(policy: ResolvedWitnessPolicy): StoredPolicy {
  return Object.freeze({
    witnesses: Object.freeze(policy.witnesses.map((w) => Object.freeze({
      url: w.url, verifierKey: w.verifierKey, ...(w.name === undefined ? {} : { name: w.name }), ...(w.timeoutMs === undefined ? {} : { timeoutMs: w.timeoutMs }),
      ...(w.token === undefined ? {} : { token: w.token }), ...(w.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}),
    }))),
    quorum: policy.quorum, mode: policy.mode, maxUnwitnessedEvents: policy.maxUnwitnessedEvents, requireOnOpen: policy.requireOnOpen, cacheMs: policy.cacheMs,
  });
}

const bad = (path: string, why: string): EngineError =>
  new EngineError("WITNESS_UNREADABLE", `witness state file ${path} is malformed (${why}); a rollback cannot be ruled out with it. Restore it, or remove it deliberately (the witnesses are asked again)`, { reason: "WITNESS_STATE_UNREADABLE", witnessPath: path });

/** Parses the side file; `EMPTY_WITNESS_STATE` when absent. Throws WITNESS_UNREADABLE when unreadable or malformed. */
export function readWitnessState(path: string): WitnessStateDoc {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if (errnoOf(error) === "ENOENT") return EMPTY_WITNESS_STATE;
    throw new EngineError("WITNESS_UNREADABLE", `witness state file ${path} cannot be read: ${messageOf(error)}`, { reason: "WITNESS_STATE_UNREADABLE", witnessPath: path, cause: errnoOf(error) });
  }
  let raw: unknown;
  try {
    raw = jsonParseWithBigints(text);
  } catch (error) {
    throw bad(path, `not JSON: ${messageOf(error)}`);
  }
  if (!isRecord(raw) || raw.version !== WITNESS_STATE_VERSION) throw bad(path, "unknown version");
  if (raw.historyId !== undefined && !isContentHash(raw.historyId)) throw bad(path, "historyId");
  let policy: StoredPolicy | undefined;
  if (raw.policy !== undefined) {
    try {
      policy = storedPolicyOf(normalizeWitnessPolicy(raw.policy));
    } catch (error) {
      throw bad(path, `policy: ${messageOf(error)}`);
    }
  }
  const witnesses: Record<string, SideWitness> = {};
  if (!isRecord(raw.witnesses)) throw bad(path, "witnesses");
  for (const [origin, value] of Object.entries(raw.witnesses)) {
    if (!isRecord(value) || typeof value.url !== "string" || typeof value.verifierKey !== "string" || typeof value.registered !== "boolean") throw bad(path, `witness ${origin}`);
    const checkpoint = value.checkpoint;
    if (checkpoint !== undefined && !(isRecord(checkpoint) && isU53(checkpoint.size) && typeof checkpoint.rootB64 === "string" && typeof checkpoint.note === "string")) throw bad(path, `checkpoint of ${origin}`);
    const latest = value.latest;
    if (latest !== undefined) {
      if (!isRecord(latest) || !(latest.head === null || isHead(latest.head)) || !isU53(latest.fetchedAt)) throw bad(path, `latest of ${origin}`);
      const seal = latest.seal;
      if (seal !== undefined && !(isRecord(seal) && typeof seal.keyId === "string" && typeof seal.scheme === "string" && typeof seal.signature === "string")) throw bad(path, `seal of ${origin}`);
    }
    const split = value.splitView;
    if (split !== undefined && !(isRecord(split) && isU53(split.detectedAt) && typeof split.message === "string")) throw bad(path, `splitView of ${origin}`);
    const rejected = value.rejected;
    if (rejected !== undefined && !(isRecord(rejected) && typeof rejected.code === "string" && typeof rejected.message === "string" && isU53(rejected.detectedAt) && isContentHash(rejected.config))) throw bad(path, `rejected of ${origin}`);
    const held = value.held;
    if (held !== undefined && !isRecord(held)) throw bad(path, `held of ${origin}`);
    witnesses[origin] = Object.freeze({
      url: value.url, verifierKey: value.verifierKey, registered: value.registered,
      ...(checkpoint === undefined ? {} : { checkpoint: Object.freeze({ size: checkpoint.size as number, rootB64: checkpoint.rootB64 as string, note: checkpoint.note as string }) }),
      ...(latest === undefined ? {} : { latest: Object.freeze({ head: latest.head === null ? null : Object.freeze({ ...(latest.head as StatementHead) }), fetchedAt: latest.fetchedAt as number, ...(latest.seal === undefined ? {} : { seal: Object.freeze({ ...(latest.seal as CacheSeal) }) }) }) }),
      ...(split === undefined ? {} : { splitView: Object.freeze({ detectedAt: split.detectedAt as number, message: split.message as string }) }),
      ...(rejected === undefined ? {} : { rejected: Object.freeze({ code: rejected.code as string, message: rejected.message as string, detectedAt: rejected.detectedAt as number, config: rejected.config as ContentHash }) }),
      ...(held === undefined ? {} : { held: held as unknown as WitnessReceipt }),
    });
  }
  if (!Array.isArray(raw.pending)) throw bad(path, "pending");
  const pending: PendingItem[] = [];
  for (const item of raw.pending) {
    if (isRecord(item) && item.kind === "statement" && isHead(item.head) && (item.statements === undefined || isRecord(item.statements))) {
      pending.push(Object.freeze({ kind: "statement", head: Object.freeze({ ...item.head }), ...(item.statements === undefined ? {} : { statements: Object.freeze({ ...(item.statements as Record<string, SignedHeadStatement>) }) }) }));
    } else if (isRecord(item) && item.kind === "rotation" && isRecord(item.rotation) && isPosition(item.previousHead) && isPosition(item.rotationHead)) {
      pending.push(Object.freeze({ kind: "rotation", rotation: item.rotation, previousHead: Object.freeze({ hash: item.previousHead.hash, position: item.previousHead.position }), rotationHead: Object.freeze({ hash: item.rotationHead.hash, position: item.rotationHead.position }) }));
    } else throw bad(path, "pending item");
  }
  return Object.freeze({
    version: WITNESS_STATE_VERSION, ...(raw.historyId === undefined ? {} : { historyId: raw.historyId as ContentHash }), ...(policy === undefined ? {} : { policy }),
    witnesses: Object.freeze(witnesses), pending: Object.freeze(pending),
  });
}

// ---------------------------------------------------------------- writing

const sleep = (ms: number): void => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };
const LOCK_STALE_MS = 10_000;
let temporaryCounter = 0;

const fsyncDirectory = (path: string): void => { syncDirectorySync(dirname(path), { bestEffort: true }); };

const writeAtomically = (path: string, text: string): void => {
  const temporary = `${path}.tmp-${process.pid}-${(temporaryCounter += 1)}`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    const bytes = Buffer.from(text);
    let done = 0;
    while (done < bytes.length) done += writeSync(fd, bytes, done, bytes.length - done);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    replaceFileSync(temporary, path);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* best effort */ }
    throw error;
  }
  fsyncDirectory(path);
};

/** Runs `critical` holding `<path>.lock` (O_EXCL, waits up to ~2 s, reclaims a lock older than 10 s). Never awaits inside. */
function withStateLock<T>(path: string, critical: () => T): T {
  const lock = `${path}.lock`;
  const deadline = Date.now() + 2000;
  let fd: number | undefined;
  for (let delay = 1; fd === undefined; delay = Math.min(delay * 2, 50)) {
    try {
      fd = openSync(lock, "wx", 0o600);
    } catch (error) {
      // Windows: a just-released lock can be delete-pending (EPERM) or held by a scanner; wait like for a held lock.
      if (isWindowsTransientError(error) && Date.now() <= deadline) { sleep(delay); continue; }
      if (errnoOf(error) !== "EEXIST") throw new EngineError("WITNESS_UNREADABLE", `cannot lock witness state ${path}: ${messageOf(error)}`, { reason: "WITNESS_STATE_UNREADABLE", witnessPath: path });
      try {
        if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) { unlinkSync(lock); continue; }
      } catch { continue; }
      if (Date.now() > deadline) throw new EngineError("STORE_BUSY", `witness state ${path} is locked by another process (${lock})`, { lockPath: lock });
      sleep(delay);
    }
  }
  try {
    return critical();
  } finally {
    closeSync(fd);
    try { unlinkSync(lock); } catch { /* already gone */ }
  }
}

const serialize = (doc: WitnessStateDoc): string => `${jsonStringifyWithBigints(doc)}\n`;

/**
 * Read-modify-write under the lock. `change` receives the current document
 * (the empty one when absent, or when it belongs to another history: its
 * witness state is dropped, its policy kept) and returns the new one, or
 * `undefined` to leave the file as it is.
 */
export function updateWitnessState(path: string, historyId: ContentHash | undefined, change: (doc: WitnessStateDoc) => WitnessStateDoc | undefined): WitnessStateDoc {
  return withStateLock(path, () => {
    let current = readWitnessState(path);
    if (historyId !== undefined && current.historyId !== undefined && current.historyId !== historyId) {
      current = Object.freeze({ ...EMPTY_WITNESS_STATE, ...(current.policy === undefined ? {} : { policy: current.policy }) });
    }
    const next = change(current);
    if (next === undefined) return current;
    const doc: WitnessStateDoc = Object.freeze({ ...next, version: WITNESS_STATE_VERSION, ...(historyId === undefined ? {} : { historyId }) });
    writeAtomically(path, serialize(doc));
    return doc;
  });
}

// ---------------------------------------------------------------- owner seals over cached witness answers

/**
 * Which witness a sealed answer came from: the history, the witness's checkpoint origin, its verifier key and the URL it
 * was asked at (the pinned one). All of them are signed, so a seal can never be credited to another witness (docs/WITNESS.md §3).
 */
export type SealedWitness = Readonly<{ historyId: ContentHash; origin: string; verifierKey: string; url: string }>;

const sealHash = (witness: SealedWitness, head: StatementHead | null, fetchedAt: U53): ContentHash =>
  hashCanonical({
    version: WITNESS_CACHE_SEAL_VERSION, historyId: witness.historyId, origin: witness.origin, verifierKey: witness.verifierKey, url: witness.url, fetchedAt,
    head: head === null ? null : { hash: head.hash, position: head.position, canonicalTime: head.canonicalTime },
  }, "sha256");

/** Seals a cached witness answer with an owner key (`undefined` when the signer cannot sign synchronously). */
export function sealCachedLatest(signer: Signer, witness: SealedWitness, head: StatementHead | null, fetchedAt: U53): CacheSeal | undefined {
  if (signer.signHashSync === undefined) return undefined;
  try {
    return Object.freeze({ keyId: signer.keyId, scheme: signer.scheme, signature: signer.signHashSync(sealHash(witness, head, fetchedAt)) });
  } catch {
    return undefined;
  }
}

/**
 * `sealCachedLatest` for a signer without `signHashSync` (ssh-agent, command, KMS): the seal once the signer answers,
 * `undefined` when it fails (a seal is an optimization: a missing one only makes a `requireOnOpen` reader ask the network).
 */
export async function sealCachedLatestAsync(signer: Signer, witness: SealedWitness, head: StatementHead | null, fetchedAt: U53): Promise<CacheSeal | undefined> {
  try {
    const signature = await signer.signHash(sealHash(witness, head, fetchedAt), { purpose: "cache-seal", historyId: witness.historyId });
    return Object.freeze({ keyId: signer.keyId, scheme: signer.scheme, signature });
  } catch {
    return undefined;
  }
}

/** True iff the cached answer carries a seal, for exactly this witness, by an owner key in force after the history's head. Never throws. */
export function cachedLatestIsSealed(state: ReplayState, witness: SealedWitness, cached: CachedLatest): boolean {
  const seal = cached.seal;
  if (seal === undefined) return false;
  const key = ownerKeysAt(state, state.head.position + 1).find((candidate) => candidate.keyId === seal.keyId && candidate.scheme === seal.scheme);
  if (key === undefined) return false;
  try {
    const suite = suiteFor(key.scheme);
    return suite.isSignature(seal.signature) && suite.verify(sealHash(witness, cached.head, cached.fetchedAt), seal.signature, suite.normalizeCredential(key.credential));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- the out-of-band minimum policy

/** The environment variable naming the out-of-band witness policy file. */
export const WITNESS_POLICY_ENV = "IRONTRELLIS_WITNESS_POLICY";
/** The out-of-band policy: its witnesses, and only the requirements the file states (absent fields constrain nothing). */
export type MinimumWitnessPolicy = Readonly<{
  path: string; witnesses: readonly RemoteWitnessConfig[]; quorum?: number; mode?: WitnessMode; maxUnwitnessedEvents?: number; requireOnOpen?: boolean; cacheMs?: number;
}>;
const MAX_POLICY_FILE_BYTES = 256 * 1024;

/**
 * The policy file named by `IRONTRELLIS_WITNESS_POLICY` (an absolute path to a
 * JSON `WitnessPolicy`: `{ witnesses: [{url, verifierKey, name?, timeoutMs?, token?, allowInsecureHttp?}], quorum?, mode?, maxUnwitnessedEvents?, requireOnOpen?, cacheMs? }`),
 * `undefined` when the variable is unset or empty. Every store the process
 * opens merges it into its witness policy as a minimum. Set but unusable (a
 * relative path, unreadable, not JSON, an invalid policy, writable by group or
 * others) → WITNESS_UNREADABLE (reason WITNESS_POLICY_UNREADABLE): an
 * operator's minimum is never dropped silently.
 */
export function minimumWitnessPolicy(env: Readonly<Record<string, string | undefined>> = process.env): MinimumWitnessPolicy | undefined {
  const path = env[WITNESS_POLICY_ENV];
  if (path === undefined || path === "") return undefined;
  const refuse = (why: string, cause?: string): never => {
    throw new EngineError("WITNESS_UNREADABLE", `the witness policy file named by ${WITNESS_POLICY_ENV} (${path}) ${why}; stores refuse to open without the operator's minimum witness policy`,
      { reason: "WITNESS_POLICY_UNREADABLE", policyPath: path, ...(cause === undefined ? {} : { cause }) });
  };
  if (!isFullyQualifiedPath(path)) refuse(process.platform === "win32" ? "is not an absolute path with a drive letter or a UNC prefix" : "is not an absolute path");
  let text: string;
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const info = fstatSync(fd);
    if (!info.isFile()) refuse("is not a regular file");
    // Windows reports synthetic mode bits: there the file is protected by its ACL (docs/PLATFORMS.md §3), not checked here.
    if (ownerOnlyModeEnforced() && (info.mode & 0o022) !== 0) refuse(`is writable by group or others (mode 0${(info.mode & 0o777).toString(8)}); it must be writable by its owner only`);
    if (info.size > MAX_POLICY_FILE_BYTES) refuse(`is larger than ${MAX_POLICY_FILE_BYTES} bytes`);
    text = readFileSync(fd, "utf8");
  } catch (error) {
    if (error instanceof EngineError) throw error;
    return refuse(`cannot be read: ${messageOf(error)}`, errnoOf(error));
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  let raw: unknown;
  try { raw = JSON.parse(text); } catch (error) { return refuse(`is not JSON: ${messageOf(error)}`); }
  let policy: ResolvedWitnessPolicy;
  try { policy = normalizeWitnessPolicy(raw); } catch (error) { return refuse(`is not a valid witness policy: ${messageOf(error)}`); }
  if (policy.fetch !== undefined) refuse("carries a transport");
  const given = raw as Record<string, unknown>;
  return Object.freeze({
    path, witnesses: policy.witnesses,
    ...(given.quorum === undefined ? {} : { quorum: policy.quorum }), ...(given.mode === undefined ? {} : { mode: policy.mode }),
    ...(given.maxUnwitnessedEvents === undefined ? {} : { maxUnwitnessedEvents: policy.maxUnwitnessedEvents }),
    ...(given.requireOnOpen === undefined ? {} : { requireOnOpen: policy.requireOnOpen }), ...(given.cacheMs === undefined ? {} : { cacheMs: policy.cacheMs }),
  });
}

/** A witness config as the side file keeps it, matched to the configs of a policy by verifier key. */
export const sameWitness = (a: Pick<RemoteWitnessConfig, "verifierKey">, b: Pick<RemoteWitnessConfig, "verifierKey">): boolean => a.verifierKey === b.verifierKey;
