/**
 * The remote witness client (docs/reference/witness-protocol.md §9.6, §9.7): one `RemoteWitness`
 * per configured witness, speaking the `irontrellis-witness/1` HTTP protocol
 * over `fetch` (injectable; no dependencies). Nothing touches the network
 * until a method is called.
 *
 * Every answer is checked before it is believed:
 *  - every checkpoint (a C2SP signed note) must verify with the configured
 *    verifier key, and must be consistent with every checkpoint this client
 *    has seen from that witness origin (in memory, and the one persisted in
 *    `<history>.witness.json` through the `CheckpointTracker`): a larger tree
 *    must come with a valid consistency proof (`/v1/proofs/consistency`), a
 *    smaller one must be proven a prefix of the stored one, and an equal size
 *    must have the same root. A witness that cannot prove it is WITNESS_SPLIT_VIEW:
 *    fatal and sticky for this client (it showed two different logs);
 *  - every receipt is verified with `verifyWitnessReceipt` against the
 *    configured verifier key (never the key the receipt names) and must
 *    reference the entry the caller expects (the history, the head, the
 *    statement, the genesis, the rotation): anything else is
 *    WITNESS_INVALID_RESPONSE;
 *  - every answer about a history (`GET /v1/histories/:id`, `POST …/heads`,
 *    `POST …/key-events`, `POST /v1/histories`) is asked with a fresh random
 *    `nonce` and must carry the witness's signed `latestNote` over it
 *    (docs/reference/witness-protocol.md §9.8): the latest head it names (or none), its leaf index
 *    and the tree size must be exactly those of the `latest` receipt in the
 *    answer. An inclusion proof only shows a head is IN the log; the note shows
 *    it is the LATEST one now, so a relay cannot replay an older genuine answer.
 *    Missing or wrong: WITNESS_INVALID_RESPONSE.
 *
 * Failures are `EngineError`s with stable codes: WITNESS_UNAVAILABLE (network,
 * timeout, 5xx, 429, unparsable body: transient), WITNESS_REJECTED (a 4xx
 * refusal with the server's `code`, `hint`), WITNESS_INVALID_RESPONSE (a
 * signature, proof or entry check failed), WITNESS_SPLIT_VIEW (sticky).
 * Protocol outcomes that are answers, not failures (STALE_PREVIOUS,
 * EQUIVOCATION, NOT_REGISTERED), are returned as results. An EQUIVOCATION
 * answer (docs/reference/witness-protocol.md §9.2 rule 4) is evidence that the submitted statement
 * conflicts with a head the witness holds; the witness keeps accepting
 * statements that extend its latest head.
 */
import { canonicalEncode } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { historyIdOfGenesis } from "./hash.ts";
import { decodeBase64, encodeBase64 } from "./transparency/base64.ts";
import type { WitnessEntry } from "./transparency/entry.ts";
import { verifyConsistency } from "./transparency/merkle.ts";
import { NoteError, openNote, parseCheckpoint, parseVerifierKey } from "./transparency/note.ts";
import { newNonce, verifyLatestNote, type LatestNote } from "./transparency/latest.ts";
import { verifyWitnessReceipt, type WitnessReceipt } from "./transparency/receipt.ts";
import type { SignedHeadStatement, StatementHead } from "./transparency/statement.ts";
import type { ContentHash, OwnerKeyEpoch, U53 } from "./types.ts";

// ---------------------------------------------------------------- configuration

/** The subset of WHATWG `fetch` the client uses; inject one for tests or custom transports. */
export type WitnessFetch = (url: string, init: Readonly<{ method: string; headers: Readonly<Record<string, string>>; body?: string; signal?: AbortSignal }>) =>
  Promise<Readonly<{ ok: boolean; status: number; text(): Promise<string> }>>;

export type RemoteWitnessConfig = Readonly<{
  /**
   * Base URL, e.g. `https://witness.example.org` (the client appends `/v1/…`).
   * `https:` only, except a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`)
   * or `allowInsecureHttp`. Every answer is signed (checkpoints, receipts, and
   * the nonce-bound latest notes that make a replayed older answer detectable,
   * docs/reference/witness-protocol.md §9.8); TLS keeps the traffic private and is defence in depth.
   */
  url: string;
  /** The witness's note verifier key `<name>+<hash8>+<base64>` (from `irontrellis-witness init` / `verifier-key`). The only trust anchor. */
  verifierKey: string;
  /** A display name (default: the verifier key's name). */
  name?: string;
  /** Per-request timeout (default 10 000 ms). */
  timeoutMs?: number;
  /** Bearer token for registration when the witness runs `registration: "token"`. Kept in the side file (mode 0600). */
  token?: string;
  /** Accept a plain `http:` URL to a host that is not loopback (replayed answers cannot be ruled out; see `url`). */
  allowInsecureHttp?: boolean;
  /** Transport (default `globalThis.fetch`). */
  fetch?: WitnessFetch;
}>;

export type WitnessMode = "sync" | "async";
/**
 * How a history uses its remote witnesses (docs/reference/witness-policy.md §5.2):
 * - `witnesses`: the witnesses to submit to and consult (1..16);
 * - `quorum` (default 1): a head counts as witnessed once this many witnesses
 *   accepted it. Evidence of a rollback, fork or split view from ANY single
 *   witness is fatal regardless of the quorum. A check (open, first write,
 *   verify) needs answers from `n - quorum + 1` witnesses, so that it meets at
 *   least one of any `quorum` witnesses that accepted the latest head;
 * - `mode` (default async): `sync` submits the head statement before an owner
 *   write returns, `async` in a background worker (coalescing to the newest head);
 * - `maxUnwitnessedEvents` (default 1000): an owner-keyed writer refuses to
 *   append (WITNESS_UNAVAILABLE) while this many events are not yet witnessed
 *   by a quorum; reads continue;
 * - `requireOnOpen` (default false): readers must confirm with the witnesses
 *   that the file contains their latest heads before reading (owner-keyed
 *   writers always check before their first write in a process);
 * - `cacheMs` (default 60 000): how long a reader may rely on a witness check
 *   made earlier (in this process, or owner-sealed in the side file) instead of
 *   asking again. A cache only ever skips a network call; it never overrides a failure.
 */
export type WitnessPolicy = Readonly<{
  witnesses: readonly RemoteWitnessConfig[];
  quorum?: number;
  mode?: WitnessMode;
  maxUnwitnessedEvents?: number;
  requireOnOpen?: boolean;
  cacheMs?: number;
  /** Transport for every witness that sets none (tests, proxies). */
  fetch?: WitnessFetch;
}>;
export type ResolvedWitnessPolicy = Readonly<{
  witnesses: readonly RemoteWitnessConfig[];
  quorum: number;
  mode: WitnessMode;
  maxUnwitnessedEvents: number;
  requireOnOpen: boolean;
  cacheMs: number;
  fetch?: WitnessFetch;
}>;

export const WITNESS_PROTOCOL_VERSION = "irontrellis-witness/1";
export const DEFAULT_WITNESS_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_UNWITNESSED_EVENTS = 1000;
export const DEFAULT_WITNESS_CACHE_MS = 60_000;
export const MAX_REMOTE_WITNESSES = 16;
/** Largest response body the client reads (receipts carry a genesis event, at most 1 MiB). */
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const messageOf = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** `https://host/base/` → `https://host/base` (the canonical spelling; witnesses are matched by verifier key). */
export function normalizeWitnessUrl(url: string): string {
  if (typeof url !== "string" || url.length === 0 || url.length > 2048) throw new EngineError("INVALID_INPUT", "a witness url is a non-empty string");
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new EngineError("INVALID_INPUT", `not a URL: ${url}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new EngineError("INVALID_INPUT", `a witness url must be http(s): ${url}`);
  if (parsed.search !== "" || parsed.hash !== "" || parsed.username !== "" || parsed.password !== "") throw new EngineError("INVALID_INPUT", `a witness url carries no query, fragment or credentials: ${url}`);
  return parsed.toString().replace(/\/+$/, "");
}

const positiveInteger = (value: unknown, name: string, min: number, max: number): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) throw new EngineError("INVALID_INPUT", `witness policy: ${name} must be an integer in ${min}..${max}`);
  return value;
};

/** `localhost`, `127.0.0.0/8` or `[::1]`: a host whose traffic never leaves the machine. */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host === "[::1]") return true;
  const octets = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return octets !== null && Number(octets[1]) === 127 && octets.slice(2).every((octet) => Number(octet) <= 255);
}

/**
 * One witness config, checked: an `https:` URL (plain `http:` only to a
 * loopback host or with `allowInsecureHttp`), a verifier key that parses,
 * bounded name/timeout/token.
 */
export function normalizeWitnessConfig(config: unknown): RemoteWitnessConfig {
  if (!isRecord(config)) throw new EngineError("INVALID_INPUT", "a remote witness is { url, verifierKey, name?, timeoutMs?, token?, allowInsecureHttp?, fetch? }");
  const unknown = Object.keys(config).filter((key) => !["url", "verifierKey", "name", "timeoutMs", "token", "allowInsecureHttp", "fetch"].includes(key));
  if (unknown.length > 0) throw new EngineError("INVALID_INPUT", `remote witness: unknown field ${unknown[0]}`);
  const url = normalizeWitnessUrl(config.url as string);
  if (config.allowInsecureHttp !== undefined && typeof config.allowInsecureHttp !== "boolean") throw new EngineError("INVALID_INPUT", "remote witness: allowInsecureHttp is a boolean");
  const parsedUrl = new URL(url);
  if (parsedUrl.protocol === "http:" && !isLoopbackHost(parsedUrl.hostname) && config.allowInsecureHttp !== true) {
    throw new EngineError("INVALID_INPUT",
      `remote witness ${url}: plain http is refused for a host that is not loopback: every answer is signed (checkpoints, receipts, and the nonce-bound latest notes that expose a replayed older answer), but anyone on the path could read the traffic and suppress or delay answers and statements; use https (or allowInsecureHttp / --allow-insecure-http to accept that)`,
      { url, reason: "INSECURE_HTTP" });
  }
  if (typeof config.verifierKey !== "string") throw new EngineError("INVALID_INPUT", "remote witness: verifierKey is required");
  try {
    parseVerifierKey(config.verifierKey);
  } catch (error) {
    throw new EngineError("INVALID_INPUT", `remote witness ${url}: invalid verifier key: ${messageOf(error)}`);
  }
  if (config.name !== undefined && (typeof config.name !== "string" || config.name.length === 0 || config.name.length > 128 || /[\u0000-\u001f\u007f]/.test(config.name))) {
    throw new EngineError("INVALID_INPUT", "remote witness: name is 1..128 characters without control characters");
  }
  if (config.timeoutMs !== undefined) positiveInteger(config.timeoutMs, "timeoutMs", 1, 600_000);
  if (config.token !== undefined && (typeof config.token !== "string" || config.token.length === 0 || config.token.length > 1024 || /[\s\u0000-\u001f\u007f]/.test(config.token))) {
    throw new EngineError("INVALID_INPUT", "remote witness: token is 1..1024 visible characters");
  }
  if (config.fetch !== undefined && typeof config.fetch !== "function") throw new EngineError("INVALID_INPUT", "remote witness: fetch must be a function");
  return Object.freeze({
    url, verifierKey: config.verifierKey, ...(config.name === undefined ? {} : { name: config.name as string }), ...(config.timeoutMs === undefined ? {} : { timeoutMs: config.timeoutMs as number }),
    ...(config.token === undefined ? {} : { token: config.token as string }), ...(config.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}),
    ...(config.fetch === undefined ? {} : { fetch: config.fetch as WitnessFetch }),
  });
}

/** Validates a policy and fills in the defaults. Witnesses are deduplicated by verifier key (the first spelling wins). */
export function normalizeWitnessPolicy(policy: unknown): ResolvedWitnessPolicy {
  if (!isRecord(policy)) throw new EngineError("INVALID_INPUT", "a witness policy is { witnesses, quorum?, mode?, maxUnwitnessedEvents?, requireOnOpen?, cacheMs? }");
  const unknown = Object.keys(policy).filter((key) => !["witnesses", "quorum", "mode", "maxUnwitnessedEvents", "requireOnOpen", "cacheMs", "fetch"].includes(key));
  if (unknown.length > 0) throw new EngineError("INVALID_INPUT", `witness policy: unknown field ${unknown[0]}`);
  if (!Array.isArray(policy.witnesses) || policy.witnesses.length > MAX_REMOTE_WITNESSES) throw new EngineError("INVALID_INPUT", `witness policy: witnesses is a list of at most ${MAX_REMOTE_WITNESSES}`);
  const witnesses: RemoteWitnessConfig[] = [];
  for (const raw of policy.witnesses) {
    const config = normalizeWitnessConfig(raw);
    if (!witnesses.some((known) => known.verifierKey === config.verifierKey)) witnesses.push(config);
  }
  const quorum = policy.quorum === undefined ? 1 : positiveInteger(policy.quorum, "quorum", 1, MAX_REMOTE_WITNESSES);
  if (witnesses.length > 0 && quorum > witnesses.length) throw new EngineError("INVALID_INPUT", `witness policy: quorum ${quorum} exceeds the ${witnesses.length} configured witness(es)`);
  if (policy.mode !== undefined && policy.mode !== "sync" && policy.mode !== "async") throw new EngineError("INVALID_INPUT", "witness policy: mode is sync or async");
  if (policy.requireOnOpen !== undefined && typeof policy.requireOnOpen !== "boolean") throw new EngineError("INVALID_INPUT", "witness policy: requireOnOpen is a boolean");
  if (policy.fetch !== undefined && typeof policy.fetch !== "function") throw new EngineError("INVALID_INPUT", "witness policy: fetch must be a function");
  return Object.freeze({
    witnesses: Object.freeze(witnesses), quorum, mode: (policy.mode as WitnessMode | undefined) ?? "async",
    maxUnwitnessedEvents: policy.maxUnwitnessedEvents === undefined ? DEFAULT_MAX_UNWITNESSED_EVENTS : positiveInteger(policy.maxUnwitnessedEvents, "maxUnwitnessedEvents", 1, Number.MAX_SAFE_INTEGER),
    requireOnOpen: policy.requireOnOpen === true,
    cacheMs: policy.cacheMs === undefined ? DEFAULT_WITNESS_CACHE_MS : positiveInteger(policy.cacheMs, "cacheMs", 0, 86_400_000),
    ...(policy.fetch === undefined ? {} : { fetch: policy.fetch as WitnessFetch }),
  });
}

/** How many witnesses a check must hear from: `n - quorum + 1` (every set of `quorum` witnesses meets it). */
export const witnessesToConsult = (policy: Pick<ResolvedWitnessPolicy, "witnesses" | "quorum">): number =>
  policy.witnesses.length === 0 ? 0 : Math.max(1, policy.witnesses.length - Math.min(policy.quorum, policy.witnesses.length) + 1);

// ---------------------------------------------------------------- checkpoints

export type StoredCheckpoint = Readonly<{ size: number; rootB64: string; note: string }>;
/**
 * Where a client keeps the last checkpoint it accepted per witness origin.
 * The store backs it with `<history>.witness.json`; that file is writable by
 * whoever can write the history, so it only ADDS split-view detection: a
 * deleted or rolled-back entry costs detection strength, never correctness
 * (the client also keeps the largest checkpoint it saw in memory).
 */
export interface CheckpointTracker {
  get(origin: string): StoredCheckpoint | undefined;
  set(origin: string, checkpoint: StoredCheckpoint): void;
}
export function memoryCheckpointTracker(): CheckpointTracker {
  const map = new Map<string, StoredCheckpoint>();
  return Object.freeze({ get: (origin: string) => map.get(origin), set: (origin: string, checkpoint: StoredCheckpoint) => { map.set(origin, checkpoint); } });
}

export type VerifiedCheckpoint = Readonly<{ origin: string; size: number; root: Uint8Array; rootB64: string; note: string }>;

// ---------------------------------------------------------------- results

export type RemoteWitnessedHead = Readonly<{ head: StatementHead; receipt: WitnessReceipt; index: number; checkpoint: VerifiedCheckpoint }>;
export type WitnessHistoryInfo = Readonly<{
  historyId: ContentHash;
  /** EQUIVOCATION entries the witness recorded for this history (evidence that the owner key signed conflicting heads; the history stays open, docs/reference/witness-operations.md). */
  equivocations: number;
  /** SUPERSEDED entries: a pre-rotated rotation overrode heads an owner key signed after the last good head (docs/reference/witness-operations.md §7.4). */
  supersedes: number;
  /** The newest verified SUPERSEDED entry, when `supersedes > 0`. */
  lastSupersede?: Readonly<{ receipt: WitnessReceipt; index: number }>;
  epochs: readonly OwnerKeyEpoch[];
  latest: RemoteWitnessedHead | null;
  /** The newest verified EQUIVOCATION entry, when `equivocations > 0`. */
  lastEquivocation?: Readonly<{ receipt: WitnessReceipt; index: number }>;
}>;
/**
 * What a verified EQUIVOCATION entry proves about a submitted statement: `SUBMITTED` records this very statement,
 * `POSITION` records another conflicting statement at the same position (the witness keeps one entry per position),
 * so its `first` is the head the witness holds there; `OTHER` is the history's most recent entry (the per-history cap
 * was reached), which proves nothing about this position: judge the (fresh, signed) `latest` instead.
 */
export type EquivocationEvidence = "SUBMITTED" | "POSITION" | "OTHER";
export type SubmitResult =
  | Readonly<{ kind: "ACCEPTED"; status: "APPENDED" | "ALREADY_WITNESSED"; receipt: WitnessReceipt; index: number; latest: RemoteWitnessedHead }>
  | Readonly<{ kind: "STALE_PREVIOUS"; latest: RemoteWitnessedHead | null }>
  /** The witness holds a different head at the statement's position: the verified EQUIVOCATION entry (see `evidence`), and the witness latest. */
  | Readonly<{ kind: "EQUIVOCATION"; receipt: WitnessReceipt; index: number; message: string; latest: RemoteWitnessedHead | null; evidence: EquivocationEvidence }>
  | Readonly<{ kind: "NOT_REGISTERED" }>
  /** 409 SUPERSEDED (docs/reference/witness-operations.md §7.4): the statement states or extends a head a pre-rotated rotation overrode; `latest` is the witness's (verified). */
  | Readonly<{ kind: "SUPERSEDED"; latest: RemoteWitnessedHead | null; message: string }>
  | Readonly<{ kind: "REJECTED"; code: string; message: string; hint?: string; status: number }>;
/** `POST …/key-events` (docs/reference/witness-protocol.md §9.2): the key event is recorded (`superseded`: it overrode heads, §7.4), or an answer that is not. */
export type KeyEventResult =
  | Readonly<{ kind: "ACCEPTED"; receipt: WitnessReceipt; index: number; epochs: readonly OwnerKeyEpoch[]; latest: RemoteWitnessedHead | null; superseded?: Readonly<{ receipt: WitnessReceipt; index: number }> }>
  | Readonly<{ kind: "STALE_PREVIOUS"; latest: RemoteWitnessedHead | null; message: string }>
  | Readonly<{ kind: "NOT_REGISTERED" }>
  | Readonly<{ kind: "REJECTED"; code: string; message: string; hint?: string; status: number }>;
/** The body of `POST …/key-events`: the event, the heads around it, and the statement for its head (and a supersede `chain`). */
export type KeyEventDelivery = Readonly<{
  event: unknown; previousHead: Readonly<{ hash: ContentHash; position: U53 }>; eventHead: Readonly<{ hash: ContentHash; position: U53 }>;
  statement?: SignedHeadStatement; chain?: SignedHeadStatement;
}>;
export type WitnessInfo = Readonly<{ version: string; origin: string; verifierKey: string; software?: string }>;

export interface RemoteWitness {
  readonly url: string;
  readonly name: string;
  readonly verifierKey: string;
  /** The checkpoint origin, once a verified checkpoint was seen. */
  readonly origin: string | undefined;
  /** The sticky split-view finding, once one was made. */
  readonly splitView: EngineError | undefined;
  /** `GET /v1/witness`; checks that the witness serves the configured verifier key. */
  info(): Promise<WitnessInfo>;
  /** `GET /v1/checkpoint`: the current signed checkpoint, verified and checked for consistency. */
  checkpoint(): Promise<VerifiedCheckpoint>;
  /**
   * `POST /v1/histories`: registers (idempotently) the genesis; the REGISTERED receipt is checked against it. `latest`:
   * the latest head the witness holds for the history, from its signed latest note over this request's nonce (`null`:
   * none; a history registered just now has none).
   */
  register(genesis: unknown): Promise<Readonly<{ historyId: ContentHash; created: boolean; receipt: WitnessReceipt; index: number; latest: Readonly<{ hash: ContentHash; position: number }> | null }>>;
  /** `GET /v1/histories/:id`; `undefined` when the witness does not know the history. */
  history(historyId: ContentHash): Promise<WitnessHistoryInfo | undefined>;
  /** `POST /v1/histories/:id/heads`. */
  submit(signed: SignedHeadStatement): Promise<SubmitResult>;
  /** `POST /v1/histories/:id/key-events` (docs/WITNESS.md §7, §9.2): an owner key rotation (a commitment-only one included), with the statement for its head. */
  keyEvent(historyId: ContentHash, body: KeyEventDelivery): Promise<KeyEventResult>;
  /** `GET /v1/histories/:id/heads/:position`; `undefined` when the witness holds no head there. */
  head(historyId: ContentHash, position: number): Promise<RemoteWitnessedHead | undefined>;
  /** `GET /v1/proofs/consistency` (raw proof; `checkpoint()` and every response already check consistency). */
  consistency(from: number, to: number): Promise<readonly Uint8Array[]>;
  /** `GET /v1/entries?start=&end=` (end exclusive, at most 1000). */
  entries(start: number, end: number): Promise<readonly WitnessEntry[]>;
}

// ---------------------------------------------------------------- the client

const failure = (code: "WITNESS_UNAVAILABLE" | "WITNESS_REJECTED" | "WITNESS_INVALID_RESPONSE" | "WITNESS_SPLIT_VIEW", url: string, message: string, detail: Record<string, unknown> = {}): EngineError =>
  new EngineError(code, `witness ${url}: ${message}`, { url, ...detail });

type Reply = Readonly<{ status: number; json: unknown; text: string }>;

const sameStatementHead = (a: unknown, b: Readonly<{ hash: string; position: number }>): boolean =>
  isRecord(a) && a.hash === b.hash && a.position === b.position;

const canonicalEqual = (a: unknown, b: unknown): boolean => {
  try {
    return canonicalEncode(a) === canonicalEncode(b);
  } catch {
    return false;
  }
};

const CONTENT_HASH = /^0x[0-9a-f]{64}$/;
const isEpochs = (value: unknown): value is OwnerKeyEpoch[] =>
  Array.isArray(value) && value.every((epoch) => isRecord(epoch) && Number.isSafeInteger(epoch.fromPosition) && Array.isArray(epoch.keys) &&
    (epoch.keys as unknown[]).every((key) => isRecord(key) && typeof key.keyId === "string" && typeof key.scheme === "string" && typeof key.credential === "string") &&
    (epoch.nextKeyDigests === undefined || (Array.isArray(epoch.nextKeyDigests) && epoch.nextKeyDigests.length > 0 && epoch.nextKeyDigests.every((digest) => typeof digest === "string" && CONTENT_HASH.test(digest)))));
/** The epochs as this client keeps them (frozen, only the known fields). */
const epochsOf = (epochs: readonly OwnerKeyEpoch[]): readonly OwnerKeyEpoch[] => Object.freeze(epochs.map((epoch) => Object.freeze({
  fromPosition: epoch.fromPosition, keys: Object.freeze(epoch.keys.map((key) => Object.freeze({ keyId: key.keyId, scheme: key.scheme, credential: key.credential }))),
  ...(epoch.nextKeyDigests === undefined ? {} : { nextKeyDigests: Object.freeze([...epoch.nextKeyDigests]) }),
})));

/**
 * A client for one remote witness. `options.tracker` persists the accepted
 * checkpoint per origin (default: memory only). Methods throw `EngineError`
 * (WITNESS_UNAVAILABLE, WITNESS_REJECTED, WITNESS_INVALID_RESPONSE,
 * WITNESS_SPLIT_VIEW); protocol answers come back as results.
 */
export function remoteWitness(config: RemoteWitnessConfig, options: Readonly<{ tracker?: CheckpointTracker; fetch?: WitnessFetch }> = {}): RemoteWitness {
  const checked = normalizeWitnessConfig(config);
  return new RemoteWitnessClient(checked, options.tracker ?? memoryCheckpointTracker(), checked.fetch ?? options.fetch);
}

class RemoteWitnessClient implements RemoteWitness {
  readonly url: string;
  readonly name: string;
  readonly verifierKey: string;
  readonly #config: RemoteWitnessConfig;
  readonly #tracker: CheckpointTracker;
  readonly #fetch: WitnessFetch;
  #origin: string | undefined;
  #splitView: EngineError | undefined;
  /** The largest checkpoint accepted in this process (the side file may be rolled back underneath). */
  #largest: StoredCheckpoint | undefined;

  constructor(config: RemoteWitnessConfig, tracker: CheckpointTracker, transport: WitnessFetch | undefined) {
    this.#config = config;
    this.url = config.url;
    this.verifierKey = config.verifierKey;
    this.name = config.name ?? parseVerifierKey(config.verifierKey).name;
    this.#tracker = tracker;
    this.#fetch = transport ?? ((url, init) => globalThis.fetch(url, init));
  }

  get origin(): string | undefined { return this.#origin; }
  get splitView(): EngineError | undefined { return this.#splitView; }

  // ---- transport

  async #call(method: "GET" | "POST", path: string, body?: unknown, authorized = false): Promise<Reply> {
    if (this.#splitView !== undefined) throw this.#splitView;
    const headers: Record<string, string> = { accept: "application/json, text/plain" };
    let payload: string | undefined;
    if (body !== undefined) {
      try {
        payload = JSON.stringify(body);
      } catch (error) {
        throw new EngineError("INVALID_INPUT", `witness request body is not JSON: ${messageOf(error)}`);
      }
      headers["content-type"] = "application/json";
    }
    if (authorized && this.#config.token !== undefined) headers.authorization = `Bearer ${this.#config.token}`;
    const timeout = this.#config.timeoutMs ?? DEFAULT_WITNESS_TIMEOUT_MS;
    let response: Awaited<ReturnType<WitnessFetch>>;
    let text: string;
    try {
      response = await this.#fetch(`${this.url}${path}`, { method, headers, ...(payload === undefined ? {} : { body: payload }), signal: AbortSignal.timeout(timeout) });
      text = await response.text();
    } catch (error) {
      throw failure("WITNESS_UNAVAILABLE", this.url, `${method} ${path} failed: ${messageOf(error)}`, { cause: (error as { name?: string } | null)?.name });
    }
    if (typeof text !== "string" || text.length > MAX_RESPONSE_BYTES) throw failure("WITNESS_UNAVAILABLE", this.url, `${method} ${path}: response too large`);
    if (response.status >= 500 || response.status === 429 || response.status === 408) {
      throw failure("WITNESS_UNAVAILABLE", this.url, `${method} ${path} answered ${response.status}`, { status: response.status });
    }
    let json: unknown;
    if (path !== "/v1/checkpoint" || !response.ok) {
      try {
        json = JSON.parse(text);
      } catch {
        throw failure("WITNESS_UNAVAILABLE", this.url, `${method} ${path} answered ${response.status} with a body that is not JSON`, { status: response.status });
      }
    }
    return { status: response.status, json, text };
  }

  /** The error body `{ error: { code, message, hint? }, ... }` of a non-2xx reply. */
  #errorOf(reply: Reply): { code: string; message: string; hint?: string } {
    const error = isRecord(reply.json) && isRecord(reply.json.error) ? reply.json.error : undefined;
    const code = typeof error?.code === "string" ? error.code : `HTTP_${reply.status}`;
    const message = typeof error?.message === "string" ? error.message : `answered ${reply.status}`;
    return { code, message, ...(typeof error?.hint === "string" ? { hint: error.hint } : {}) };
  }

  #rejected(reply: Reply, what: string): EngineError {
    const { code, message, hint } = this.#errorOf(reply);
    return failure("WITNESS_REJECTED", this.url, `${what}: ${code}: ${message}`, { status: reply.status, code, ...(hint === undefined ? {} : { hint }) });
  }

  #invalid(message: string, detail: Record<string, unknown> = {}): EngineError {
    return failure("WITNESS_INVALID_RESPONSE", this.url, message, detail);
  }

  // ---- checkpoints and consistency

  #markSplitView(message: string, detail: Record<string, unknown>): never {
    this.#splitView = failure("WITNESS_SPLIT_VIEW", this.url, `split view: ${message}`, { origin: this.#origin, ...detail });
    throw this.#splitView;
  }

  /** Opens and parses a signed checkpoint note with the configured key; pins the origin. */
  #open(note: unknown): VerifiedCheckpoint {
    if (typeof note !== "string") throw this.#invalid("checkpoint is not a signed note");
    let checkpoint: ReturnType<typeof parseCheckpoint>;
    try {
      checkpoint = parseCheckpoint(openNote(note, [this.verifierKey]).body);
    } catch (error) {
      throw this.#invalid(`checkpoint does not verify with the configured verifier key: ${error instanceof NoteError ? `${error.code}: ${error.message}` : messageOf(error)}`);
    }
    if (this.#origin !== undefined && checkpoint.origin !== this.#origin) throw this.#invalid(`checkpoint origin ${JSON.stringify(checkpoint.origin)} is not the witness origin ${JSON.stringify(this.#origin)}`);
    this.#origin ??= checkpoint.origin;
    return Object.freeze({ origin: checkpoint.origin, size: checkpoint.size, root: checkpoint.root, rootB64: encodeBase64(checkpoint.root), note });
  }

  /** Proves `smaller` is a prefix of `larger` with the witness's consistency proof; split view otherwise. */
  async #prove(smaller: StoredCheckpoint, larger: StoredCheckpoint, which: string): Promise<void> {
    if (smaller.size === larger.size) {
      if (smaller.rootB64 !== larger.rootB64) this.#markSplitView(`two checkpoints of size ${smaller.size} with different roots (${which})`, { stored: smaller, received: larger });
      return;
    }
    if (smaller.size === 0) return; // the empty tree is a prefix of every tree
    let proof: Uint8Array[];
    try {
      proof = await this.#consistencyProof(smaller.size, larger.size);
    } catch (error) {
      // Both checkpoints verify with the witness key, so the witness signed both trees. An honest witness can always prove
      // the smaller a prefix of the larger; a refusal (4xx, e.g. "to exceeds the log size": the log it serves now is shorter
      // than one it signed) is a split view, not unavailability. Transport failures (5xx, network) stay transient.
      if (error instanceof EngineError && error.code === "WITNESS_REJECTED") {
        this.#markSplitView(`the witness refuses to prove that its tree of size ${smaller.size} is a prefix of its tree of size ${larger.size} (${which}): ${error.message}`, { stored: smaller, received: larger });
      }
      throw error;
    }
    const smallRoot = decodeBase64(smaller.rootB64), largeRoot = decodeBase64(larger.rootB64);
    if (smallRoot === undefined || largeRoot === undefined || !verifyConsistency(smaller.size, larger.size, smallRoot, largeRoot, proof)) {
      this.#markSplitView(`the witness cannot prove that its tree of size ${smaller.size} is a prefix of its tree of size ${larger.size} (${which})`, { stored: smaller, received: larger });
    }
  }

  /**
   * Accepts a checkpoint seen in any response: verified note, then consistent
   * with the largest checkpoint of this process and the tracker's; the largest
   * is kept. Split view is sticky.
   */
  async #observe(note: unknown): Promise<VerifiedCheckpoint> {
    const checkpoint = this.#open(note);
    const received: StoredCheckpoint = { size: checkpoint.size, rootB64: checkpoint.rootB64, note: checkpoint.note };
    const known: StoredCheckpoint[] = [];
    if (this.#largest !== undefined) known.push(this.#largest);
    let stored: StoredCheckpoint | undefined;
    try {
      stored = this.#tracker.get(checkpoint.origin);
    } catch {
      stored = undefined;
    }
    // A stored checkpoint must itself verify with the configured key; one that does not is ignored (the file is not trusted).
    if (stored !== undefined && (this.#largest === undefined || stored.size !== this.#largest.size || stored.rootB64 !== this.#largest.rootB64)) {
      let valid = false;
      try {
        const reopened = parseCheckpoint(openNote(stored.note, [this.verifierKey]).body);
        valid = reopened.origin === checkpoint.origin && reopened.size === stored.size && encodeBase64(reopened.root) === stored.rootB64;
      } catch {
        valid = false;
      }
      if (valid) known.push(stored);
    }
    for (const earlier of known) {
      if (earlier.size <= received.size) await this.#prove(earlier, received, "new checkpoint against an earlier one");
      else await this.#prove(received, earlier, "older checkpoint against a later one");
    }
    const largest = [received, ...known].reduce((a, b) => (b.size > a.size ? b : a));
    this.#largest = largest;
    if (stored === undefined || largest.size > stored.size) {
      try { this.#tracker.set(checkpoint.origin, largest); } catch { /* best effort: memory still holds it */ }
    }
    return checkpoint;
  }

  async #consistencyProof(from: number, to: number): Promise<Uint8Array[]> {
    const reply = await this.#call("GET", `/v1/proofs/consistency?from=${from}&to=${to}`);
    if (reply.status !== 200) throw this.#rejected(reply, `consistency proof ${from}..${to}`);
    const body = reply.json;
    if (!isRecord(body) || body.from !== from || body.to !== to || !Array.isArray(body.proof)) throw this.#invalid("malformed consistency proof response");
    const proof: Uint8Array[] = [];
    for (const element of body.proof) {
      const bytes = decodeBase64(element);
      if (bytes === undefined || bytes.length !== 32) throw this.#invalid("consistency proof elements are base64 32-byte hashes");
      proof.push(bytes);
    }
    return proof;
  }

  /** A receipt: verified with the configured key, its checkpoint observed, its entry checked by `expect` (a reason on mismatch). */
  async #receipt(receipt: unknown, expect: (entry: Record<string, unknown>) => string | null): Promise<{ receipt: WitnessReceipt; index: number; checkpoint: VerifiedCheckpoint }> {
    const verdict = verifyWitnessReceipt(receipt, [this.verifierKey]);
    if (!verdict.ok) throw this.#invalid(`receipt does not verify: ${verdict.reason}: ${verdict.message}`, { reason: verdict.reason });
    const value = receipt as WitnessReceipt;
    const mismatch = expect(value.entry as unknown as Record<string, unknown>);
    if (mismatch !== null) throw this.#invalid(`receipt names another entry: ${mismatch}`);
    const checkpoint = await this.#observe(value.checkpoint);
    return { receipt: value, index: verdict.index, checkpoint };
  }

  /** `{ head, receipt }` where the receipt is a HEAD entry of `historyId` for exactly `head`. */
  async #witnessedHead(value: unknown, historyId: ContentHash): Promise<RemoteWitnessedHead> {
    if (!isRecord(value) || !isRecord(value.head)) throw this.#invalid("malformed witnessed head");
    const head = value.head;
    if (typeof head.hash !== "string" || !Number.isSafeInteger(head.position) || !Number.isSafeInteger(head.canonicalTime)) throw this.#invalid("malformed witnessed head");
    const checked = await this.#receipt(value.receipt, (entry) => {
      if (entry.kind !== "HEAD" || entry.historyId !== historyId) return `expected a HEAD entry of ${historyId}`;
      const statement = (entry.signedStatement as { statement?: { head?: unknown } } | undefined)?.statement;
      return sameStatementHead(statement?.head, head as { hash: string; position: number }) && (statement!.head as { canonicalTime?: unknown }).canonicalTime === head.canonicalTime
        ? null : "the HEAD entry states another head";
    });
    return Object.freeze({
      head: Object.freeze({ hash: head.hash as ContentHash, position: head.position as number, canonicalTime: head.canonicalTime as number }),
      receipt: checked.receipt, index: checked.index, checkpoint: checked.checkpoint,
    });
  }

  /** An EQUIVOCATION leaf of `historyId`; with `second`, what it proves about that statement (`EquivocationEvidence`). */
  async #equivocation(receipt: unknown, historyId: ContentHash, second?: SignedHeadStatement): Promise<{ receipt: WitnessReceipt; index: number; evidence: EquivocationEvidence }> {
    let evidence: EquivocationEvidence = "OTHER";
    const checked = await this.#receipt(receipt, (entry) => {
      if (entry.kind !== "EQUIVOCATION" || entry.historyId !== historyId) return `expected an EQUIVOCATION entry of ${historyId}`;
      if (second !== undefined) {
        const held = (entry.first as { statement?: { head?: { hash?: unknown; position?: unknown } } } | undefined)?.statement?.head;
        if (canonicalEqual(entry.second, second)) evidence = "SUBMITTED";
        else if (held?.position === second.statement.head.position && held.hash !== second.statement.head.hash) evidence = "POSITION";
      }
      return null;
    });
    return { receipt: checked.receipt, index: checked.index, evidence };
  }

  /**
   * The signed latest note of an answer about `historyId` (docs/reference/witness-protocol.md §9.8): opened with the configured key, for
   * this origin, history and `nonce`, and naming exactly `latest` (its head, its leaf index, its checkpoint's tree
   * size; or none). `sizeOf`: the tree size a `null` latest is checked against (the answer's other receipts or its
   * top-level checkpoint), when there is one. WITNESS_INVALID_RESPONSE otherwise: a missing or wrong note means the
   * answer may be a replayed older one.
   */
  #fresh(note: unknown, historyId: ContentHash, nonce: string, latest: RemoteWitnessedHead | null, sizeOf?: number): LatestNote {
    if (note === undefined) throw this.#invalid("the answer carries no signed latest note (latestNote): it cannot be told from a replayed older answer", { reason: "LATEST_NOTE_MISSING" });
    const verdict = verifyLatestNote(note, [this.verifierKey], { historyId, nonce, ...(this.#origin === undefined ? {} : { origin: this.#origin }) });
    if (!verdict.ok) throw this.#invalid(`the latest note does not verify: ${verdict.reason}: ${verdict.message}`, { reason: "LATEST_NOTE_INVALID", cause: verdict.reason });
    const signed = verdict.latest;
    if (latest === null) {
      if (signed.latest !== null) throw this.#invalid(`the witness signed latest head position ${signed.latest.position} but the answer names none (a replayed or altered answer)`, { reason: "LATEST_NOTE_MISMATCH" });
      if (sizeOf !== undefined && signed.treeSize !== sizeOf) throw this.#invalid(`the latest note is for tree size ${signed.treeSize}, the answer for ${sizeOf}`, { reason: "LATEST_NOTE_MISMATCH" });
      return signed;
    }
    const named = signed.latest;
    if (named === null || named.position !== latest.head.position || named.hash !== latest.head.hash || named.index !== latest.index || signed.treeSize !== latest.checkpoint.size) {
      throw this.#invalid(`the latest note (${named === null ? "no head" : `position ${named.position}, leaf ${named.index}`}, tree size ${signed.treeSize}) does not name the answer's latest head (position ${latest.head.position}, leaf ${latest.index}, tree size ${latest.checkpoint.size}): a replayed or altered answer`,
        { reason: "LATEST_NOTE_MISMATCH" });
    }
    return signed;
  }

  /**
   * The latest note of an answer that does not carry a `latest` receipt (registration, rotation): signed over the
   * nonce for this history, at the tree size of the answer's receipt.
   */
  #freshNote(note: unknown, historyId: ContentHash, nonce: string, treeSize: number): LatestNote {
    if (note === undefined) throw this.#invalid("the answer carries no signed latest note (latestNote)", { reason: "LATEST_NOTE_MISSING" });
    const verdict = verifyLatestNote(note, [this.verifierKey], { historyId, nonce, ...(this.#origin === undefined ? {} : { origin: this.#origin }) });
    if (!verdict.ok) throw this.#invalid(`the latest note does not verify: ${verdict.reason}: ${verdict.message}`, { reason: "LATEST_NOTE_INVALID", cause: verdict.reason });
    if (verdict.latest.treeSize !== treeSize) throw this.#invalid(`the latest note is for tree size ${verdict.latest.treeSize}, the answer for ${treeSize}`, { reason: "LATEST_NOTE_MISMATCH" });
    return verdict.latest;
  }

  /** The tree size of the reply's top-level checkpoint (verified and observed), for a `null` latest; `undefined` when absent. */
  async #replySize(body: Record<string, unknown>): Promise<number | undefined> {
    return typeof body.checkpoint === "string" ? (await this.#observe(body.checkpoint)).size : undefined;
  }

  // ---- methods

  async info(): Promise<WitnessInfo> {
    const reply = await this.#call("GET", "/v1/witness");
    if (reply.status !== 200) throw this.#rejected(reply, "witness info");
    const body = reply.json;
    if (!isRecord(body) || typeof body.origin !== "string" || typeof body.verifierKey !== "string" || typeof body.version !== "string") throw this.#invalid("malformed witness info");
    if (body.verifierKey !== this.verifierKey) throw this.#invalid(`the witness serves verifier key ${body.verifierKey}, not the configured ${this.verifierKey}`);
    return Object.freeze({ version: body.version, origin: body.origin, verifierKey: body.verifierKey, ...(typeof body.software === "string" ? { software: body.software } : {}) });
  }

  async checkpoint(): Promise<VerifiedCheckpoint> {
    const reply = await this.#call("GET", "/v1/checkpoint");
    if (reply.status !== 200) throw this.#rejected(reply, "checkpoint");
    return this.#observe(reply.text);
  }

  async register(genesis: unknown): Promise<Readonly<{ historyId: ContentHash; created: boolean; receipt: WitnessReceipt; index: number; latest: Readonly<{ hash: ContentHash; position: number }> | null }>> {
    let historyId: ContentHash;
    try {
      historyId = historyIdOfGenesis(genesis);
    } catch (error) {
      throw new EngineError("INVALID_INPUT", `genesis is not an event: ${messageOf(error)}`);
    }
    const nonce = newNonce();
    const reply = await this.#call("POST", `/v1/histories?nonce=${nonce}`, { genesis }, true);
    if (reply.status !== 200 && reply.status !== 201) throw this.#rejected(reply, "register");
    const body = reply.json;
    if (!isRecord(body) || body.historyId !== historyId) throw this.#invalid(`registration names history ${isRecord(body) ? String(body.historyId) : "?"}, not ${historyId}`);
    const checked = await this.#receipt(body.receipt, (entry) =>
      entry.kind === "REGISTERED" && entry.historyId === historyId && canonicalEqual(entry.genesis, genesis) ? null : "expected the REGISTERED entry of this genesis");
    const note = this.#freshNote(body.latestNote, historyId, nonce, checked.checkpoint.size);
    if (reply.status === 201 && note.latest !== null) throw this.#invalid("a new registration cannot already hold a head", { reason: "LATEST_NOTE_MISMATCH" });
    const latest = note.latest === null ? null : Object.freeze({ hash: note.latest.hash as ContentHash, position: note.latest.position });
    return Object.freeze({ historyId, created: reply.status === 201, receipt: checked.receipt, index: checked.index, latest });
  }

  async history(historyId: ContentHash): Promise<WitnessHistoryInfo | undefined> {
    const nonce = newNonce();
    const reply = await this.#call("GET", `/v1/histories/${historyId}?nonce=${nonce}`);
    if (reply.status === 404) return undefined;
    if (reply.status !== 200) throw this.#rejected(reply, "history");
    const body = reply.json;
    if (!isRecord(body) || body.historyId !== historyId || !Number.isSafeInteger(body.equivocations) || (body.equivocations as number) < 0 || !isEpochs(body.epochs) ||
      !Number.isSafeInteger(body.supersedes) || (body.supersedes as number) < 0 || (body.latest !== null && !isRecord(body.latest))) {
      throw this.#invalid("malformed history summary");
    }
    const equivocations = body.equivocations as number;
    const supersedes = body.supersedes as number;
    const superseded = body.lastSupersede === undefined || body.lastSupersede === null ? undefined : await this.#receipt(body.lastSupersede, (entry) =>
      entry.kind === "SUPERSEDED" && entry.historyId === historyId ? null : `expected a SUPERSEDED entry of ${historyId}`);
    const lastSupersede = superseded === undefined ? undefined : Object.freeze({ receipt: superseded.receipt, index: superseded.index });
    if (supersedes > 0 && lastSupersede === undefined) throw this.#invalid(`the witness counts ${supersedes} supersede(s) for this history but shows no SUPERSEDED receipt`);
    if (supersedes === 0 && lastSupersede !== undefined) throw this.#invalid("the witness shows a SUPERSEDED receipt but counts no supersede");
    const latest = body.latest === null ? null : await this.#witnessedHead(body.latest, historyId);
    const evidence = body.lastEquivocation === undefined || body.lastEquivocation === null ? undefined : await this.#equivocation(body.lastEquivocation, historyId);
    const lastEquivocation = evidence === undefined ? undefined : Object.freeze({ receipt: evidence.receipt, index: evidence.index });
    if (equivocations > 0 && lastEquivocation === undefined) throw this.#invalid(`the witness counts ${equivocations} equivocation(s) for this history but shows no EQUIVOCATION receipt`);
    if (equivocations === 0 && lastEquivocation !== undefined) throw this.#invalid("the witness shows an EQUIVOCATION receipt but counts no equivocation");
    const note = this.#fresh(body.latestNote, historyId, nonce, latest, latest === null ? await this.#replySize(body) : undefined);
    if (note.equivocations !== equivocations) throw this.#invalid(`the latest note counts ${note.equivocations} equivocation(s), the answer ${equivocations}`, { reason: "LATEST_NOTE_MISMATCH" });
    if (note.supersedes !== supersedes) throw this.#invalid(`the latest note counts ${note.supersedes} supersede(s), the answer ${supersedes}`, { reason: "LATEST_NOTE_MISMATCH" });
    return Object.freeze({
      historyId, equivocations, supersedes, epochs: epochsOf(body.epochs), latest, ...(lastEquivocation === undefined ? {} : { lastEquivocation }),
      ...(lastSupersede === undefined ? {} : { lastSupersede }),
    });
  }

  async submit(signed: SignedHeadStatement): Promise<SubmitResult> {
    const historyId = signed.statement.historyId;
    const nonce = newNonce();
    const reply = await this.#call("POST", `/v1/histories/${historyId}/heads?nonce=${nonce}`, signed);
    const body = reply.json;
    if (reply.status === 200 || reply.status === 201) {
      if (!isRecord(body) || (body.status !== "APPENDED" && body.status !== "ALREADY_WITNESSED")) throw this.#invalid("malformed head response");
      const exact = body.status === "APPENDED";
      const checked = await this.#receipt(body.receipt, (entry) => {
        if (entry.kind !== "HEAD" || entry.historyId !== historyId) return `expected a HEAD entry of ${historyId}`;
        // APPENDED: the very statement; ALREADY_WITNESSED: the held statement for the same head (its previous may differ).
        if (exact) return canonicalEqual(entry.signedStatement, signed) ? null : "the HEAD entry is not the submitted statement";
        return sameStatementHead((entry.signedStatement as { statement?: { head?: unknown } } | undefined)?.statement?.head, signed.statement.head) ? null : "the HEAD entry states another head";
      });
      const latest = await this.#witnessedHead(body.latest, historyId);
      this.#fresh(body.latestNote, historyId, nonce, latest);
      return Object.freeze({ kind: "ACCEPTED" as const, status: body.status, receipt: checked.receipt, index: checked.index, latest });
    }
    if (reply.status === 404) return Object.freeze({ kind: "NOT_REGISTERED" as const });
    const { code, message, hint } = this.#errorOf(reply);
    if (reply.status === 409 && code === "STALE_PREVIOUS") {
      if (!isRecord(body) || (body.latest !== null && !isRecord(body.latest))) throw this.#invalid("STALE_PREVIOUS without latest");
      const latest = body.latest === null ? null : await this.#witnessedHead(body.latest, historyId);
      this.#fresh(body.latestNote, historyId, nonce, latest, latest === null ? await this.#replySize(body) : undefined);
      return Object.freeze({ kind: "STALE_PREVIOUS" as const, latest });
    }
    if (reply.status === 409 && code === "SUPERSEDED") {
      if (!isRecord(body) || (body.latest !== null && !isRecord(body.latest))) throw this.#invalid("SUPERSEDED without latest");
      const latest = body.latest === null ? null : await this.#witnessedHead(body.latest, historyId);
      this.#fresh(body.latestNote, historyId, nonce, latest, latest === null ? await this.#replySize(body) : undefined);
      return Object.freeze({ kind: "SUPERSEDED" as const, latest, message });
    }
    if (reply.status === 409 && code === "EQUIVOCATION") {
      // Evidence first (docs/reference/witness-protocol.md §9.7): a verifiable EQUIVOCATION leaf of this history, and the fresh latest; anything less is an invalid answer, not an alarm.
      if (!isRecord(body) || body.receipt === undefined || (body.latest !== null && !isRecord(body.latest))) throw this.#invalid("EQUIVOCATION without its receipt and latest");
      const evidence = await this.#equivocation(body.receipt, historyId, signed);
      const latest = body.latest === null ? null : await this.#witnessedHead(body.latest, historyId);
      this.#fresh(body.latestNote, historyId, nonce, latest, latest === null ? await this.#replySize(body) : undefined);
      return Object.freeze({ kind: "EQUIVOCATION" as const, receipt: evidence.receipt, index: evidence.index, message, latest, evidence: evidence.evidence });
    }
    return Object.freeze({ kind: "REJECTED" as const, code, message, status: reply.status, ...(hint === undefined ? {} : { hint }) });
  }

  async keyEvent(historyId: ContentHash, body: KeyEventDelivery): Promise<KeyEventResult> {
    const at = (head: Readonly<{ hash: ContentHash; position: U53 }>) => ({ hash: head.hash, position: head.position });
    const request = {
      event: body.event, previousHead: at(body.previousHead), eventHead: at(body.eventHead),
      ...(body.statement === undefined ? {} : { statement: body.statement }), ...(body.chain === undefined ? {} : { chain: body.chain }),
    };
    const nonce = newNonce();
    const reply = await this.#call("POST", `/v1/histories/${historyId}/key-events?nonce=${nonce}`, request);
    const response = reply.json;
    if (reply.status === 200 || reply.status === 201) {
      if (!isRecord(response) || !isEpochs(response.epochs) || (response.latest !== null && !isRecord(response.latest))) throw this.#invalid("malformed key-event response");
      const checked = await this.#receipt(response.receipt, (entry) => {
        // The only owner key event is OWNER_KEYS_ROTATED: its leaf is ROTATED.
        if (entry.kind !== "ROTATED" || entry.historyId !== historyId) return "expected the ROTATED entry of this key event";
        return canonicalEqual(entry.rotation, body.event) && sameStatementHead(entry.previousHead, body.previousHead) && sameStatementHead(entry.rotationHead, body.eventHead)
          ? null : "expected the ROTATED entry of this key event";
      });
      let superseded: Readonly<{ receipt: WitnessReceipt; index: number }> | undefined;
      if (response.superseded !== undefined) {
        const verified = await this.#receipt(response.superseded, (entry) =>
          entry.kind === "SUPERSEDED" && entry.historyId === historyId && canonicalEqual(entry.rotation, body.event) && canonicalEqual(entry.chain, body.chain) ? null : "expected the SUPERSEDED entry of this rotation");
        superseded = Object.freeze({ receipt: verified.receipt, index: verified.index });
      }
      const latest = response.latest === null ? null : await this.#witnessedHead(response.latest, historyId);
      this.#fresh(response.latestNote, historyId, nonce, latest, latest === null ? await this.#replySize(response) : undefined);
      return Object.freeze({ kind: "ACCEPTED" as const, receipt: checked.receipt, index: checked.index, epochs: epochsOf(response.epochs), latest, ...(superseded === undefined ? {} : { superseded }) });
    }
    if (reply.status === 404) return Object.freeze({ kind: "NOT_REGISTERED" as const });
    const { code, message, hint } = this.#errorOf(reply);
    if (reply.status === 409 && code === "STALE_PREVIOUS") {
      if (!isRecord(response) || (response.latest !== null && !isRecord(response.latest))) throw this.#invalid("STALE_PREVIOUS without latest");
      const latest = response.latest === null ? null : await this.#witnessedHead(response.latest, historyId);
      this.#fresh(response.latestNote, historyId, nonce, latest, latest === null ? await this.#replySize(response) : undefined);
      return Object.freeze({ kind: "STALE_PREVIOUS" as const, latest, message });
    }
    return Object.freeze({ kind: "REJECTED" as const, code, message, status: reply.status, ...(hint === undefined ? {} : { hint }) });
  }

  async head(historyId: ContentHash, position: number): Promise<RemoteWitnessedHead | undefined> {
    const reply = await this.#call("GET", `/v1/histories/${historyId}/heads/${position}`);
    if (reply.status === 404) return undefined;
    if (reply.status !== 200) throw this.#rejected(reply, "head");
    const witnessed = await this.#witnessedHead(reply.json, historyId);
    if (witnessed.head.position !== position) throw this.#invalid(`asked for position ${position}, got ${witnessed.head.position}`);
    return witnessed;
  }

  async consistency(from: number, to: number): Promise<readonly Uint8Array[]> {
    return Object.freeze(await this.#consistencyProof(from, to));
  }

  async entries(start: number, end: number): Promise<readonly WitnessEntry[]> {
    const reply = await this.#call("GET", `/v1/entries?start=${start}&end=${end}`);
    if (reply.status !== 200) throw this.#rejected(reply, "entries");
    const body = reply.json;
    if (!isRecord(body) || body.start !== start || !Array.isArray(body.entries)) throw this.#invalid("malformed entries page");
    return Object.freeze(body.entries as WitnessEntry[]);
  }
}
