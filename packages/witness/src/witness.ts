/**
 * The witness engine: the log, the Merkle tree, the per-history state, the
 * checkpoint signer and the receipts, behind one async mutex that serializes
 * every append. Transport-agnostic: every operation returns `{ status, body }`
 * with the docs/reference/witness-protocol.md §9.6 wire bodies; `server.ts` puts them on HTTP.
 */
import {
  LATEST_NOTE_VERSION, MerkleTree, buildReceipt, emptyRoot, encodeBase64, entryLeafHash, formatCheckpoint, formatLatestNote, leafHash, openNote, parseCheckpoint, signNote,
} from "@ramex-labs/irontrellis/transparency";
import type { NoteSigner, WitnessEntry, WitnessReceipt } from "@ramex-labs/irontrellis/transparency";
import type { ContentHash, OwnerKeyEpoch } from "@ramex-labs/irontrellis";
import { join } from "node:path";
import {
  acquireServerLock, CHECKPOINTS_FILE, CheckpointFile, DataError, entryBytesOfLine, LOG_FILE, LogFile, readCheckpoints, type ServerLock, type Warn,
} from "./log.ts";
import {
  applyEntry, decideHead, decideKeyEvent, decideRegister, emptyState, headOf, type Decision, type HistoryState, type KeyEventRoute, type WitnessErrorCode, type WitnessState,
} from "./state.ts";

export const WITNESS_PROTOCOL_VERSION = "irontrellis-witness/1";

export type Reply = Readonly<{ status: number; body: Readonly<Record<string, unknown>> }>;
export type Logger = Readonly<{ info: Warn; warn: Warn; error: Warn }>;

export type WitnessOptions = Readonly<{
  dataDir: string;
  origin: string;
  signer: NoteSigner;
  verifierKey: string;
  /** At most one checkpoint per interval (0: one per append). Every reply still carries a checkpoint covering what it references. */
  checkpointIntervalMs?: number;
  maxHistories?: number;
  /** Clock for `receivedAt` and checkpoint times (tests). */
  now?: () => number;
  logger?: Logger;
  /** Take `server.lock` (default true). */
  lock?: boolean;
  /** Override a lock whose holder cannot be judged dead (another host). */
  forceUnlock?: boolean;
}>;

type Published = Readonly<{ size: number; note: string; root: Uint8Array; time: number }>;

const silent: Logger = Object.freeze({ info: () => {}, warn: () => {}, error: () => {} });
const MAX_ENTRIES_PAGE = 1000;
const CACHE_ENTRIES = 2048;

const errorReply = (status: number, code: WitnessErrorCode, message: string, extra: Readonly<Record<string, unknown>> = {}, hint?: string): Reply =>
  Object.freeze({ status, body: Object.freeze({ error: Object.freeze({ code, message, ...(hint === undefined ? {} : { hint }) }), ...extra }) });

/** Serializes async sections (all appends go through one). */
class Mutex {
  #tail: Promise<unknown> = Promise.resolve();
  #pending = 0;
  get pending(): number {
    return this.#pending;
  }
  run<T>(section: () => Promise<T>): Promise<T> {
    this.#pending += 1;
    const result = this.#tail.then(section);
    this.#tail = result.then(() => undefined, () => undefined).finally(() => {
      this.#pending -= 1;
    });
    return result;
  }
  idle(): Promise<void> {
    return this.#tail.then(() => undefined);
  }
}

/**
 * The owner key epochs as the wire carries them: each with its next-key commitment when the witness knows one and
 * (format 2, A-100.1) the owner approval policy as written when the epoch has one. `policyKnown: false` (A-111.3) is
 * stated only for an epoch whose policy the witness does not know; absent, it is known. A history without a policy gets
 * exactly the older shape, and the protocol stays `irontrellis-witness/1`.
 */
export const epochsWire = (epochs: readonly OwnerKeyEpoch[], facts: readonly Readonly<{ policyKnown: boolean }>[] = []): unknown[] =>
  epochs.map((epoch, index) => ({
    fromPosition: epoch.fromPosition, keys: epoch.keys.map((key) => ({ keyId: key.keyId, scheme: key.scheme, credential: key.credential })),
    ...(epoch.nextKeyDigests === undefined ? {} : { nextKeyDigests: [...epoch.nextKeyDigests] }),
    ...(epoch.policy === undefined ? {} : { policy: epoch.policy }),
    ...(facts[index]?.policyKnown === false ? { policyKnown: false } : {}),
  }));

export class Witness {
  readonly origin: string;
  readonly verifierKey: string;
  readonly dataDir: string;
  readonly #signer: NoteSigner;
  readonly #tree = new MerkleTree();
  readonly #state: WitnessState = emptyState();
  readonly #mutex = new Mutex();
  readonly #cache = new Map<number, WitnessEntry>();
  readonly #now: () => number;
  readonly #logger: Logger;
  readonly #interval: number;
  readonly #maxHistories: number | undefined;
  #log!: LogFile;
  #checkpoints!: CheckpointFile;
  #lock: ServerLock | undefined;
  #published!: Published;
  #issuing: Promise<Published> | undefined;
  #failure: Error | undefined;
  #closing = false;
  #closed = false;
  readonly #active = new Set<Promise<unknown>>();
  #appendCount = 0;
  #appendMs = 0;
  #cappedEquivocations = 0;

  private constructor(options: WitnessOptions) {
    // A checkpoint's first line is the origin; the latest notes' first line is their version, so the two must never be equal (docs/reference/witness-protocol.md §9.8).
    if (options.origin === LATEST_NOTE_VERSION) throw new Error(`the witness origin cannot be ${options.origin} (it would make a checkpoint look like a latest note)`);
    this.dataDir = options.dataDir;
    this.origin = options.origin;
    this.verifierKey = options.verifierKey;
    this.#signer = options.signer;
    this.#now = options.now ?? Date.now;
    this.#logger = options.logger ?? silent;
    this.#interval = Math.max(0, options.checkpointIntervalMs ?? 0);
    this.#maxHistories = options.maxHistories;
  }

  /** Takes the lock, replays the log (refusing a corrupt one), checks the last checkpoint and signs a current one. */
  static async open(options: WitnessOptions): Promise<Witness> {
    const witness = new Witness(options);
    if (options.lock !== false) witness.#lock = acquireServerLock(options.dataDir, { force: options.forceUnlock === true, warn: witness.#logger.warn });
    try {
      await witness.#load();
    } catch (error) {
      // Either may not have been opened yet.
      await (witness.#log as LogFile | undefined)?.close().catch(() => undefined);
      await (witness.#checkpoints as CheckpointFile | undefined)?.close().catch(() => undefined);
      witness.#lock?.release();
      throw error;
    }
    return witness;
  }

  async #load(): Promise<void> {
    this.#log = await LogFile.open(join(this.dataDir, LOG_FILE), (record, line, log) => {
      const problem = applyEntry(this.#state, record.entry, record.index, { lookup: (index) => log.read(index).entry });
      if (problem !== null) throw new DataError(problem, LOG_FILE, line.lineNumber);
      this.#tree.append(leafHash(entryBytesOfLine(line, record)));
    }, this.#logger.warn);

    const checkpointsPath = join(this.dataDir, CHECKPOINTS_FILE);
    const records = readCheckpoints(checkpointsPath, this.#logger.warn, true);
    const last = records.at(-1);
    if (last !== undefined) {
      let size: number;
      let root: Uint8Array;
      try {
        const opened = openNote(last.note, [this.verifierKey]);
        const checkpoint = parseCheckpoint(opened.body);
        if (checkpoint.origin !== this.origin) throw new Error(`origin ${JSON.stringify(checkpoint.origin)} is not ${JSON.stringify(this.origin)}`);
        size = checkpoint.size;
        root = checkpoint.root;
      } catch (error) {
        throw new DataError(`the last checkpoint does not verify with this witness's key and origin (${error instanceof Error ? error.message : String(error)}); a new key or origin needs a new data directory`, CHECKPOINTS_FILE, records.length);
      }
      if (size !== last.size) throw new DataError("the recorded size differs from the note", CHECKPOINTS_FILE, records.length);
      if (size > this.#tree.size) {
        throw new DataError(`the witness signed a checkpoint of size ${size} but log.jsonl has only ${this.#tree.size} entries: the log lost acknowledged entries; restore it from a backup`, CHECKPOINTS_FILE, records.length);
      }
      if (encodeBase64(this.#tree.root(size)) !== encodeBase64(root)) {
        throw new DataError(`the checkpoint of size ${size} does not match the root recomputed from log.jsonl: the log was altered`, CHECKPOINTS_FILE, records.length);
      }
      this.#published = Object.freeze({ size, note: last.note, root, time: last.time });
    }
    this.#checkpoints = await CheckpointFile.open(checkpointsPath);
    if (last === undefined || last.size < this.#tree.size) await this.#issue();
    this.#logger.info("witness log replayed", { entries: this.#tree.size, histories: this.#state.histories.size, checkpointSize: this.#published.size });
  }

  // ---------------------------------------------------------------- introspection

  get size(): number {
    return this.#tree.size;
  }

  get checkpoint(): Readonly<{ size: number; note: string; time: number }> {
    return this.#published;
  }

  get failure(): Error | undefined {
    return this.#failure;
  }

  stats(): Readonly<{
    entries: number; histories: number; equivocatingHistories: number; kinds: Readonly<Record<string, number>>; checkpointSize: number; checkpointTime: number;
    appendCount: number; appendSeconds: number; logBytes: number; cappedEquivocations: number;
  }> {
    return {
      entries: this.#tree.size, histories: this.#state.histories.size, equivocatingHistories: this.#state.equivocatingHistories, kinds: { ...this.#state.kinds },
      checkpointSize: this.#published.size, checkpointTime: this.#published.time, appendCount: this.#appendCount, appendSeconds: this.#appendMs / 1000,
      logBytes: this.#log.bytes, cappedEquivocations: this.#cappedEquivocations,
    };
  }

  /** The history a request is about, for per-history rate limits (undefined when not registered). */
  isRegistered(historyId: ContentHash): boolean {
    return this.#state.histories.has(historyId);
  }

  get historyCount(): number {
    return this.#state.histories.size;
  }

  info(software: string): Reply {
    return { status: 200, body: { version: WITNESS_PROTOCOL_VERSION, origin: this.origin, verifierKey: this.verifierKey, software } };
  }

  // ---------------------------------------------------------------- entries, receipts, checkpoints

  /** The entry at `index`, from the cache or re-read from disk and checked against the tree. */
  #entry(index: number): WitnessEntry {
    const cached = this.#cache.get(index);
    if (cached !== undefined) return cached;
    const record = this.#log.read(index);
    if (encodeBase64(entryLeafHash(record.entry)) !== encodeBase64(this.#tree.leaf(index))) {
      throw new DataError("log line changed on disk since it was appended", LOG_FILE, index + 1);
    }
    this.#remember(index, record.entry);
    return record.entry;
  }

  #remember(index: number, entry: WitnessEntry): void {
    this.#cache.set(index, entry);
    if (this.#cache.size > CACHE_ENTRIES) {
      const oldest = this.#cache.keys().next().value;
      if (oldest !== undefined) this.#cache.delete(oldest);
    }
  }

  #receipt(index: number, checkpoint: Published): WitnessReceipt {
    return buildReceipt({
      origin: this.origin, verifierKey: this.verifierKey, entry: this.#entry(index), index, checkpoint: checkpoint.note,
      inclusionProof: this.#tree.inclusionProof(index, checkpoint.size),
    });
  }

  /** Signs and records a checkpoint of the current tree (waiting out the batching interval first). */
  async #issue(): Promise<Published> {
    if (this.#interval > 0 && this.#published !== undefined) {
      const wait = this.#published.time + this.#interval - this.#now();
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
    }
    const size = this.#tree.size;
    const root = size === 0 ? emptyRoot() : this.#tree.root(size);
    const note = signNote(formatCheckpoint(this.origin, size, root), this.#signer);
    const time = this.#now();
    try {
      await this.#checkpoints.append({ note, size, time });
    } catch (error) {
      this.#fail(error);
      throw error;
    }
    this.#published = Object.freeze({ size, note, root, time });
    return this.#published;
  }

  /** A published (signed and recorded) checkpoint whose size is at least `size`. */
  async #covering(size: number): Promise<Published> {
    for (;;) {
      const current = this.#published;
      if (current !== undefined && current.size >= size) return current;
      if (this.#issuing === undefined) {
        const issuing = this.#issue();
        this.#issuing = issuing;
        void issuing.then(() => undefined, () => undefined).finally(() => {
          if (this.#issuing === issuing) this.#issuing = undefined;
        });
      }
      await this.#issuing;
    }
  }

  /**
   * Builds a reply body against one checkpoint that covers every index the
   * body references. `refs` lists those indexes for the current state; the
   * state may grow while we wait for a checkpoint, so it is asked again.
   */
  async #withCheckpoint(refs: () => number[], build: (checkpoint: Published) => Record<string, unknown>): Promise<Record<string, unknown>> {
    for (let attempt = 0; ; attempt += 1) {
      const checkpoint = await this.#covering(Math.max(-1, ...refs()) + 1);
      if (Math.max(-1, ...refs()) < checkpoint.size) return { ...build(checkpoint), checkpoint: checkpoint.note };
      if (attempt > 1000) throw new Error("no checkpoint covers the reply");
    }
  }

  #latestWire(history: HistoryState, checkpoint: Published): unknown {
    const latest = history.latest;
    return latest === undefined ? null : { head: headOf(latest), receipt: this.#receipt(latest.index, checkpoint) };
  }

  /**
   * The signed latest note (docs/reference/witness-protocol.md §9.8): the history's latest head (or none) at the size of the reply's
   * checkpoint, the equivocation count, bound to the client's nonce. The caller's refs include the latest index, so the
   * checkpoint covers it.
   */
  #latestNote(history: HistoryState, checkpoint: Published, nonce: string): string {
    const latest = history.latest;
    return signNote(formatLatestNote({
      origin: this.origin, historyId: history.historyId, nonce, treeSize: checkpoint.size, equivocations: history.equivocations, supersedes: history.supersedes,
      latest: latest === undefined ? null : { position: latest.position, hash: latest.hash, index: latest.index },
    }), this.#signer);
  }

  // ---------------------------------------------------------------- appends

  #fail(error: unknown): void {
    if (this.#failure !== undefined) return;
    this.#failure = error instanceof Error ? error : new Error(String(error));
    this.#logger.error("the witness stopped accepting writes after a storage failure; restart it once the cause is fixed", { error: this.#failure.message });
  }

  #unavailable(): Reply | undefined {
    if (this.#failure !== undefined) return errorReply(503, "INTERNAL", "the witness is not accepting writes (storage failure; see the server log)");
    return undefined;
  }

  async #mutate(kind: "register" | "head" | "key-event", historyIdOf: (decision: Decision) => ContentHash | undefined, decide: (now: number) => Decision, nonce: string | undefined): Promise<Reply> {
    const unavailable = this.#unavailable();
    if (unavailable !== undefined) return unavailable;
    const outcome = await this.#mutex.run(async (): Promise<Readonly<{ decision: Decision; index?: number; first?: number }> | Reply> => {
      if (this.#closed) return errorReply(503, "INTERNAL", "the witness is shutting down");
      if (this.#failure !== undefined) return errorReply(503, "INTERNAL", "the witness is not accepting writes (storage failure; see the server log)");
      const decision = decide(this.#now());
      if (decision.capped === true) this.#cappedEquivocations += 1;
      if (decision.append === undefined) return { decision };
      if (this.#lock !== undefined && !this.#lock.stillHeld()) {
        this.#fail(new Error(`${this.#lock.path} was taken over by another process`));
        return errorReply(503, "INTERNAL", "the witness lost its data directory lock; nothing was written");
      }
      const { entries } = decision.append;
      const first = this.#state.size;
      const records = entries.map((entry, n) => ({ index: first + n, entry }));
      const started = performance.now();
      try {
        // One write and one fsync for the whole decision (a key event with the head it binds, a supersede with both).
        await this.#log.appendAll(records);
      } catch (error) {
        if (error instanceof DataError) return errorReply(400, "INVALID_REQUEST", "the request contains values that cannot be stored exactly");
        this.#fail(error);
        return errorReply(503, "INTERNAL", "the witness could not store the entry; nothing was acknowledged");
      }
      for (const { index, entry } of records) {
        this.#remember(index, entry);
        const problem = applyEntry(this.#state, entry, index, { lookup: (i) => this.#entry(i) });
        if (problem !== null) {
          // The decision and the replay rules disagree: never keep serving from a state the log cannot reproduce.
          this.#fail(new Error(`internal rule mismatch at leaf ${index}: ${problem}`));
          return errorReply(500, "INTERNAL", "internal error");
        }
        this.#tree.append(entryLeafHash(entry));
        this.#appendCount += 1;
      }
      this.#appendMs += performance.now() - started;
      return { decision, index: first + entries.length - 1, first };
    });
    if ("status" in outcome && "body" in outcome) return outcome;
    const { decision, index, first } = outcome as Readonly<{ decision: Decision; index?: number; first?: number }>;
    return this.#respond(kind, decision, historyIdOf(decision), index, nonce, first);
  }

  async #respond(kind: "register" | "head" | "key-event", decision: Decision, historyId: ContentHash | undefined, appended: number | undefined, nonce: string | undefined, first?: number): Promise<Reply> {
    const receiptIndex = decision.receipt === "appended" ? appended : decision.receipt;
    const supersededIndex = decision.superseded === "first" ? first : decision.superseded;
    const history = historyId === undefined ? undefined : this.#state.histories.get(historyId);
    const refs = (): number[] => {
      const out: number[] = [];
      if (receiptIndex !== undefined) out.push(receiptIndex);
      if (supersededIndex !== undefined) out.push(supersededIndex);
      if ((decision.latest === true || nonce !== undefined) && history?.latest !== undefined) out.push(history.latest.index);
      return out;
    };
    const needsLog = receiptIndex !== undefined || decision.latest === true || decision.epochs === true;
    if (decision.error !== undefined && !needsLog) return errorReply(decision.status, decision.error.code, decision.error.message, {}, decision.error.hint);
    const body = await this.#withCheckpoint(refs, (checkpoint) => {
      const out: Record<string, unknown> = {};
      if (decision.error !== undefined) out.error = { code: decision.error.code, message: decision.error.message, ...(decision.error.hint === undefined ? {} : { hint: decision.error.hint }) };
      if (kind === "register" && decision.historyId !== undefined) out.historyId = decision.historyId;
      if (kind === "head" && decision.result !== undefined) out.status = decision.result;
      if (receiptIndex !== undefined) out.receipt = this.#receipt(receiptIndex, checkpoint);
      if (supersededIndex !== undefined) out.superseded = this.#receipt(supersededIndex, checkpoint);
      if (decision.latest === true && history !== undefined) out.latest = this.#latestWire(history, checkpoint);
      if (decision.epochs === true && history !== undefined) out.epochs = epochsWire(history.epochs, history.epochFacts);
      if (nonce !== undefined && history !== undefined) out.latestNote = this.#latestNote(history, checkpoint, nonce);
      return out;
    });
    return { status: decision.status, body };
  }

  /** Runs an operation unless the witness is closing, and lets `close()` wait for it. */
  #track(operation: () => Promise<Reply>): Promise<Reply> {
    if (this.#closing || this.#closed) return Promise.resolve(errorReply(503, "INTERNAL", "the witness is shutting down"));
    const promise = operation();
    this.#active.add(promise);
    void promise.then(() => undefined, () => undefined).finally(() => this.#active.delete(promise));
    return promise;
  }

  #sync(operation: () => Reply): Reply {
    if (this.#closing || this.#closed) return errorReply(503, "INTERNAL", "the witness is shutting down");
    return operation();
  }

  /**
   * `POST /v1/histories`. With `nonce` (checked by the caller: `isValidNonce`), every reply that carries log state also
   * carries the signed `latestNote` (docs/reference/witness-protocol.md §9.8); the same for the other history routes below.
   */
  register(body: unknown, nonce?: string): Promise<Reply> {
    return this.#track(() => this.#mutate("register", (decision) => decision.historyId, (now) =>
      decideRegister(this.#state, body, { now, lookup: (i) => this.#entry(i), ...(this.#maxHistories === undefined ? {} : { maxHistories: this.#maxHistories }) }), nonce));
  }

  /** `POST /v1/histories/:id/heads`. */
  submitHead(historyId: ContentHash, body: unknown, nonce?: string): Promise<Reply> {
    return this.#track(() => this.#mutate("head", () => historyId, (now) => decideHead(this.#state, historyId, body, { now, lookup: (i) => this.#entry(i) }), nonce));
  }

  /**
   * `POST /v1/histories/:id/key-events` (docs/reference/witness-protocol.md §9.2); with `route: "admin"` the body is a key-event
   * bundle (`POST /v1/admin/key-events`, `import-key-events`): the same checks, the bundle's `historyId` naming the history.
   */
  keyEvent(historyId: ContentHash, body: unknown, nonce?: string, route: KeyEventRoute = "key-events"): Promise<Reply> {
    return this.#track(() => this.#mutate("key-event", () => historyId,
      (now) => decideKeyEvent(this.#state, historyId, body, { now, lookup: (i) => this.#entry(i) }, route), nonce));
  }

  /** A key-event bundle delivered out of band (admin route or offline import): its history id is read from the bundle. */
  importBundle(bundle: unknown, nonce?: string): Promise<Reply> {
    const historyId = bundle !== null && typeof bundle === "object" && !Array.isArray(bundle) ? (bundle as { historyId?: unknown }).historyId : undefined;
    if (typeof historyId !== "string" || !/^0x[0-9a-f]{64}$/.test(historyId)) {
      return Promise.resolve(errorReply(400, "INVALID_REQUEST", "not a key-event bundle: historyId must be a lowercase 0x-prefixed sha256 hash"));
    }
    return this.keyEvent(historyId as ContentHash, bundle, nonce, "admin");
  }

  // ---------------------------------------------------------------- reads

  /** `GET /v1/histories/:id`. */
  history(historyId: ContentHash, nonce?: string): Promise<Reply> {
    return this.#track(() => this.#history(historyId, nonce));
  }

  async #history(historyId: ContentHash, nonce: string | undefined): Promise<Reply> {
    const history = this.#state.histories.get(historyId);
    if (history === undefined) return errorReply(404, "NOT_REGISTERED", `history ${historyId} is not registered with this witness`);
    const body = await this.#withCheckpoint(
      () => [...(history.latest === undefined ? [] : [history.latest.index]), ...(history.lastEquivocationIndex === undefined ? [] : [history.lastEquivocationIndex]),
        ...(history.lastSupersedeIndex === undefined ? [] : [history.lastSupersedeIndex])],
      (checkpoint) => ({
        historyId, domain: history.domain, equivocations: history.equivocations, supersedes: history.supersedes, epochs: epochsWire(history.epochs, history.epochFacts), latest: this.#latestWire(history, checkpoint),
        ...(history.lastEquivocationIndex === undefined ? {} : { lastEquivocation: this.#receipt(history.lastEquivocationIndex, checkpoint) }),
        ...(history.lastSupersedeIndex === undefined ? {} : { lastSupersede: this.#receipt(history.lastSupersedeIndex, checkpoint) }),
        ...(nonce === undefined ? {} : { latestNote: this.#latestNote(history, checkpoint, nonce) }),
      }),
    );
    return { status: 200, body };
  }

  /** `GET /v1/histories/:id/heads/:position`. */
  headAt(historyId: ContentHash, position: number): Promise<Reply> {
    return this.#track(() => this.#headAt(historyId, position));
  }

  async #headAt(historyId: ContentHash, position: number): Promise<Reply> {
    const history = this.#state.histories.get(historyId);
    if (history === undefined) return errorReply(404, "NOT_REGISTERED", `history ${historyId} is not registered with this witness`);
    const held = history.heads.get(position);
    if (held === undefined) return errorReply(404, "NOT_FOUND", `the witness holds no head at position ${position} for this history`);
    const body = await this.#withCheckpoint(() => [held.index], (checkpoint) => ({ head: headOf(held), receipt: this.#receipt(held.index, checkpoint) }));
    return { status: 200, body };
  }

  /** `GET /v1/proofs/inclusion?index=&size=` (size defaults to the latest checkpoint's). */
  inclusion(index: number, size: number | undefined): Reply {
    return this.#sync(() => this.#inclusion(index, size));
  }

  #inclusion(index: number, size: number | undefined): Reply {
    const treeSize = size ?? this.#published.size;
    if (treeSize > this.#tree.size) return errorReply(400, "INVALID_REQUEST", `size ${treeSize} exceeds the log size ${this.#tree.size}`);
    if (index >= treeSize) return errorReply(400, "INVALID_REQUEST", `index ${index} is not below size ${treeSize}`);
    return { status: 200, body: { index, size: treeSize, proof: this.#tree.inclusionProof(index, treeSize).map(encodeBase64) } };
  }

  /** `GET /v1/proofs/consistency?from=&to=` (to defaults to the latest checkpoint's size). */
  consistency(from: number, to: number | undefined): Reply {
    return this.#sync(() => this.#consistency(from, to));
  }

  #consistency(from: number, to: number | undefined): Reply {
    const toSize = to ?? this.#published.size;
    if (toSize > this.#tree.size) return errorReply(400, "INVALID_REQUEST", `to ${toSize} exceeds the log size ${this.#tree.size}`);
    if (from > toSize) return errorReply(400, "INVALID_REQUEST", `from ${from} exceeds to ${toSize}`);
    return { status: 200, body: { from, to: toSize, proof: this.#tree.consistencyProof(from, toSize).map(encodeBase64) } };
  }

  /** `GET /v1/entries?start=&end=` (end exclusive; at most 1000 per page; clamped to the log size). */
  entries(start: number, end: number | undefined): Reply {
    return this.#sync(() => this.#entries(start, end));
  }

  #entries(start: number, end: number | undefined): Reply {
    if (start > this.#tree.size) return errorReply(400, "INVALID_REQUEST", `start ${start} exceeds the log size ${this.#tree.size}`);
    const requested = end ?? start + MAX_ENTRIES_PAGE;
    if (requested < start) return errorReply(400, "INVALID_REQUEST", "end must not be below start");
    const stop = Math.min(requested, start + MAX_ENTRIES_PAGE, this.#tree.size);
    const entries: WitnessEntry[] = [];
    for (let index = start; index < stop; index += 1) entries.push(this.#entry(index));
    return { status: 200, body: { start, entries } };
  }

  // ---------------------------------------------------------------- shutdown

  /** Stops accepting writes, lets queued appends and checkpoints finish, closes the files and releases the lock. */
  async close(): Promise<void> {
    if (this.#closing) return;
    // Appends already queued finish (and are answered); new ones get 503.
    this.#closing = true;
    while (this.#active.size > 0) await Promise.allSettled([...this.#active]);
    await this.#mutex.idle();
    this.#closed = true;
    if (this.#issuing !== undefined) await this.#issuing.catch(() => undefined);
    await this.#log.close();
    await this.#checkpoints.close();
    this.#lock?.release();
  }

  /** Appends waiting for or holding the mutex. */
  get inFlight(): number {
    return this.#mutex.pending;
  }
}
