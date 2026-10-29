/**
 * Migration to format 2 (SPEC-IRONTRELLIS-CORE-v2 §16.2, the eight steps; addendum A-17) from a legacy
 * (`continuity-event/0.2`) or a format-1 (`irontrellis-event/1`) source. The target history's genesis carries
 * `migratedFrom` (the source's final head in its own algorithm, its last store-line `recordHash`, its genesis and
 * `versions` as written) and its events 1..n transcribe the source events 1..n (same ids, types, timestamps; step 2:
 * Amount markers → strings on the exhaustive path list, new `/2` control signatures with a format-1 source's `/1`
 * authorization kept as `sourceControlAuthorization`, `declarationAuthorization: null` on prefix declarations, legacy
 * sessions gain `credentialScheme`, everything runtime-signed verbatim), so target positions equal source positions.
 * Replay validates the prefix against the source's shadow (step 3, `state.ts openShadow`; the reader inverts the
 * transcription with `transcription.ts invertTranscription`). The source file is never modified: it stays the archive
 * (and a ZK-provable file); after a completed migration it is fenced by `<source>.migrated` (step 6) and every later
 * open of it is read only (`FORMAT_READ_ONLY {reason: "MIGRATED", target}`).
 *
 * Idempotent resume (step 7): the plan `<target>.migration-plan.json` (`irontrellis-migration-plan/1`, atomic) is
 * written first; a re-run with the same plan verifies the outputs that exist (target file, pin, snapshot, fence) and
 * resumes at the first missing one; `migrationStatus(plan)` reports the phase from the actual files. The control
 * signatures are deterministic (Ed25519; RFC 6979 for secp256k1), so a re-run transcribes byte-identical events and a
 * partial or corrupt target is simply rewritten. Capacity: the whole target is dry-run on a private format-2 state
 * before a byte is written, so a source whose transcription would hit the format-2 reserve or a cap is refused up front
 * (`MIGRATION_UNSUPPORTED {reason: "CAPACITY"}`). Plan-time refusals of a source that stays read only: a rotation or witness
 * binding (`SOURCE_KEY_ROTATED`, `SOURCE_WITNESS_BOUND`, A-63.1) and a key failing the §3.3 declaration test (`SOURCE_KEY_INVALID`, A-79.1).
 *
 * Pre-rotation and key custody are as the format-1 migration: by default the target genesis commits the new owner key
 * to a next key (`<target>.owner-next-key.json`, a `nextSigner`, a `nextKeyReference` or a `nextPublicKey`);
 * `nextKey: false` migrates without one.
 */
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { FORMAT2_VERSIONS, LEGACY_FORMAT, PROJECTION_VERSION, TRELLIS2_FORMAT, TRELLIS_FORMAT } from "./events.ts";
import { applyEvent, createReplayState } from "./replay.ts";
import {
  createNextOwnerKeyFile, createOwnerKeyFile, loadNextOwnerKeyFile, loadOwnerKeyFile, nextOwnerKeyPathFor, ownerKeyPathFor, readKeyReferenceFile, signControlEvent, writeKeyReferenceFile,
  type Signer,
} from "./signer.ts";
import { OWNER_KEY_REF_VERSION, OWNER_NEXT_KEY_REF_VERSION, parseKeyReference, parsePublicKey, publicKeySigner, referenceSigner, withReferenceVersion, type OwnerKeyReference } from "./custody/reference.ts";
import { ownerKeyDigest, verifyHeadAttestationFacts } from "./owner-keys.ts";
import { suiteFor } from "./crypto/suites.ts";
import { ed25519KeyCheck } from "./crypto/ed25519-point.ts";
import { EngineError } from "./errors.ts";
import { canonicalPath, createHistoryStore, markerTargetOf, markerTargetPath, migratedMarkerPathFor, MIGRATED_MARKER_VERSION, openHistoryStore, readMigratedMarker, type HistoryStore, type MigratedMarker, type PinnedHead } from "./store.ts";
import { readSnapshotBase } from "./snapshot.ts";
import { rootAt, stateRecordsOf } from "./state-records.ts";
import { canonicalEncode } from "./canonical.ts";
import { IronTrellisError, requireCondition, time } from "./input.ts";
import { capturedReference, nextFreeOwnerKeyId, POLICY_VERSIONS, signerFailure, translate } from "./owner.ts";
import { transcribeData } from "./transcription.ts";
import { replaceFileSync, syncDirectorySync } from "./platform.ts";
import { closeSync, openSync, writeSync, fsyncSync } from "node:fs";
import { dirname } from "node:path";
import { CONTROL_EVENT_TYPES, type CanonicalEvent, type ContentHash, type HistoryFormat, type HistoryHead, type ReplayState } from "./types.ts";

export const MIGRATION_PLAN_VERSION = "irontrellis-migration-plan/1";
/** TEST ONLY (builder test T4): a hook called at `plan-written`, `target-written` and `before-fence`; a test's worker process kills itself there. */
let cutHook: ((name: string) => void) | undefined;
export const setMigrationCutHookForTests = (hook: ((name: string) => void) | undefined): void => { cutHook = hook; };
const cut = (name: string): void => { cutHook?.(name); };
export const migrationPlanPathFor = (target: string): string => `${target}.migration-plan.json`;

export type MigrationOptions = Readonly<{
  /** The legacy (`continuity-event/0.2`) or format-1 (`irontrellis-event/1`) history file. */
  source: string;
  /** The format-2 history file to create. */
  target: string;
  /** The plan file; default `<target>.migration-plan.json`. */
  plan?: string;
  /** Owner key for the target's control events; default: a fresh `<target>.owner-key.json`. */
  signer?: Signer;
  /** The target's owner key is held by the signer this reference names (written to `<target>.owner-key.json`, no secret). Excludes `signer`. */
  ownerKeyReference?: OwnerKeyReference;
  now: () => number;
  /**
   * Migrate a source whose pinned head is missing or does not match the file (SPEC §16.2 step 1, the format-1 rule): a legacy
   * file is unsigned and most Continuity-written histories have no pin; a format-1 file normally has one. The caller
   * opts in explicitly, having checked the source by other means.
   */
  acceptUnpinnedSource?: boolean;
  /** Adopt an owner key file already at `<target>.owner-key.json` (and a next-key file) instead of refusing with KEY_EXISTS. */
  reuseExistingKey?: boolean;
  /** Pre-rotation (default true): the target genesis commits the owner key to a next key. */
  nextKey?: boolean;
  nextSigner?: Signer;
  nextKeyReference?: OwnerKeyReference;
  nextPublicKey?: string;
  /** Addendum A-17.2: genesis fields the migration options may add (absent otherwise). */
  capacity?: Readonly<{ maxEvents: number | null; maxStateRecords?: number | null }>;
  checkpointPolicy?: Readonly<{ everyEvents: number | null }>;
  projection?: typeof PROJECTION_VERSION | null;
  /** A-179.1: the target genesis's session time horizon (≥ 1, or `null`); sessions surviving the prefix cannot write until the first time-advancing owner event after it. */
  sessionTimeHorizonMs?: number | null;
  /**
   * A-40.3: the migration id (`0x` + 64 hex) to write into a NEW plan; default 32 fresh random bytes. For reproducible
   * test twins only (the regenerated suite pins migration roots, G2.5); a re-run always takes the id from the plan.
   */
  migrationId?: ContentHash;
}>;
export type MigrationResult = Readonly<{
  sourceHead: HistoryHead; targetHead: HistoryHead; eventCount: number; ownerKeyId: string;
  /** A-41.3: the target's `historyId` (`recordHash(0)`), to pin readers to it (hook and gateway configs). */
  historyId: ContentHash;
  /** SPEC §7.1: `rootAt(targetHead.position)`. */
  stateRoot: ContentHash;
  phase: "FENCED"; target: string; plan: string;
  /** A-52.2: the transcribed sessions without `expiresAt` — valid for the prefix only; post-prefix signing needs a fresh finite-expiry session. */
  sessionsWithoutExpiry: readonly string[];
  nextKeyDigests?: readonly ContentHash[]; nextKeyId?: string; nextKeyFile?: string;
}>;
export type MigrationPlan = Readonly<{
  version: typeof MIGRATION_PLAN_VERSION; source: string; sourceFormat: HistoryFormat; sourceHead: HistoryHead; target: string;
  ownerKey: Readonly<{ keyId: string; scheme: string; credential: string }>; createdAt: number;
  /** A-40.3: 32 random bytes (`0x` + 64 hex) drawn at plan time and carried in the target's `migratedFrom.migrationId`. */
  migrationId: ContentHash;
}>;
export type MigrationPhase = "PLANNED" | "WRITTEN" | "PINNED" | "FENCED";
export type MigrationStatus = Readonly<{
  phase: MigrationPhase;
  /** Whether every output present verifies (the target replays with the plan's `migratedFrom`, the pin is attested by the plan's owner key, the fence names the source and target heads). */
  verified: boolean;
  plan: string; source: string; target: string; sourceHead: HistoryHead;
  /** Which outputs exist. */
  outputs: Readonly<{ target: boolean; pin: boolean; snapshot: boolean; fence: boolean }>;
  /** What failed verification, when `verified` is false. */
  problems: readonly string[];
}>;

const unsupported = (reason: string, detail?: Readonly<Record<string, unknown>>): IronTrellisError => new IronTrellisError("MIGRATION_UNSUPPORTED", false, reason, detail);
const isSigner = (value: unknown): value is Signer => value !== null && typeof value === "object" && typeof (value as Signer).keyId === "string" &&
  typeof (value as Signer).credential === "string" && typeof (value as Signer).scheme === "string" && typeof (value as Signer).signHash === "function";

/** The record hash of the source's last line, read from the file itself (the source store's own chain field; SPEC §16.2 step 4, A-17.4). */
const lastRecordHash = (path: string): ContentHash => {
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line.length > 0);
  const last: unknown = JSON.parse(lines[lines.length - 1] ?? "null");
  const hash = (last as { recordHash?: unknown } | null)?.recordHash;
  requireCondition(typeof hash === "string" && /^0x[0-9a-f]{64}$/.test(hash), "INVALID_HISTORY");
  return hash as ContentHash;
};

/** Write-to-temp + rename + directory sync (the plan and the fence are written atomically, SPEC §16.2 steps 1 and 6). */
const writeAtomically = (path: string, text: string): void => {
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  const fd = openSync(temporary, "wx", 0o600);
  try { writeSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
  try { replaceFileSync(temporary, path); } catch (error) { try { unlinkSync(temporary); } catch { /* best effort */ } throw error; }
  syncDirectorySync(dirname(path));
};
const sameHead = (a: HistoryHead, b: HistoryHead): boolean => a.hash === b.hash && a.position === b.position && a.canonicalTime === b.canonicalTime;

/**
 * SPEC §16.2 step 4 and A-17.2: the target genesis. Rewritten: `domain` (version "2"), `versions`, `policyVersion`
 * (the source format's local-owner literal → `irontrellis-local-owner/2`; another literal is carried verbatim),
 * `ownerKeys`, `migratedFrom`; options-only: `nextKeyDigests`, `capacity`, `checkpointPolicy`, `projection`, `sessionTimeHorizonMs`; copied as
 * written: `adapterPolicyHash`, `canonicalLineageId`, `rootRecognitionPolicy`, `globalPolicySourceId`, `timeSource`,
 * `finality`. The source genesis stays as written in `migratedFrom.genesis`.
 */
const migratedGenesis = (source: ReplayState, signer: Signer, recordHash: ContentHash, next: Signer | undefined, options: MigrationOptions, provenance: Provenance): CanonicalEvent => {
  const g = source.genesis, original = source.events[0]!;
  return Object.freeze({
    id: original.id, type: "DEPLOYMENT_INITIALIZED", timestamp: original.timestamp,
    data: {
      domain: { protocol: "irontrellis", version: "2", deploymentId: (g.domain as { deploymentId: string }).deploymentId },
      adapterPolicyHash: g.adapterPolicyHash, canonicalLineageId: g.canonicalLineageId,
      versions: { ...FORMAT2_VERSIONS, signatureScheme: source.signatureScheme },
      // A-52.4 / A-17.2 (g25 X-6 reading (i)): the policy literal is always rewritten to the format-2 local owner's.
      policyVersion: POLICY_VERSIONS[TRELLIS2_FORMAT],
      rootRecognitionPolicy: g.rootRecognitionPolicy, globalPolicySourceId: g.globalPolicySourceId, timeSource: g.timeSource, finality: g.finality,
      ownerKeys: [{ keyId: signer.keyId, scheme: signer.scheme, credential: signer.credential }],
      ...(next === undefined ? {} : { nextKeyDigests: [ownerKeyDigest(next)] }),
      ...(options.capacity === undefined ? {} : { capacity: { maxEvents: options.capacity.maxEvents, ...(options.capacity.maxStateRecords === undefined ? {} : { maxStateRecords: options.capacity.maxStateRecords }) } }),
      ...(options.checkpointPolicy === undefined ? {} : { checkpointPolicy: { everyEvents: options.checkpointPolicy.everyEvents } }),
      ...(options.projection === undefined ? {} : { projection: options.projection }),
      ...(options.sessionTimeHorizonMs === undefined ? {} : { sessionTimeHorizonMs: options.sessionTimeHorizonMs }),
      migratedFrom: {
        format: source.format, historyHash: source.head.hash, position: source.head.position, recordHash,
        genesis: g, genesisEventId: original.id, genesisTimestamp: original.timestamp, versions: g.versions,
        // A-40.2–3: the source pin's attestation of the migrated head (format 1; null for legacy or an unpinned source) and the plan's random id.
        sourceAttestation: provenance.sourceAttestation, migrationId: provenance.migrationId,
      },
    },
  });
};

/** A-40.2–3: the provenance fields of `migratedFrom`. */
type Provenance = Readonly<{ sourceAttestation: Readonly<Record<string, unknown>> | null; migrationId: ContentHash }>;
/** Step 2: the whole target, dry-run on a private format-2 state (capacity included) before a byte is written; deterministic for a given owner key and plan. */
async function transcribe(source: ReplayState, signer: Signer, recordHash: ContentHash, next: Signer | undefined, options: MigrationOptions, provenance: Provenance): Promise<CanonicalEvent[]> {
  const trial = createReplayState(TRELLIS2_FORMAT);
  const events: CanonicalEvent[] = [migratedGenesis(source, signer, recordHash, next, options, provenance)];
  const applied = applyEvent(trial, events[0]!);
  if (!applied.ok) throw unsupported(`genesis: ${applied.code}: ${applied.reason}`, { reason: "GENESIS", code: applied.code });
  for (let position = 1; position < source.events.length; position += 1) {
    const original = source.events[position]!;
    let data: Readonly<Record<string, unknown>>;
    try { data = transcribeData(original, source.format, source.signatureScheme); } catch (error) {
      if (error instanceof EngineError && error.code === "MIGRATION_UNSUPPORTED") throw new IronTrellisError("MIGRATION_UNSUPPORTED", false, `event ${position} (${original.type}): ${error.message}`, { ...(error.detail as object), position });
      throw error;
    }
    let event: CanonicalEvent = Object.freeze({ id: original.id, type: original.type, timestamp: original.timestamp, data: Object.freeze(data) });
    if (CONTROL_EVENT_TYPES.has(event.type)) {
      try { event = await signControlEvent(signer, event, trial.genesis.domain, trial.head, trial.hashAlgorithm); } catch (error) { throw signerFailure(error); }
    }
    const result = applyEvent(trial, event);
    if (!result.ok) {
      const capacity = result.code === "CAPACITY_EXCEEDED" || result.code === "CAPACITY_RESERVED" || result.code === "CAPACITY_CONTROL_ONLY";
      throw unsupported(`event ${position} (${original.type}) cannot be re-recorded under format 2: ${result.code}: ${result.reason}`, { reason: capacity ? "CAPACITY" : "TRANSITION", code: result.code, position });
    }
    events.push(event);
  }
  // A-52.3: every source-derived state record must satisfy the §3.1 canonical limits (4,096 list members, 256 keys, 16 MiB);
  // a record that cannot is refused before the target is published — never truncated.
  // (The replay's fast record encoder does not check the limits; the validating encoder does.)
  assertSourceStateLimits(stateRecordsOf(trial));
  return events;
}
/** A-52.3: `MIGRATION_UNSUPPORTED {reason: SOURCE_STATE_LIMIT, kind, key}` for the first record over the §3.1 limits (exported for the unit test). */
export function assertSourceStateLimits(records: Iterable<Readonly<{ kind: string; key: string; record: unknown }>>): void {
  for (const entry of records) {
    try { canonicalEncode(entry.record); } catch (error) {
      throw unsupported(`the source-derived state record (${entry.kind}, ${entry.key}) exceeds the §3.1 canonical limits: ${error instanceof Error ? error.message : String(error)}`, { reason: "SOURCE_STATE_LIMIT", kind: entry.kind, key: entry.key });
    }
  }
}

const readPlan = (path: string): MigrationPlan | undefined => {
  if (!existsSync(path)) return undefined;
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(path, "utf8")); } catch { throw new IronTrellisError("INVALID_INPUT", false, `the migration plan ${path} is not JSON`); }
  const p = parsed as Partial<MigrationPlan> | null;
  if (p === null || typeof p !== "object" || p.version !== MIGRATION_PLAN_VERSION || typeof p.source !== "string" || typeof p.target !== "string" || typeof p.sourceFormat !== "string" ||
      p.sourceHead === undefined || p.ownerKey === undefined || typeof p.createdAt !== "number" || typeof p.migrationId !== "string" || !/^0x[0-9a-f]{64}$/.test(p.migrationId)) throw new IronTrellisError("INVALID_INPUT", false, `the migration plan ${path} is not an ${MIGRATION_PLAN_VERSION} record`);
  return p as MigrationPlan;
};
const samePlan = (a: MigrationPlan, b: Omit<MigrationPlan, "createdAt" | "migrationId">): boolean =>
  a.source === b.source && a.target === b.target && a.sourceFormat === b.sourceFormat && sameHead(a.sourceHead, b.sourceHead) &&
  a.ownerKey.keyId === b.ownerKey.keyId && a.ownerKey.scheme === b.ownerKey.scheme && a.ownerKey.credential.toLowerCase() === b.ownerKey.credential.toLowerCase();

/** Opens the source read only (full replay; a fenced source still reads) and checks it is a migratable format (step 1). */
/** A-63.1 for a source whose witness gate refuses the read: inspect it; a witness binding → SOURCE_WITNESS_BOUND, otherwise returns. */
function witnessBoundRefusal(path: string): void {
  let events: readonly CanonicalEvent[];
  try { events = openHistoryStore(path, { trust: "FULL_REPLAY", allowUnpinned: true, inspect: true }).state().events; } catch { return; }
  const bound = events.findIndex((e) => e.type === "WITNESSES_BOUND" || e.type === "WITNESSES_UNBOUND");
  if (bound >= 0) throw unsupported(`the source ${path} bound or unbound witnesses (position ${bound}); format-1 sources with a witness binding cannot be migrated in this format (A-63) — it stays readable and verifiable read only`, { reason: "SOURCE_WITNESS_BOUND", position: bound });
}
function openSource(path: string): HistoryStore {
  let store: HistoryStore;
  // `allowUnpinned`: a missing or unattested pin is judged below (`acceptUnpinnedSource`, the format-1 rule); a file behind its pin still fails the open.
  try { store = openHistoryStore(path, { trust: "FULL_REPLAY", allowUnpinned: true }); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  requireCondition(store.format !== undefined, "READ_UNAVAILABLE");
  if (store.format === TRELLIS2_FORMAT) throw unsupported(`the source ${path} is already a format-2 history`, { reason: "SOURCE_FORMAT_2" });
  return store;
}

/**
 * A-79.1: every owner, session and counterparty Ed25519 key of the source passes the §3.3 declaration test (A-32.2), so a
 * migrated prefix never carries a key the format-2 replay refuses. Otherwise the source stays readable read only, where
 * `verify` reports the key (A-32.3).
 */
function sourceKeyRefusal(path: string, source: ReplayState): void {
  const test = (role: string, id: string, credential: string, position: number): void => {
    const check = ed25519KeyCheck(Buffer.from(credential.replace(/^0x/, ""), "hex"));
    if (check !== "OK") throw unsupported(`the source ${path} declares ${role} key ${id} (position ${position}), which fails the format-2 key declaration test (${check}; A-32.2); such a source cannot be migrated (A-79) — it stays readable and verifiable read only`, { reason: "SOURCE_KEY_INVALID", role, id, position, check });
  };
  for (const epoch of source.ownerKeyEpochs ?? []) for (const key of epoch.keys) if (key.scheme === "ed25519") test("owner", key.keyId, key.credential, epoch.fromPosition);
  for (const session of source.runtimeSessions.values()) if (session.credentialScheme === "ed25519") test("session", session.id, session.credentialAddressKey, session.admissionEventPosition);
  for (const counterparty of source.counterparties.values()) {
    for (const key of counterparty.keys as readonly Readonly<{ keyId: string; credential: string }>[]) test("counterparty", `${String(counterparty.counterpartyId)}/${key.keyId}`, key.credential, counterparty.position as number);
  }
}

export async function migrateHistory(options: MigrationOptions): Promise<MigrationResult> {
  requireCondition(options !== null && typeof options === "object" && typeof options.source === "string" && typeof options.target === "string" && typeof options.now === "function");
  time(options.now());
  for (const flag of ["acceptUnpinnedSource", "reuseExistingKey", "nextKey"] as const) requireCondition(options[flag] === undefined || typeof options[flag] === "boolean");
  requireCondition(options.plan === undefined || (typeof options.plan === "string" && options.plan.length > 0));
  requireCondition(options.nextSigner === undefined || isSigner(options.nextSigner));
  requireCondition(options.projection === undefined || options.projection === null || options.projection === PROJECTION_VERSION);
  if (options.capacity !== undefined) {
    requireCondition(options.capacity !== null && typeof options.capacity === "object" && (options.capacity.maxEvents === null || time(options.capacity.maxEvents) > 0));
    requireCondition(options.capacity.maxStateRecords === undefined || options.capacity.maxStateRecords === null || time(options.capacity.maxStateRecords) > 0);
  }
  if (options.checkpointPolicy !== undefined) requireCondition(options.checkpointPolicy !== null && typeof options.checkpointPolicy === "object" && (options.checkpointPolicy.everyEvents === null || time(options.checkpointPolicy.everyEvents) >= 1));
  requireCondition(options.sessionTimeHorizonMs === undefined || options.sessionTimeHorizonMs === null || time(options.sessionTimeHorizonMs) >= 1);
  // A-184.1: the target is canonicalised once (symlinks resolved), so the plan, HISTORY_EXISTS, SOURCE_FENCED and a re-run
  // naming it by another path compare the same string; the plan keeps absolute paths.
  const target = canonicalPath(options.target), planPath = resolve(options.plan ?? migrationPlanPathFor(target));
  const existingPlan = readPlan(planPath);
  // ---- step 1: the source, its pin, the owner key, the plan
  const sourceStore = openSource(options.source);
  const sourcePath = sourceStore.path;
  let source: ReplayState;
  try { source = sourceStore.state(); } catch (error) {
    // A-63.1: a witness-bound format-1 source cannot be read before a witness check; it is refused at plan time anyway,
    // so the refusal is decided on an inspect-mode read (no witness gate, nothing written) instead of a witness error.
    if (error instanceof EngineError && error.code === "WITNESS_UNAVAILABLE") witnessBoundRefusal(sourcePath);
    translate(error, "READ_UNAVAILABLE");
  }
  if (source.format === TRELLIS_FORMAT && source.genesis.migratedFrom !== undefined) {
    throw unsupported(`the source ${sourcePath} was itself migrated from a legacy history (migratedFrom); a second shadow level is not supported — it stays readable and verifiable read only (DECISIONS call 13)`, { reason: "SOURCE_ALREADY_MIGRATED" });
  }
  // A-63.1: a format-1 source with an owner-key rotation or a witness binding is not migratable in this format (plan time).
  if (source.format === TRELLIS_FORMAT) {
    const rotated = source.events.findIndex((e) => e.type === "OWNER_KEYS_ROTATED");
    if (rotated >= 0) throw unsupported(`the source ${sourcePath} rotated its owner keys (position ${rotated}); format-1 sources with a rotation cannot be migrated in this format (A-63) — it stays readable and verifiable read only`, { reason: "SOURCE_KEY_ROTATED", position: rotated });
    const bound = source.events.findIndex((e) => e.type === "WITNESSES_BOUND" || e.type === "WITNESSES_UNBOUND");
    if (bound >= 0) throw unsupported(`the source ${sourcePath} bound or unbound witnesses (position ${bound}); format-1 sources with a witness binding cannot be migrated in this format (A-63) — it stays readable and verifiable read only`, { reason: "SOURCE_WITNESS_BOUND", position: bound });
  }
  sourceKeyRefusal(sourcePath, source);
  const fence = readMigratedMarker(sourcePath);
  // A-184.1: the marker's target (either form) and the requested target are compared only after canonicalising both.
  const fencedTo = fence === undefined ? undefined : markerTargetPath(sourcePath, fence.target);
  if (fencedTo !== undefined && fencedTo !== canonicalPath(target)) throw unsupported(`the source ${sourcePath} is already fenced: it was migrated to ${fencedTo}`, { reason: "SOURCE_FENCED", target: fencedTo });
  if (existingPlan === undefined && (existsSync(target) || fence !== undefined)) {
    throw new IronTrellisError("HISTORY_EXISTS", false, `the target ${target} exists without a migration plan at ${planPath}; a migration never adopts a file it did not plan`, { target, plan: planPath });
  }
  if (options.acceptUnpinnedSource !== true) {
    let pinned: string;
    try { pinned = sourceStore.verify().pinnedHeadStatus; } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    if (pinned !== "MATCHES") {
      throw unsupported(pinned === "UNPINNED" || pinned === "MISSING"
        ? `the source ${sourcePath} has no pinned head, so an edit or truncation of it cannot be ruled out, and migration would sign it under the new owner key; check the source and pass acceptUnpinnedSource to migrate it anyway`
        : `the source's pinned head does not match the file (${pinned}); pass acceptUnpinnedSource to migrate it anyway`, { reason: pinned === "UNPINNED" || pinned === "MISSING" ? "SOURCE_UNPINNED" : "SOURCE_PIN_MISMATCH", pinnedHeadStatus: pinned });
    }
  }
  const recordHash = lastRecordHash(sourcePath);
  // The owner key: as the format-1 migration (key file, reference or signer); a re-run must use the key the plan names.
  let reference: OwnerKeyReference | undefined;
  if (options.ownerKeyReference !== undefined) {
    if (options.signer !== undefined) throw new IronTrellisError("INVALID_INPUT", false, "pass the owner key once: signer or ownerKeyReference");
    try { reference = withReferenceVersion(parseKeyReference(JSON.parse(JSON.stringify(options.ownerKeyReference)), "ownerKeyReference"), OWNER_KEY_REF_VERSION); } catch (error) {
      throw new IronTrellisError("INVALID_INPUT", false, error instanceof Error ? error.message : String(error));
    }
  }
  let signer = options.signer, createdKeyFile: string | undefined;
  const keyPath = ownerKeyPathFor(target);
  let writeReference = false;
  if (signer === undefined) {
    if (existsSync(keyPath) && options.reuseExistingKey !== true && existingPlan === undefined) {
      throw new IronTrellisError("KEY_EXISTS", false, `an owner key file already exists: ${keyPath}; a leftover or planted key is never adopted silently (remove it, or pass reuseExistingKey to use it)`, { keyPath });
    }
    if (existsSync(keyPath)) {
      try { signer = loadOwnerKeyFile(keyPath); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
      if (reference !== undefined) {
        let there: OwnerKeyReference | undefined;
        if (signer.custody?.holder === "reference") { try { there = readKeyReferenceFile(keyPath, "owner"); } catch { there = undefined; } }
        if (there === undefined || there.publicKey.toLowerCase() !== reference.publicKey.toLowerCase() || sortedJson(there.signer) !== sortedJson(reference.signer)) {
          const what = there === undefined ? (signer.custody?.holder === "reference" ? "an unreadable reference" : "a key file (not a reference)") : there.publicKey.toLowerCase() !== reference.publicKey.toLowerCase() ? "a reference to another key" : `a reference to the same key in another signer (${there.signer.kind})`;
          throw new IronTrellisError("KEY_EXISTS", false, `the owner key file ${keyPath} is ${what}, not a reference to the key ownerKeyReference names in the same signer; move it aside first`, { keyPath, reason: "REUSE_MISMATCH" });
        }
      }
    } else if (reference !== undefined) {
      try { signer = referenceSigner(reference); } catch (error) { throw signerFailure(error); }
      writeReference = true;
    } else {
      try { signer = createOwnerKeyFile(keyPath); createdKeyFile = keyPath; } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    }
  }
  const planBody: Omit<MigrationPlan, "createdAt" | "migrationId"> = { version: MIGRATION_PLAN_VERSION, source: sourcePath, sourceFormat: source.format, sourceHead: source.head, target, ownerKey: { keyId: signer.keyId, scheme: signer.scheme, credential: signer.credential } };
  // A-40.3: the migration id is drawn once, at plan time; a re-run reads it from the plan (so the re-transcription is byte-identical).
  if (options.migrationId !== undefined && !/^0x[0-9a-f]{64}$/.test(options.migrationId)) throw new IronTrellisError("INVALID_INPUT", false, "migrationId must be 0x + 64 lowercase hex");
  const migrationId = existingPlan?.migrationId ?? options.migrationId ?? (`0x${randomBytes(32).toString("hex")}` as ContentHash);
  // A-40.2: a format-1 source's pin attestation of exactly the migrated head; null for a legacy source or without one.
  const pinned = source.format === TRELLIS_FORMAT ? sourceStore.pinnedHead() : undefined;
  const pinAttestation = pinned?.attestation as Readonly<Record<string, unknown>> | undefined;
  const attestedHead = pinAttestation?.head as HistoryHead | undefined;
  const sourceAttestation = pinAttestation !== undefined && attestedHead !== undefined && sameHead(attestedHead, source.head) ? pinAttestation : null;
  const provenance: Provenance = Object.freeze({ sourceAttestation, migrationId });
  if (existingPlan !== undefined && !samePlan(existingPlan, planBody)) {
    throw new IronTrellisError("MIGRATION_UNSUPPORTED", false, `a migration plan already exists at ${planPath} with different contents (source, head, target or owner key); remove it deliberately or use another target`, { reason: "PLAN_MISMATCH", plan: planPath });
  }
  const nextPath = nextOwnerKeyPathFor(target);
  let next: Signer | undefined, createdNextFile: string | undefined;
  let events: CanonicalEvent[];
  try {
    if (createdKeyFile === undefined && existingPlan === undefined) await provePossession(signer);
    if (writeReference) { try { signer = writeKeyReferenceFile(keyPath, reference!); createdKeyFile = keyPath; } catch (error) { translate(error, "READ_UNAVAILABLE"); } }
    // The next key the genesis commits to (pre-rotation); on a re-run the committed key is the one the files hold.
    next = await resolveNextKey(options, signer, nextPath, existingPlan !== undefined, (file) => { createdNextFile = file; });
    // Step 1: the plan, written before any output (verified equal on a re-run).
    if (existingPlan === undefined) writeAtomically(planPath, `${JSON.stringify({ ...planBody, createdAt: time(options.now()), migrationId } satisfies MigrationPlan)}\n`);
    cut("plan-written");
    // Step 2–4: transcription (dry-run, capacity included).
    events = await transcribe(source, signer, recordHash, next, options, provenance);
  } catch (error) {
    if (existingPlan === undefined && !existsSync(target)) {
      for (const file of [createdKeyFile, createdNextFile]) if (file !== undefined) { try { unlinkSync(file); } catch { /* best effort */ } }
      try { unlinkSync(planPath); } catch { /* absent */ }
    }
    throw error;
  }
  // ---- step 5: the target file, its pin, then the snapshot — each verified when it exists, written when it does not
  let targetStore: HistoryStore | undefined;
  const existingTarget = inspectTarget(target, events, planBody.ownerKey);
  if (existingTarget.state === "COMPLETE") {
    try { targetStore = openHistoryStore(target, { signer, trust: "FULL_REPLAY" }); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  } else {
    if (existingTarget.state === "PARTIAL") removeTargetFiles(target); // a torn or partial write of this very plan: rewritten byte for byte
    try { targetStore = createHistoryStore(target, events, { signer, reuseExistingKey: true, trust: "FULL_REPLAY" }); } catch (error) { translate(error, "WRITE_UNCONFIRMED"); }
  }
  cut("target-written");
  const targetHead = targetStore.head();
  requireCondition(targetHead !== undefined, "WRITE_UNCONFIRMED");
  // The pin: an asynchronous signer attests after the append; a pin without the owner's attestation of the head is re-pinned.
  try { await targetStore.flush(); } catch (error) {
    const failure = signerFailure(error);
    throw new IronTrellisError(failure.code, false, `the target history was written, but its pinned head could not be attested (${failure.message}); run the migration again`, failure.detail);
  }
  if (!pinAttests(targetStore.pinnedHead(), targetHead, targetStore.state())) {
    try { targetStore.repin(); await targetStore.attestationsSettled(); } catch (error) { translate(error, "WRITE_UNCONFIRMED"); }
  }
  const stateRoot = rootAt(targetStore.state(), targetHead.position)!;
  // A-41.3 / A-19.4: the target's identity (`historyId = recordHash(0)`) to configure in hooks and gateways.
  const historyId = targetStore.state().eventHistoryHashes[0]!;
  targetStore.close();
  // The snapshot: a resume-mode open rebuilds it when it is missing or stale (the writer's own open left one).
  if (readSnapshotBase(target) === undefined) { try { openHistoryStore(target, { trust: "CHECKPOINT_RESUME" }).close(); } catch { /* the snapshot is a cache */ } }
  // ---- step 6: the fence beside the source (atomic); the source bytes are never touched
  cut("before-fence");
  if (fence === undefined) {
    // A-184.1: `target` relative to the source's directory (the plan file keeps absolute paths).
    const marker: MigratedMarker = { version: MIGRATED_MARKER_VERSION, target: markerTargetOf(sourcePath, target), sourceHead: source.head, targetHead, migratedAt: time(options.now()) };
    writeAtomically(migratedMarkerPathFor(sourcePath), `${JSON.stringify(marker)}\n`);
  }
  sourceStore.close();
  return Object.freeze({
    sourceHead: source.head, targetHead, historyId, eventCount: events.length, ownerKeyId: signer.keyId, stateRoot, phase: "FENCED" as const, target, plan: planPath,
    sessionsWithoutExpiry: Object.freeze([...source.runtimeSessions.values()].filter((session) => session.expiresAt === undefined).map((session) => session.id).sort()),
    ...(next === undefined ? {} : { nextKeyDigests: Object.freeze([ownerKeyDigest(next)]), nextKeyId: next.keyId }),
    ...(createdNextFile === undefined ? {} : { nextKeyFile: createdNextFile }),
  });
}

/** The next key per the options; on a re-run (`rerun`) the files written by the first run are adopted. */
async function resolveNextKey(options: MigrationOptions, signer: Signer, nextPath: string, rerun: boolean, created: (file: string) => void): Promise<Signer | undefined> {
  if (options.nextKey === false) {
    if ([options.nextSigner, options.nextKeyReference, options.nextPublicKey].some((v) => v !== undefined)) throw new IronTrellisError("INVALID_INPUT", false, "a next key (nextSigner, nextKeyReference, nextPublicKey) cannot be combined with nextKey: false");
    return undefined;
  }
  const nextReference = options.nextKeyReference === undefined ? undefined : capturedReference(options.nextKeyReference, OWNER_NEXT_KEY_REF_VERSION, "nextKeyReference");
  let nextPublicKey: string | undefined;
  if (options.nextPublicKey !== undefined) {
    try { nextPublicKey = parsePublicKey(options.nextPublicKey); } catch (error) { throw new IronTrellisError("INVALID_INPUT", false, `nextPublicKey: ${error instanceof Error ? error.message : String(error)}`); }
  }
  if ([options.nextSigner, nextReference, nextPublicKey].filter((v) => v !== undefined).length > 1) throw new IronTrellisError("INVALID_INPUT", false, "pass the next key once: nextSigner, nextKeyReference or nextPublicKey");
  const proposedId = nextFreeOwnerKeyId(new Set([signer.keyId]));
  let next: Signer;
  if (options.nextSigner !== undefined) { next = options.nextSigner; if (!rerun) await provePossession(next); }
  else if (nextPublicKey !== undefined) next = publicKeySigner(nextPublicKey, proposedId);
  else if (nextReference !== undefined) {
    if (existsSync(nextPath) && !rerun) throw new IronTrellisError("KEY_EXISTS", false, `a next-key file already exists: ${nextPath}; move it aside, then migrate again`, { keyPath: nextPath });
    if (existsSync(nextPath)) { try { next = loadNextOwnerKeyFile(nextPath); } catch (error) { translate(error, "READ_UNAVAILABLE"); } }
    else {
      try { next = referenceSigner(nextReference); } catch (error) { throw signerFailure(error); }
      await provePossession(next);
      try { next = writeKeyReferenceFile(nextPath, nextReference); created(nextPath); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    }
  } else if (existsSync(nextPath)) {
    if (options.reuseExistingKey !== true && !rerun) throw new IronTrellisError("KEY_EXISTS", false, `a next-key file already exists: ${nextPath}; a leftover or planted key is never adopted silently (remove it, or pass reuseExistingKey to commit to it)`, { keyPath: nextPath });
    try { next = loadNextOwnerKeyFile(nextPath); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
    if (next.custody?.holder === "reference" && !rerun) await provePossession(next);
  } else {
    try { next = createNextOwnerKeyFile(nextPath, proposedId); created(nextPath); } catch (error) { translate(error, "READ_UNAVAILABLE"); }
  }
  if (next.scheme === signer.scheme && next.credential.toLowerCase() === signer.credential.toLowerCase()) throw new IronTrellisError("INVALID_INPUT", false, "the next key must differ from the owner key");
  return next;
}

/** The target file against the transcription: absent, a partial/torn/different write, or the complete byte-for-byte expected history. */
function inspectTarget(target: string, events: readonly CanonicalEvent[], ownerKey: MigrationPlan["ownerKey"]): Readonly<{ state: "ABSENT" | "PARTIAL" | "COMPLETE"; store?: undefined }> {
  if (!existsSync(target)) return { state: "ABSENT" };
  let store: HistoryStore;
  try { store = openHistoryStore(target, { inspect: true, trust: "FULL_REPLAY" }); } catch { return { state: "PARTIAL" }; }
  try {
    const written = store.readAll();
    if (written.length !== events.length) return { state: "PARTIAL" };
    for (let index = 0; index < events.length; index += 1) if (JSON.stringify(written[index]) !== JSON.stringify(events[index])) return { state: "PARTIAL" };
    const genesisKeys = (written[0]!.data.ownerKeys as readonly { credential: string }[]);
    if (genesisKeys[0]?.credential.toLowerCase() !== ownerKey.credential.toLowerCase()) return { state: "PARTIAL" };
    return { state: "COMPLETE" };
  } finally { store.close(); }
}
const removeTargetFiles = (target: string): void => {
  for (const suffix of ["", ".head", ".state", ".state.journal", ".anchors", ".writer-lock"]) { try { unlinkSync(`${target}${suffix}`); } catch { /* absent */ } }
};
/** The pin carries a valid owner attestation of exactly `head` with the right root and projection head (SPEC §7.4). */
const pinAttests = (pin: PinnedHead | undefined, head: HistoryHead, state: ReplayState): boolean => {
  if (pin === undefined || pin.position !== head.position || pin.hash !== head.hash || pin.attestation === undefined) return false;
  const facts = verifyHeadAttestationFacts(pin.attestation, state);
  return facts.valid && pin.attestation.head.position === head.position;
};

/**
 * SPEC §16.2 step 7: the phase from the actual files, not from a journal — PLANNED (the plan exists; no complete target),
 * WRITTEN (the target file is complete, its pin is not the owner's attestation of its head), PINNED (the pin attests the
 * head; the snapshot may or may not exist yet), FENCED (`<source>.migrated` exists and names this target). `verified`
 * says whether every output present verifies.
 */
export function migrationStatus(planPath: string): MigrationStatus {
  requireCondition(typeof planPath === "string" && planPath.length > 0);
  const plan = readPlan(resolve(planPath));
  if (plan === undefined) throw new IronTrellisError("READ_UNAVAILABLE", false, `no migration plan at ${planPath}`);
  const problems: string[] = [];
  const outputs = { target: existsSync(plan.target), pin: existsSync(`${plan.target}.head`), snapshot: existsSync(`${plan.target}.state`), fence: existsSync(migratedMarkerPathFor(plan.source)) };
  let phase: MigrationPhase = "PLANNED";
  let targetHead: HistoryHead | undefined;
  if (outputs.target) {
    try {
      const store = openHistoryStore(plan.target, { inspect: true, trust: "FULL_REPLAY" });
      try {
        const state = store.state();
        const migrated = state.genesis.migratedFrom;
        if (state.format !== TRELLIS2_FORMAT) problems.push("the target is not a format-2 history");
        else if (migrated === undefined || migrated.historyHash !== plan.sourceHead.hash || migrated.position !== plan.sourceHead.position) problems.push("the target's migratedFrom does not name the plan's source head");
        else if (state.events.length - 1 !== plan.sourceHead.position) problems.push(`the target holds ${state.events.length} events, the plan's source ${plan.sourceHead.position + 1}`);
        else {
          phase = "WRITTEN";
          targetHead = state.head;
          const pin = store.pinnedHead();
          if (pin !== undefined && pinAttests(pin, state.head, state)) {
            const keys = (state.genesis.ownerKeys ?? []) as readonly { credential: string }[];
            if (keys[0]?.credential.toLowerCase() === plan.ownerKey.credential.toLowerCase()) phase = "PINNED"; else problems.push("the target's genesis owner key is not the plan's");
          } else if (outputs.pin) problems.push("the pin does not carry the owner's attestation of the target head");
        }
      } finally { store.close(); }
    } catch (error) {
      problems.push(`the target does not open: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (outputs.fence) {
    try {
      const marker = readMigratedMarker(plan.source)!;
      if (markerTargetPath(plan.source, marker.target) !== canonicalPath(plan.target)) problems.push("the fence names another target");
      else if (!sameHead(marker.sourceHead, plan.sourceHead)) problems.push("the fence's source head is not the plan's");
      else if (targetHead !== undefined && !sameHead(marker.targetHead, targetHead)) problems.push("the fence's target head is not the target's");
      else if (phase === "PINNED") phase = "FENCED";
      else problems.push("the fence exists before the target is complete and pinned");
    } catch (error) {
      problems.push(`the fence is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return Object.freeze({ phase, verified: problems.length === 0, plan: resolve(planPath), source: plan.source, target: plan.target, sourceHead: plan.sourceHead, outputs: Object.freeze(outputs), problems: Object.freeze(problems) });
}

/** Sorted-key JSON, to compare two signer descriptions regardless of key order. */
const sortedJson = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(sortedJson).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${sortedJson((value as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(value);
};

/** The signer signs a fresh random challenge and the signature verifies against its public key; else the signer's error. */
async function provePossession(signer: Signer): Promise<void> {
  const challenge = `0x${createHash("sha256").update("irontrellis-migrate-possession/1\0").update(randomBytes(32)).digest("hex")}` as ContentHash;
  let signature: string;
  try { signature = await signer.signHash(challenge, { purpose: "signer-test" }); } catch (error) { throw signerFailure(error); }
  let valid = false;
  try { valid = suiteFor(signer.scheme).verify(challenge, signature as never, signer.credential); } catch { valid = false; }
  if (!valid) throw new IronTrellisError("SIGNER_FAILED", false, `the owner key's signer did not prove possession of ${signer.keyId} (${signer.credential}): its signature over a challenge does not verify; nothing was written`, { reason: "POSSESSION_NOT_PROVEN" });
}
