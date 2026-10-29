/**
 * Operator tools around one case (a history file plus a private record
 * directory): the host lease, dead-host recovery, content-free diagnostics,
 * offline snapshots with verification, and authority revocation.
 */
import { closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { HISTORY_FILE_LIMITS, capacityOf, inspectDutyPolicyState, openHistoryStore, openLocalOwner, type AuthorizationDomain, type CapacityReport, type HistoryHead, type HistoryStore, type ReplayState } from "@ramex-labs/irontrellis";
import { GatewayError, check, codeOf, durableCreate, exact, explained, isPrivateMode, privateDirectory, privateFileBytes, privateFileCheck, readPrivate, syncDirectory, type Json } from "./data.ts";

export const LOCK_FILE = "gateway-host.lock.json";
const RECORD_LIMIT = 131072, RECORD_ENTRIES = 4096;
/** The history may be as large as the core store allows (1 GiB for formats 2 and 1, 64 MiB legacy); the operator tools must not stop earlier than the writer. */
const MAX_HISTORY_BYTES = Math.max(...Object.values(HISTORY_FILE_LIMITS));
const historyLimit = (format: string | undefined): number =>
  format !== undefined && Object.hasOwn(HISTORY_FILE_LIMITS, format) ? HISTORY_FILE_LIMITS[format as keyof typeof HISTORY_FILE_LIMITS] : MAX_HISTORY_BYTES;
/**
 * Companion files a snapshot copies next to the history when they exist: the pinned head, the local anchor log and
 * the remote witness side file (`<history>.witness.json`: the witness policy, which the history does not record —
 * quorum, mode, requireOnOpen, witnesses configured but not bound —, the checkpoints remembered for split-view
 * detection, and head statements the rotated-out owner key signed that no key file in the snapshot could sign again).
 * They carry integrity evidence and policy. The side file's policy may also hold a secret: a witness's registration
 * `token`; the snapshot's copy of the side file has every `token` removed (`withoutTokens`), since secrets never belong
 * in a snapshot. Never key files.
 */
const HISTORY_COMPANIONS = [".head", ".anchors", ".witness.json"] as const;
const PIN_LIMIT = 131072, ANCHORS_LIMIT = 64 * 1024 * 1024, WITNESS_STATE_LIMIT = 1024 * 1024, CONFIG_LIMIT = 131072;
const companionLimit = (suffix: (typeof HISTORY_COMPANIONS)[number]): number => (suffix === ".head" ? PIN_LIMIT : suffix === ".anchors" ? ANCHORS_LIMIT : WITNESS_STATE_LIMIT);
/**
 * The side file as a snapshot keeps it: every registration `token` in its policy removed (a restored case registers with
 * a witness again only when the operator gives the token again). Anything else is copied as it is.
 */
function withoutTokens(bytes: Uint8Array): Uint8Array {
  let doc: unknown;
  try { doc = JSON.parse(Buffer.from(bytes).toString("utf8")); } catch { throw new GatewayError("WITNESS_STATE_INVALID", false, "the remote witness side file is not JSON"); }
  const policy = (doc as { policy?: { witnesses?: unknown } } | null)?.policy;
  if (policy === undefined || !Array.isArray(policy.witnesses) || !policy.witnesses.some((w) => w !== null && typeof w === "object" && "token" in w)) return bytes;
  const witnesses = policy.witnesses.map((w) => {
    if (w === null || typeof w !== "object") return w;
    const { token: _secret, ...rest } = w as Record<string, unknown>;
    return rest;
  });
  return Buffer.from(`${JSON.stringify({ ...(doc as object), policy: { ...policy, witnesses } })}\n`, "utf8");
}
/** Open the case history after checking it is a private file within the store's limit for its format (PRIVATE_FILE_TOO_LARGE names size and limit). */
function openCaseHistory(historyFile: string): HistoryStore {
  privateFileCheck(historyFile, MAX_HISTORY_BYTES);
  const store = openHistoryStore(historyFile);
  privateFileCheck(historyFile, historyLimit(store.format));
  return store;
}
/**
 * `requireOnOpen`'s gate (WITNESS_UNAVAILABLE, reason NOT_CHECKED). The core store raises it only after its read guard
 * found no rollback or split-view evidence (this process's alarm, the side file's remembered witness head or recorded
 * split view): those are thrown first and still refuse the operator tools.
 */
const awaitingWitnessCheck = (error: unknown): boolean => {
  const info = error as { detail?: { reason?: unknown }; context?: { reason?: unknown } } | null;
  return codeOf(error) === "WITNESS_UNAVAILABLE" && (info?.detail?.reason === "NOT_CHECKED" || info?.context?.reason === "NOT_CHECKED");
};
/**
 * The case history's state for the offline operator tools (inspect, snapshot). They never ask the remote witnesses,
 * so they never establish currentness: a policy with `requireOnOpen` (readers must ask the witnesses first) does not
 * gate them, the history is then read without its witness session and `remoteWitnessCheck: "SKIPPED"` says so.
 * Evidence of a rollback or a split view still refuses (the store's guard raises it before the gate).
 */
function readCaseHistory(historyFile: string): { store: HistoryStore; state: ReplayState; remoteWitnessCheck: "NOT_REQUIRED" | "SKIPPED" } {
  const store = openCaseHistory(historyFile);
  try {
    return { store, state: store.state(), remoteWitnessCheck: "NOT_REQUIRED" };
  } catch (error) {
    if (!awaitingWitnessCheck(error)) throw error;
    store.close();
    const offline = openHistoryStore(historyFile, { witness: false });
    return { store: offline, state: offline.state(), remoteWitnessCheck: "SKIPPED" };
  }
}
const digest = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
type LockRecord = Readonly<{ version: "irontrellis-gateway-host/1"; host: string; pid: number; nonce: string }>;
function lockRecord(path: string): LockRecord {
  const value = exact(readPrivate(path), ["version", "host", "pid", "nonce"]);
  check(value.version === "irontrellis-gateway-host/1" && typeof value.host === "string" && Number.isSafeInteger(value.pid) && (value.pid as number) > 0 && typeof value.nonce === "string", "HOST_LOCK_INVALID");
  return value as LockRecord;
}
export type HostLease = Readonly<{ assertOwned(): void; release(): void }>;

/** A process ownership guard for one record directory; it is not core authority or a distributed lock. */
export function acquireHostLease(storage: string): HostLease {
  const directory = privateDirectory(storage), path = join(directory, LOCK_FILE);
  check(!existsSync(path), "HOST_ALREADY_OWNED");
  const value: LockRecord = { version: "irontrellis-gateway-host/1", host: hostname(), pid: process.pid, nonce: randomUUID() };
  try { durableCreate(path, value); } catch (error) { if (codeOf(error) === "EEXIST") throw new GatewayError("HOST_ALREADY_OWNED"); throw error; }
  const identity = lstatSync(path);
  let closed = false;
  const assertOwned = (): void => {
    check(!closed, "HOST_NOT_OWNED");
    const named = lstatSync(path);
    check(named.ino === identity.ino && named.dev === identity.dev && lockRecord(path).nonce === value.nonce, "HOST_NOT_OWNED");
  };
  return Object.freeze({
    assertOwned,
    release() { if (closed) return; assertOwned(); unlinkSync(path); syncDirectory(directory); closed = true; },
  });
}

/** Explicit operator action: remove only a same-host lease whose PID provably no longer exists. */
export function recoverDeadHost(storage: string) {
  const directory = privateDirectory(storage), path = join(directory, LOCK_FILE), value = lockRecord(path), identity = lstatSync(path);
  check(value.host === hostname(), "HOST_RECOVERY_UNVERIFIED");
  let absent = false;
  try { process.kill(value.pid, 0); } catch (error) { check(codeOf(error) === "ESRCH", "HOST_RECOVERY_UNVERIFIED"); absent = true; }
  check(absent, "HOST_STILL_RUNNING");
  const current = lstatSync(path);
  check(current.ino === identity.ino && current.dev === identity.dev && lockRecord(path).nonce === value.nonce, "HOST_RECOVERY_UNVERIFIED");
  unlinkSync(path);
  syncDirectory(directory);
  return { status: "DEAD_HOST_LEASE_REMOVED" as const, historyChanged: false as const, authorityChanged: false as const };
}

function recordNames(storage: string): string[] {
  const names = readdirSync(storage);
  check(names.length <= RECORD_ENTRIES, "RECORD_CAPACITY");
  for (const n of names) check(n.length <= 200 && !n.includes("/") && !n.startsWith("."), "RECORD_NAME_INVALID");
  return names.filter((n) => n !== LOCK_FILE).sort();
}
function historyState(historyFile: string): { state: ReplayState; verification: ReturnType<HistoryStore["verify"]>; remoteWitnessCheck: "NOT_REQUIRED" | "SKIPPED" } {
  const { store, state, remoteWitnessCheck } = readCaseHistory(historyFile);
  return { state, verification: store.verify(), remoteWitnessCheck };
}

export type CaseLocation = Readonly<{ historyFile: string; storage: string }>;
export type CaseDiagnostic = Readonly<{
  profile: string; format: string; eventCount: number; maxEvents: number | null; mode: CapacityReport["mode"]; canDeclareJob: boolean; declaredJobs: number;
  remainingCoreEvents: number | null; capacity: CapacityReport; observedHeadHash: string; chain: string; pinnedHeadStatus: string; rollback: boolean;
  recordFiles: number; recordBytes: number; leasePresent: boolean; warnings: readonly string[]; limits: Readonly<{ recordEntries: number; recordBytes: number; historyBytes: number }>;
  /** docs/API.md §2, SPEC §13.3: attempt duties by their current view (`OPEN`, `COMPLETED_UNDER_POLICY`, `NEEDS_REVIEW`, `CONTESTED`, …; `NO_POLICY` without one). Counts only. */
  duties: Readonly<{ total: number; withPolicy: number; outstanding: number; byView: Readonly<Record<string, number>> }>;
  pointInTimeOnly: true; restoreAuthorization: false;
}>;
/** Counts of the case's attempt duties by their duty view (no ids, no content). */
function dutySummary(state: ReplayState): CaseDiagnostic["duties"] {
  const byView: Record<string, number> = {};
  let withPolicy = 0, outstanding = 0;
  for (const dutyId of state.attemptDuties.keys()) {
    const view = inspectDutyPolicyState(state, dutyId);
    const key = view === null ? "NO_POLICY" : String(view.dutyDisposition);
    byView[key] = (byView[key] ?? 0) + 1;
    if (view !== null) withPolicy += 1;
    if (view === null ? String(state.attemptDuties.get(dutyId)!.record.status) === "OPEN" : view.outstanding) outstanding += 1;
  }
  return Object.freeze({ total: state.attemptDuties.size, withPolicy, outstanding, byView: Object.freeze(byView) });
}
/** Counts only: no identities, arguments, reports, paths or credentials in the returned summary. */
export function inspectCase({ historyFile, storage }: CaseLocation): CaseDiagnostic {
  const directory = privateDirectory(storage);
  const { state, verification, remoteWitnessCheck } = historyState(historyFile), names = recordNames(directory);
  let recordBytes = 0;
  for (const name of names) {
    const s = lstatSync(join(directory, name));
    check(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && isPrivateMode(s.mode) && s.size <= RECORD_LIMIT, "PRIVATE_FILE_INVALID");
    recordBytes += s.size;
  }
  const capacity = capacityOf(state), rollback = verification.pinnedHeadStatus === "ROLLBACK";
  return Object.freeze({
    profile: capacity.profile, format: state.format, eventCount: capacity.eventCount, maxEvents: capacity.maxEvents, mode: capacity.mode, canDeclareJob: capacity.canDeclareJob,
    declaredJobs: capacity.declaredJobs, remainingCoreEvents: capacity.remainingPhysicalEvents, capacity, observedHeadHash: state.head.hash,
    chain: verification.chain, pinnedHeadStatus: verification.pinnedHeadStatus, rollback,
    recordFiles: names.length, recordBytes, leasePresent: existsSync(join(directory, LOCK_FILE)),
    warnings: [...(capacity.mode === "CONTROL_ONLY" ? ["CAPACITY_CONTROL_ONLY"] : []), ...(rollback ? ["ROLLBACK_DETECTED"] : []), ...(remoteWitnessCheck === "SKIPPED" ? ["REMOTE_WITNESS_NOT_CHECKED"] : [])],
    limits: { recordEntries: RECORD_ENTRIES, recordBytes: RECORD_LIMIT, historyBytes: historyLimit(state.format) },
    duties: dutySummary(state), pointInTimeOnly: true, restoreAuthorization: false,
  });
}

function writeBytes(path: string, bytes: Uint8Array): void {
  const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
}
/** Top-level files a snapshot may hold besides `records/` and `snapshot.json`. */
const SNAPSHOT_TOP_FILES: Readonly<Record<string, number>> = {
  "history.jsonl": MAX_HISTORY_BYTES, "history.jsonl.head": PIN_LIMIT, "history.jsonl.anchors": ANCHORS_LIMIT, "history.jsonl.witness.json": WITNESS_STATE_LIMIT,
  "gateway.json": CONFIG_LIMIT,
};
const snapshotLimit = (path: string): number => SNAPSHOT_TOP_FILES[path] ?? RECORD_LIMIT;
/**
 * Offline private copy of a case: the history, its pinned head (`<history>.head`), local anchor log
 * (`<history>.anchors`) and remote witness side file (`<history>.witness.json`, its registration tokens removed) when present, every record, and the gateway
 * configuration file when `configFile` is given. Key files (the owner key, the session key named by `keyFile`) and witness tokens are never copied. The caller must stop
 * every history writer, including owner administration.
 */
export function snapshotCase({ historyFile, storage, directory, configFile }: CaseLocation & Readonly<{ directory: string; configFile?: string }>) {
  const source = privateDirectory(storage), target = resolve(directory);
  explained("the snapshot's parent directory:", () => privateDirectory(dirname(target)));
  // path.relative, not a "/" prefix: Windows separates with "\\" and compares names without case.
  const within = relative(source, target);
  check(within !== "" && (within === ".." || within.startsWith(`..${sep}`) || isAbsolute(within)), "SNAPSHOT_TARGET_INVALID", "the snapshot directory must not be inside the case's storage directory");
  check(!existsSync(target), "SNAPSHOT_TARGET_INVALID", `${target} already exists; a snapshot is written to a new directory`);
  const lease = acquireHostLease(source);
  try {
    const { store, state, remoteWitnessCheck } = readCaseHistory(historyFile), limit = historyLimit(store.format);
    const before = privateFileBytes(historyFile, limit), head = state.head;
    const companions = HISTORY_COMPANIONS.flatMap((suffix) => (existsSync(historyFile + suffix) ? [suffix] : []));
    const companionBytes = companions.map((suffix) => privateFileBytes(historyFile + suffix, companionLimit(suffix)));
    const config = configFile === undefined ? undefined : privateFileBytes(configFile, CONFIG_LIMIT);
    // The manifest is one private file (at most 128 KiB, the bound every gateway file shares): a case with too many records
    // for it is refused before anything is created, so no partial snapshot directory is left and a later run is not blocked.
    // The bound is an upper estimate (each row at its longest size and digest).
    const names = recordNames(source);
    const rows = ["history.jsonl", ...companions.map((suffix) => "history.jsonl" + suffix), ...(config === undefined ? [] : ["gateway.json"]), ...names.map((name) => "records/" + name)]
      .map((path) => ({ path, bytes: 9_007_199_254_740_991, sha256: `0x${"0".repeat(64)}` }));
    const estimate = Buffer.byteLength(JSON.stringify({ version: "irontrellis-private-snapshot/1", head, files: rows, restoreAuthorized: false }));
    check(estimate <= 131_072, "SNAPSHOT_TOO_LARGE", `the case holds ${names.length} record files: its snapshot manifest would need up to ${estimate} bytes, over the 131,072 a gateway file may hold; nothing was written (prune or archive the records first)`);
    mkdirSync(target, { mode: 0o700 });
    mkdirSync(join(target, "records"), { mode: 0o700 });
    const files: { path: string; bytes: number; sha256: string }[] = [];
    const put = (name: string, bytes: Uint8Array): void => { writeBytes(join(target, name), bytes); files.push({ path: name, bytes: bytes.length, sha256: digest(bytes) }); };
    put("history.jsonl", before);
    companions.forEach((suffix, i) => put("history.jsonl" + suffix, suffix === ".witness.json" ? withoutTokens(companionBytes[i]!) : companionBytes[i]!));
    if (config !== undefined) put("gateway.json", config);
    for (const name of names) { lease.assertOwned(); put("records/" + name, privateFileBytes(join(source, name), RECORD_LIMIT)); }
    check(digest(privateFileBytes(historyFile, limit)) === digest(before), "HISTORY_CHANGED_DURING_SNAPSHOT");
    companions.forEach((suffix, i) => check(existsSync(historyFile + suffix) && digest(privateFileBytes(historyFile + suffix, companionLimit(suffix))) === digest(companionBytes[i]!), "HISTORY_CHANGED_DURING_SNAPSHOT"));
    durableCreate(join(target, "snapshot.json"), { version: "irontrellis-private-snapshot/1", head, files, restoreAuthorized: false });
    syncDirectory(join(target, "records"));
    syncDirectory(target);
    return {
      status: "PRIVATE_SNAPSHOT_CREATED" as const, files: files.length, pinnedHead: companions.includes(".head"), anchors: companions.includes(".anchors"),
      witnessState: companions.includes(".witness.json"), configuration: config !== undefined, keysIncluded: false as const, restoreAuthorized: false as const,
      // An offline copy: the remote witnesses are not asked ("SKIPPED": the policy has requireOnOpen and the gate was not
      // waited for), so the snapshot proves integrity of what was copied, never that it is the witnessed latest.
      remoteWitnessCheck, currentnessEstablished: false as const,
    };
  } finally {
    lease.release();
  }
}
export function verifySnapshot(directory: string) {
  const root = privateDirectory(directory), recordDirectory = privateDirectory(join(root, "records"));
  const manifest = exact(readPrivate(join(root, "snapshot.json")), ["version", "head", "files", "restoreAuthorized"]);
  const topFiles = Object.keys(SNAPSHOT_TOP_FILES);
  check(manifest.version === "irontrellis-private-snapshot/1" && manifest.restoreAuthorized === false && Array.isArray(manifest.files) && manifest.files.length <= RECORD_ENTRIES + topFiles.length, "SNAPSHOT_INVALID");
  const seen = new Set<string>();
  for (const raw of manifest.files as unknown[]) {
    const row = exact(raw, ["path", "bytes", "sha256"]) as Readonly<{ path: string; bytes: number; sha256: string }>;
    check(topFiles.includes(row.path) || /^records\/[A-Za-z0-9:_.-]+$/.test(row.path), "SNAPSHOT_INVALID", `lists an unexpected file "${String(row.path).slice(0, 64)}"`);
    check(!seen.has(row.path), "SNAPSHOT_INVALID", "lists a file twice");
    seen.add(row.path);
    const bytes = privateFileBytes(join(root, row.path), snapshotLimit(row.path));
    check(bytes.length === row.bytes && digest(bytes) === row.sha256, "SNAPSHOT_MISMATCH", `${row.path} does not match its checksum`);
  }
  const expectedRoot = ["records", "snapshot.json", ...[...seen].filter((p) => !p.startsWith("records/"))].sort().join("|");
  check(seen.has("history.jsonl") && readdirSync(root).sort().join("|") === expectedRoot, "SNAPSHOT_INVALID", "the snapshot directory holds files its manifest does not list");
  check(readdirSync(recordDirectory).every((n) => n !== LOCK_FILE && seen.has("records/" + n)), "SNAPSHOT_INVALID", "records/ holds files the manifest does not list");
  // Offline: the remote witnesses are not asked (currentness is not established here), so the copied side file's policy
  // (requireOnOpen) must not gate the read either.
  const store = openHistoryStore(join(root, "history.jsonl"), { witness: false }), state = store.state();
  check(state.head.hash === (manifest.head as HistoryHead).hash, "SNAPSHOT_MISMATCH", "the history's head is not the head the manifest recorded");
  return {
    status: "PRIVATE_SNAPSHOT_VERIFIED" as const, files: seen.size, eventCount: state.events.length, pinnedHeadStatus: store.verify().pinnedHeadStatus,
    anchors: seen.has("history.jsonl.anchors"), witnessState: seen.has("history.jsonl.witness.json"), configuration: seen.has("gateway.json"), currentnessEstablished: false as const, restoreAuthorized: false as const,
  };
}

export type RevocationRequest = Readonly<{
  historyFile: string; authority: string;
  /** Owner profile; derived from the history when absent (genesis domain, PRINCIPAL_CREATED, the recorded controller). */
  domain?: AuthorizationDomain; owner?: string; controller?: string;
  now?: () => number;
}>;
export type RevocationResult = Readonly<{
  status: "AUTHORITY_REVOKED" | "ALREADY_REVOKED"; authorityId: string; eventId?: string; head: HistoryHead; historyChanged: boolean; authorityChanged: boolean;
  /** Whether a grant of this id still decides any current permission: never, once revoked. */
  followsRestart: false;
}>;
/** Revoke one recorded authority (grant, delegation or prohibition) as the owner. Control writes are always admitted, whatever the capacity. */
export async function revokeAuthority(request: RevocationRequest): Promise<RevocationResult> {
  const r = exact(request, ["historyFile", "authority"], ["domain", "owner", "controller", "now"]) as RevocationRequest;
  check(typeof r.historyFile === "string" && typeof r.authority === "string" && r.authority.length > 0);
  const reader = openHistoryStore(r.historyFile);
  // A witness policy with requireOnOpen: the history is confirmed with the remote witnesses before it is read (the owner write asks them anyway).
  if (reader.witnessStatus()?.checkRequired === true) await reader.checkWitnesses();
  const state = reader.state();
  const principal = state.events[1];
  check(principal?.type === "PRINCIPAL_CREATED", "PROFILE_MISMATCH");
  const recordedController = state.events.find((e) => e.type === "AGENT_CREATED" || e.type === "RUNTIME_SESSION_ADMITTED")?.data.controllerId;
  const owner = openLocalOwner({
    historyFile: r.historyFile, domain: r.domain ?? state.genesis.domain, owner: r.owner ?? (principal.data.principalId as string),
    controller: r.controller ?? (typeof recordedController === "string" ? recordedController : (principal.data.principalId as string)), now: r.now ?? Date.now,
    // The file's own format is named (the core opens older formats read only without it, SPEC §16.1).
    format: state.format,
  });
  const authority = state.authorities.get(r.authority);
  check(authority !== undefined, "UNKNOWN_AUTHORITY");
  if (authority.revocationEventId !== undefined) {
    return Object.freeze({ status: "ALREADY_REVOKED", authorityId: r.authority, eventId: authority.revocationEventId, head: state.head, historyChanged: false, authorityChanged: false, followsRestart: false });
  }
  const written = await owner.revoke(r.authority);
  // A short-lived operator process: submit the head statement to the remote witnesses now (best effort; witness evidence is an error).
  if (owner.witnessStatus() !== undefined) {
    try { await owner.flush(); } catch (error) {
      if (error instanceof Error && "code" in error && (error.code === "ROLLBACK_DETECTED" || error.code === "WITNESS_SPLIT_VIEW")) throw error;
    }
  }
  return Object.freeze({ status: "AUTHORITY_REVOKED", authorityId: r.authority, eventId: written.eventId, head: written.head, historyChanged: true, authorityChanged: true, followsRestart: false });
}
export type { Json };
