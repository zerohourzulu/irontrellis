/**
 * The engine-private snapshot of a format-2 history (SPEC-IRONTRELLIS-CORE-v2 §7.5, `CHECKPOINT_RESUME`).
 *
 * Two files beside the history, both the reader's own cache (never trusted on their own; every resume recomputes the
 * §7.1 root from the records and matches it against an owner-signed root at exactly that position):
 *  - `<history>.state`         — the base: `{version: "irontrellis-snapshot/2", position, stateRoot, records: [{kind, key, record}]}`,
 *                                the SPEC's closed schema, written atomically (tmp + rename) at creation, at every
 *                                compaction and after a full-replay fallback;
 *  - `<history>.state.journal` — one line per accepted event after the base, appended (not rewritten) on every write:
 *                                `{position, type, recordHash, set: [{kind, key, record}], delete: [{kind, key}]}`, the
 *                                records that event created, changed or removed (its own `event` record included).
 * A full snapshot per append would be several MB of JSON at 12,000 records (thoughts item 3); the journal line is a
 * few records, so the per-append cost is one small append. Every `SNAPSHOT_JOURNAL_LIMIT` lines the base is rewritten
 * at the head and the journal emptied (compaction). Positions the base already covers are ignored in the journal; a
 * gap, a malformed line or a torn tail ends the usable journal (the lines after it are stale). Nothing here is
 * fsynced or locked: a torn or missing snapshot is `SNAPSHOT_STALE` and costs a full replay, never a wrong answer.
 *
 * `stateRoot` in the base is informational: the reader never compares it (SPEC §7.5 step 3 forbids using a stored root
 * in place of the recomputation); it lets an operator see what the writer believed.
 */
import { closeSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from "node:fs";
import { parseStrictJson } from "./strict-json.ts";
import { EngineError } from "./errors.ts";
import type { RecordInput } from "./state-rebuild.ts";
import { replaceFileSync } from "./platform.ts";
import type { ContentHash, EventType, ReplayState } from "./types.ts";
import type { MutableReplayState } from "./state.ts";
import { stateRecordsOf } from "./state-records.ts";

export const SNAPSHOT_VERSION = "irontrellis-snapshot/2";
/** Journal lines before the base is rewritten at the head (the §14 budget assumes ≤ 256 events after the snapshot). */
export const SNAPSHOT_JOURNAL_LIMIT = 256;
export const snapshotPathFor = (historyPath: string): string => `${historyPath}.state`;
export const journalPathFor = (historyPath: string): string => `${historyPath}.state.journal`;

/** One record change of an accepted event: `record` undefined = removed (SPEC §7.2: unbound witnesses are removed). */
export type RecordChange = Readonly<{ kind: string; key: string; record: Readonly<Record<string, unknown>> | undefined }>;
export type SnapshotBase = Readonly<{ version: typeof SNAPSHOT_VERSION; position: number; stateRoot: ContentHash; records: readonly RecordInput[] }>;
export type JournalLine = Readonly<{ position: number; type: EventType; recordHash: ContentHash; set: readonly RecordInput[]; delete: readonly Readonly<{ kind: string; key: string }>[] }>;
export type SnapshotFiles = Readonly<{ base: SnapshotBase; journal: readonly JournalLine[] }>;

const isRecordInput = (value: unknown): value is RecordInput =>
  value !== null && typeof value === "object" && typeof (value as RecordInput).kind === "string" && typeof (value as RecordInput).key === "string" &&
  (value as RecordInput).record !== null && typeof (value as RecordInput).record === "object" && !Array.isArray((value as RecordInput).record) && Object.keys(value as object).length === 3;
const isHash = (value: unknown): value is ContentHash => typeof value === "string" && /^0x[0-9a-f]{64}$/.test(value);
const isPosition = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/**
 * A-44.2: the snapshot's size bound, checked against the file size before anything is read (default `2 × HARD_BYTES` =
 * 2 GiB; configurable with `setSnapshotMaxBytes`, stated in docs/reference/operator-monitoring-incidents.md and DEVIATIONS so the Python port matches), and its
 * entry bound (`HARD_RECORDS` records after the journal). A violation makes the snapshot stale (`SNAPSHOT_STALE` +
 * `FULL_REPLAY`). The §3.1 limits apply to each record, never to the container. Validation is never weakened to fit.
 */
export const SNAPSHOT_MAX_BYTES_DEFAULT = 2 * 1024 * 1024 * 1024;
export const SNAPSHOT_MAX_ENTRIES = 1_048_576;
let snapshotMaxBytes = SNAPSHOT_MAX_BYTES_DEFAULT;
/** Operator setting (A-44.2): the largest snapshot base a reader loads; `undefined` restores the default. */
export const setSnapshotMaxBytes = (bytes?: number): number => (snapshotMaxBytes = bytes === undefined ? SNAPSHOT_MAX_BYTES_DEFAULT : bytes);
/** The base file, or `undefined` when absent, too large (A-44.2) or not a well-formed `irontrellis-snapshot/2` (closed schema; strict JSON, A-34). */
export function readSnapshotBase(historyPath: string): SnapshotBase | undefined {
  let text: string;
  try {
    if (statSync(snapshotPathFor(historyPath)).size > snapshotMaxBytes) return undefined;
    text = readFileSync(snapshotPathFor(historyPath), "utf8");
  } catch { return undefined; }
  let parsed: unknown;
  try { parsed = parseStrictJson(text); } catch { return undefined; }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const base = parsed as Record<string, unknown>;
  const keys = Object.keys(base).sort().join(",");
  if (keys !== "position,records,stateRoot,version" || base.version !== SNAPSHOT_VERSION || !isPosition(base.position) || !isHash(base.stateRoot) || !Array.isArray(base.records) || base.records.length > SNAPSHOT_MAX_ENTRIES || !base.records.every(isRecordInput)) return undefined;
  return base as unknown as SnapshotBase;
}
/** The usable journal lines after `base.position`: contiguous from `base.position + 1`, each well-formed; stops at the first gap or defect. */
export function readJournal(historyPath: string, base: SnapshotBase): readonly JournalLine[] {
  let text: string;
  try { text = readFileSync(journalPathFor(historyPath), "utf8"); } catch { return []; }
  const lines: JournalLine[] = [];
  let expected = base.position + 1;
  for (const raw of text.split("\n")) {
    if (raw.length === 0) continue;
    let parsed: unknown;
    try { parsed = parseStrictJson(raw); } catch { break; }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) break;
    const line = parsed as Record<string, unknown>;
    if (!isPosition(line.position) || typeof line.type !== "string" || !isHash(line.recordHash) || !Array.isArray(line.set) || !line.set.every(isRecordInput) ||
        !Array.isArray(line.delete) || !line.delete.every((d) => d !== null && typeof d === "object" && typeof (d as { kind: unknown }).kind === "string" && typeof (d as { key: unknown }).key === "string")) break;
    if (line.position <= base.position) continue; // covered by the base (a compaction the journal truncation did not follow yet)
    if (line.position !== expected) break;
    lines.push(line as unknown as JournalLine);
    expected += 1;
  }
  return lines;
}
/** Both files, or `undefined` when there is no usable base. */
export function readSnapshotFiles(historyPath: string): SnapshotFiles | undefined {
  const base = readSnapshotBase(historyPath);
  return base === undefined ? undefined : { base, journal: readJournal(historyPath, base) };
}
/** The record set at `position` (base + journal lines through it), or `undefined` when the files do not reach it. */
export function recordsAt(files: SnapshotFiles, position: number): readonly RecordInput[] | undefined {
  if (position < files.base.position) return undefined;
  const lastJournal = files.journal.at(-1)?.position ?? files.base.position;
  if (position > lastJournal) return undefined;
  const map = new Map<string, RecordInput>();
  for (const entry of files.base.records) map.set(`${entry.kind}\u0000${entry.key}`, entry);
  for (const line of files.journal) {
    if (line.position > position) break;
    for (const removed of line.delete) map.delete(`${removed.kind}\u0000${removed.key}`);
    for (const entry of line.set) map.set(`${entry.kind}\u0000${entry.key}`, entry);
  }
  // A-44.2: the container holds at most HARD_RECORDS entries after journal application.
  if (map.size > SNAPSHOT_MAX_ENTRIES) return undefined;
  return [...map.values()];
}
/** The record hash the journal (or the base's records) claims for `position`, when known. */
export function journalRecordHash(files: SnapshotFiles, position: number): ContentHash | undefined {
  return files.journal.find((line) => line.position === position)?.recordHash;
}

const plainRecords = (state: ReplayState): RecordInput[] => stateRecordsOf(state).map((entry) => ({ kind: entry.kind, key: entry.key, record: entry.record }));
const writeAtomic = (path: string, text: string): void => {
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  const fd = openSync(temporary, "wx", 0o600);
  try { writeSync(fd, text); } finally { closeSync(fd); }
  try { replaceFileSync(temporary, path); } catch (error) { try { unlinkSync(temporary); } catch { /* best effort */ } throw error; }
};
/** Writes the base at the state's head and empties the journal (a compaction, the first snapshot, or a rebuild after a fallback). */
export function writeSnapshotBase(historyPath: string, state: ReplayState, afterBase?: () => void): void {
  const root = state.stateRoots[state.head.position];
  if (root === undefined) throw new EngineError("INVALID_INPUT", "snapshot: the state has no root at its head");
  writeSnapshotBaseRecords(historyPath, state.head.position, root, plainRecords(state), afterBase);
}
/** Writes the base from a record set at `position` and empties the journal. */
export function writeSnapshotBaseRecords(historyPath: string, position: number, stateRoot: ContentHash, records: readonly RecordInput[], afterBase?: () => void): void {
  const base: SnapshotBase = { version: SNAPSHOT_VERSION, position, stateRoot, records };
  writeAtomic(snapshotPathFor(historyPath), `${JSON.stringify(base)}\n`);
  afterBase?.(); // a test's cut point between the base and the journal truncation (T3)
  writeAtomic(journalPathFor(historyPath), "");
}
/** Appends one journal line for the event at `position` (its record changes as `applyStateRecords` recorded them). */
export function appendJournalLine(historyPath: string, position: number, type: EventType, recordHash: ContentHash, changes: readonly RecordChange[]): void {
  const line: JournalLine = {
    position, type, recordHash,
    set: changes.filter((c) => c.record !== undefined).map((c) => ({ kind: c.kind, key: c.key, record: c.record! })),
    delete: changes.filter((c) => c.record === undefined).map((c) => ({ kind: c.kind, key: c.key })),
  };
  const fd = openSync(journalPathFor(historyPath), "a", 0o600);
  try { writeSync(fd, `${JSON.stringify(line)}\n`); } finally { closeSync(fd); }
}
/** Removes both files (a store that found them unusable and cannot rebuild them yet). */
export function removeSnapshot(historyPath: string): void {
  for (const path of [snapshotPathFor(historyPath), journalPathFor(historyPath)]) { try { unlinkSync(path); } catch { /* absent */ } }
}
/** The record changes of the last accepted event (set by `applyStateRecords`), consumed by the store's journal. */
export const takeRecordChanges = (state: MutableReplayState): readonly RecordChange[] => {
  const changes = state.lastRecordChanges ?? [];
  state.lastRecordChanges = undefined;
  return changes;
};
