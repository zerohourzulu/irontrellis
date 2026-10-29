/**
 * The witness data directory (docs/reference/witness-service.md §4.6, §9.3): `log.jsonl` (one canonical
 * JSON line per Merkle leaf, the only source of truth), `checkpoints.jsonl`
 * (every checkpoint note issued, for audit) and `server.lock` (one writer).
 *
 * Durability: a line is written and the file fsynced (and the directory, when
 * the file was just created) before anything that depends on it is answered.
 * A crash can therefore leave at most one torn final line, which was never
 * acknowledged; it is cut off with a warning at start-up. Anything else that
 * does not parse, is not in canonical form, or skips an index is corruption:
 * the witness refuses to start and names the file and line.
 */
import { closeSync, fstatSync, fsyncSync, ftruncateSync, linkSync, openSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeSync, type BigIntStats } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { hostname } from "node:os";
import { basename, dirname, join } from "node:path";
import { canonicalEncode } from "@ramex-labs/irontrellis";
import { isWindowsTransientError } from "@ramex-labs/irontrellis/platform";
import type { WitnessEntry } from "@ramex-labs/irontrellis/transparency";

export const LOG_FILE = "log.jsonl";
export const CHECKPOINTS_FILE = "checkpoints.jsonl";
export const LOCK_FILE = "server.lock";
export const KEY_FILE = "witness-key.json";
export const CONFIG_FILE = "config.json";

/** The data directory cannot be used as it is: the witness refuses to start. */
export class DataError extends Error {
  readonly file: string | undefined;
  readonly line: number | undefined;
  constructor(message: string, file?: string, line?: number) {
    super(file === undefined ? message : `${file}${line === undefined ? "" : ` line ${line}`}: ${message}`);
    this.name = "DataError";
    this.file = file;
    this.line = line;
  }
}

export type Warn = (message: string, fields?: Readonly<Record<string, unknown>>) => void;

const errnoCode = (error: unknown): string | undefined => (error as NodeJS.ErrnoException | null)?.code;
const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const UTF8 = new TextEncoder();
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

/**
 * fsync a directory so a newly created or renamed entry survives a crash. Skipped on Windows, which cannot fsync a
 * directory (NTFS journals directory changes itself); elsewhere only the "cannot do that here" answers of unusual
 * file systems are tolerated.
 */
export function fsyncDir(dir: string): void {
  if (process.platform === "win32") return;
  let fd: number | undefined;
  try {
    fd = openSync(dir, "r");
    fsyncSync(fd);
  } catch (error) {
    if (!["EISDIR", "EPERM", "EINVAL", "EBADF"].includes(errnoCode(error) ?? "")) throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

// ---------------------------------------------------------------- line files

export type RawLine = Readonly<{ text: string; offset: number; length: number; lineNumber: number }>;
export type LineScan = Readonly<{ validBytes: number; tornBytes: number; lines: number }>;

/**
 * Streams the complete (newline-terminated) lines of `path` to `onLine`, in
 * 1 MiB chunks. A final fragment without its newline is reported as torn and
 * not passed on. A missing file scans as empty.
 */
export function scanLines(path: string, onLine: (line: RawLine) => void): LineScan {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return { validBytes: 0, tornBytes: 0, lines: 0 };
    throw error;
  }
  try {
    const size = fstatSync(fd).size;
    let chunk = Buffer.alloc(1 << 20);
    let carry = Buffer.alloc(0);
    let carryOffset = 0;
    let position = 0;
    let lineNumber = 0;
    while (position < size) {
      const read = readSync(fd, chunk, 0, Math.min(chunk.length, size - position), position);
      if (read === 0) break;
      let data = carry.length === 0 ? chunk.subarray(0, read) : Buffer.concat([carry, chunk.subarray(0, read)]);
      let dataOffset = carry.length === 0 ? position : carryOffset;
      position += read;
      let start = 0;
      for (let newline = data.indexOf(0x0a, start); newline >= 0; newline = data.indexOf(0x0a, start)) {
        lineNumber += 1;
        const bytes = data.subarray(start, newline);
        let text: string;
        try {
          text = STRICT_UTF8.decode(bytes);
        } catch {
          throw new DataError("not valid UTF-8", basename(path), lineNumber);
        }
        onLine({ text, offset: dataOffset + start, length: newline - start + 1, lineNumber });
        start = newline + 1;
      }
      carry = Buffer.from(data.subarray(start));
      carryOffset = dataOffset + start;
      data = Buffer.alloc(0);
      dataOffset = 0;
      if (carry.length > chunk.length / 2) chunk = Buffer.alloc(chunk.length * 2);
    }
    const validBytes = size - carry.length;
    return { validBytes, tornBytes: carry.length, lines: lineNumber };
  } finally {
    closeSync(fd);
  }
}

/** Cuts a torn tail off `path` (the bytes after `validBytes`) and fsyncs. */
export function truncateTail(path: string, validBytes: number): void {
  const fd = openSync(path, "r+");
  try {
    ftruncateSync(fd, validBytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

// ---------------------------------------------------------------- log.jsonl

export type LogRecord = Readonly<{ index: number; entry: WitnessEntry }>;

/** One log line: `{"index":N,"entry":{…}}`, canonical key order, newline-terminated. The leaf is self-contained (ROTATED entries carry `previousHead`, docs/reference/witness-protocol.md §9.3). */
export function encodeLogLine(record: LogRecord): string {
  const text = canonicalEncode({ index: record.index, entry: record.entry });
  // Whatever is written must read back byte-identically (the replay checks canonical form).
  if (canonicalEncode(JSON.parse(text)) !== text) throw new DataError("entry does not survive a JSON round trip");
  return `${text}\n`;
}

/** Parses one log line; throws DataError naming the line. Checks the canonical form (so an edit that changes nothing else is still caught). */
export function parseLogLine(line: RawLine, file = LOG_FILE): LogRecord {
  let value: unknown;
  try {
    value = JSON.parse(line.text);
  } catch {
    throw new DataError("not JSON", file, line.lineNumber);
  }
  if (!isRecord(value)) throw new DataError("not a JSON object", file, line.lineNumber);
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "entry,index") throw new DataError("a log line is {index, entry}", file, line.lineNumber);
  let canonical: string;
  try {
    canonical = canonicalEncode(value);
  } catch (error) {
    throw new DataError(`not canonically encodable: ${error instanceof Error ? error.message : String(error)}`, file, line.lineNumber);
  }
  if (canonical !== line.text) {
    // A CR before the newline is what a Windows editor or git's core.autocrlf leaves: name it, the fix is mechanical.
    const crlf = line.text.endsWith("\r") && canonical === line.text.slice(0, -1);
    throw new DataError(crlf ? "not in canonical form: the line ends with a carriage return (CRLF line endings, e.g. from a Windows editor or git core.autocrlf); convert the file back to LF line endings" : "not in canonical form", file, line.lineNumber);
  }
  if (!Number.isSafeInteger(value.index) || (value.index as number) !== line.lineNumber - 1) {
    throw new DataError(`index ${String(value.index)} where ${line.lineNumber - 1} was expected`, file, line.lineNumber);
  }
  return { index: value.index as number, entry: value.entry as WitnessEntry };
}

/**
 * The entry's canonical bytes (its Merkle leaf data), cut out of a line `parseLogLine` accepted. Such a line is exactly
 * `canonicalEncode({ index, entry })`, i.e. `{"entry":` + canonicalEncode(entry) + `,"index":<index>}` (keys in canonical
 * order, no whitespace; the entry nested one level deeper than on its own, so it passed every bound it would face
 * alone), so the slice is byte for byte what `encodeEntry(entry)` returns, without encoding the entry a second time
 * (start-up replays every line; this was a fifth of it). Anything else falls back to encoding the entry.
 */
export function entryBytesOfLine(line: RawLine, record: LogRecord): Uint8Array {
  const text = line.text;
  const suffix = `,"index":${record.index}}`;
  if (text.startsWith(ENTRY_PREFIX) && text.endsWith(suffix)) return UTF8.encode(text.slice(ENTRY_PREFIX.length, text.length - suffix.length));
  return UTF8.encode(canonicalEncode(record.entry));
}
const ENTRY_PREFIX = '{"entry":';

/**
 * The append side of `log.jsonl` plus random access to earlier lines. All
 * appends must be serialized by the caller (the witness holds one mutex).
 */
export class LogFile {
  readonly path: string;
  readonly #offsets: number[] = [];
  readonly #lengths: number[] = [];
  #size = 0;
  #append: FileHandle | undefined;
  #readFd: number | undefined;
  #created: boolean;

  private constructor(path: string, created: boolean) {
    this.path = path;
    this.#created = created;
  }

  /** Opens (creating when missing) and indexes every existing line; `onRecord` sees each parsed line in order. */
  static async open(path: string, onRecord: (record: LogRecord, line: RawLine, log: LogFile) => void, warn: Warn): Promise<LogFile> {
    let created = false;
    try {
      statSync(path);
    } catch (error) {
      if (errnoCode(error) !== "ENOENT") throw error;
      created = true;
    }
    const log = new LogFile(path, created);
    if (!created) log.#readFd = openSync(path, "r");
    let scan: LineScan;
    try {
      scan = scanLines(path, (line) => {
        const record = parseLogLine(line, basename(path));
        log.#offsets.push(line.offset);
        log.#lengths.push(line.length);
        onRecord(record, line, log);
      });
    } catch (error) {
      await log.close();
      throw error;
    }
    if (scan.tornBytes > 0) {
      warn("log.jsonl ends in a torn line (a crash during an append that was never acknowledged); truncating it", { file: path, bytes: scan.tornBytes, keptLines: scan.lines });
      truncateTail(path, scan.validBytes);
    }
    log.#size = scan.validBytes;
    log.#append = await open(path, "a", 0o600);
    if (created) fsyncDir(dirname(path));
    log.#readFd ??= openSync(path, "r");
    return log;
  }

  get count(): number {
    return this.#offsets.length;
  }

  get bytes(): number {
    return this.#size;
  }

  /** Appends one line and fsyncs; on failure the file is cut back to its previous length (and the error rethrown). */
  async append(record: LogRecord): Promise<void> {
    return this.appendAll([record]);
  }

  /**
   * Appends consecutive lines with one write and one fsync (the entries of one decision); on failure the file is cut back
   * to its previous length (and the error rethrown). Nothing is acknowledged before every line is durable.
   */
  async appendAll(records: readonly LogRecord[]): Promise<void> {
    if (this.#append === undefined) throw new Error("log is closed");
    const texts: string[] = [];
    for (const [n, record] of records.entries()) {
      if (record.index !== this.#offsets.length + n) throw new Error(`log append out of order: ${record.index} after ${this.#offsets.length + n} lines`);
      try {
        texts.push(encodeLogLine(record));
      } catch (error) {
        // Not a storage failure: the entry itself cannot be stored exactly (nothing was written).
        throw error instanceof DataError ? error : new DataError(`entry is not canonically encodable: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    const lines = texts.map((text) => UTF8.encode(text));
    const bytes = Buffer.concat(lines);
    const before = this.#size;
    try {
      let written = 0;
      while (written < bytes.length) {
        const { bytesWritten } = await this.#append.write(bytes, written, bytes.length - written);
        written += bytesWritten;
      }
      await this.#append.sync();
      if (this.#created) {
        fsyncDir(dirname(this.path));
        this.#created = false;
      }
    } catch (error) {
      try {
        await this.#append.truncate(before);
        await this.#append.sync();
      } catch {
        // the caller marks the witness failed; the torn tail is cut at the next start
      }
      throw error;
    }
    let offset = before;
    for (const line of lines) {
      this.#offsets.push(offset);
      this.#lengths.push(line.length);
      offset += line.length;
    }
    this.#size = before + bytes.length;
  }

  /** Reads line `index` back from disk. */
  read(index: number): LogRecord {
    if (this.#readFd === undefined) throw new Error("log is closed");
    const offset = this.#offsets[index];
    const length = this.#lengths[index];
    if (offset === undefined || length === undefined) throw new RangeError(`no log line ${index}`);
    const buffer = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const n = readSync(this.#readFd, buffer, read, length - read, offset + read);
      if (n === 0) throw new DataError("log.jsonl is shorter than when it was indexed", LOG_FILE, index + 1);
      read += n;
    }
    if (buffer[length - 1] !== 0x0a) throw new DataError("log line changed on disk", LOG_FILE, index + 1);
    return parseLogLine({ text: STRICT_UTF8.decode(buffer.subarray(0, length - 1)), offset, length, lineNumber: index + 1 });
  }

  async close(): Promise<void> {
    const handle = this.#append;
    this.#append = undefined;
    if (handle !== undefined) await handle.close();
    if (this.#readFd !== undefined) closeSync(this.#readFd);
    this.#readFd = undefined;
  }
}

// ---------------------------------------------------------------- checkpoints.jsonl

export type CheckpointRecord = Readonly<{ note: string; size: number; time: number }>;

export function parseCheckpointLine(line: RawLine): CheckpointRecord {
  let value: unknown;
  try {
    value = JSON.parse(line.text);
  } catch {
    throw new DataError("not JSON", CHECKPOINTS_FILE, line.lineNumber);
  }
  if (!isRecord(value) || Object.keys(value).sort().join(",") !== "note,size,time" || typeof value.note !== "string" ||
    !Number.isSafeInteger(value.size) || !Number.isSafeInteger(value.time)) {
    throw new DataError("a checkpoint line is {note, size, time}", CHECKPOINTS_FILE, line.lineNumber);
  }
  return value as CheckpointRecord;
}

/** Reads every checkpoint line (cutting a torn tail with a warning when `repair`); returns them in order. */
export function readCheckpoints(path: string, warn: Warn, repair: boolean): CheckpointRecord[] {
  const records: CheckpointRecord[] = [];
  const scan = scanLines(path, (line) => records.push(parseCheckpointLine(line)));
  if (scan.tornBytes > 0) {
    warn(`${CHECKPOINTS_FILE} ends in a torn line${repair ? "; truncating it" : ""}`, { file: path, bytes: scan.tornBytes });
    if (repair) truncateTail(path, scan.validBytes);
  }
  return records;
}

export class CheckpointFile {
  readonly #handle: FileHandle;
  #created: boolean;
  readonly #path: string;

  private constructor(path: string, handle: FileHandle, created: boolean) {
    this.#path = path;
    this.#handle = handle;
    this.#created = created;
  }

  static async open(path: string): Promise<CheckpointFile> {
    let created = false;
    try {
      statSync(path);
    } catch (error) {
      if (errnoCode(error) !== "ENOENT") throw error;
      created = true;
    }
    return new CheckpointFile(path, await open(path, "a", 0o600), created);
  }

  async append(record: CheckpointRecord): Promise<void> {
    const bytes = UTF8.encode(`${canonicalEncode(record)}\n`);
    let written = 0;
    while (written < bytes.length) {
      const { bytesWritten } = await this.#handle.write(bytes, written, bytes.length - written);
      written += bytesWritten;
    }
    await this.#handle.sync();
    if (this.#created) {
      fsyncDir(dirname(this.#path));
      this.#created = false;
    }
  }

  async close(): Promise<void> {
    await this.#handle.close();
  }
}

// ---------------------------------------------------------------- server.lock

export type LockHolder = Readonly<{ pid?: unknown; hostname?: unknown; createdAt?: unknown }>;
/** An unreadable lock (a writer that died between creating and filling it) is reclaimed after this long. */
const UNREADABLE_LOCK_STALE_MS = 10_000;

/** Lock paths this process holds right now (a lock naming our own pid is live only if it is one of these). */
const heldLocks = new Set<string>();

/** Same file by device and inode, as bigints (a double rounds a 64-bit NTFS file id, like the core store's lock). */
const sameFile = (a: BigIntStats | undefined, b: BigIntStats | undefined): boolean => a !== undefined && b !== undefined && a.dev === b.dev && a.ino === b.ino;
const BIG = { bigint: true } as const;

type LockView = Readonly<{ vanished: boolean; stale: boolean; info?: BigIntStats; text?: string; holder?: LockHolder }>;

function inspectLock(path: string): LockView {
  const ours = heldLocks.has(path);
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (error) {
    return { vanished: errnoCode(error) === "ENOENT", stale: false };
  }
  let info: BigIntStats, text: string;
  try {
    info = fstatSync(fd, BIG);
    text = readFileSync(fd, "utf8");
  } catch {
    return { vanished: false, stale: false };
  } finally {
    closeSync(fd);
  }
  let holder: LockHolder | undefined;
  try {
    const parsed: unknown = JSON.parse(text);
    holder = isRecord(parsed) ? parsed : undefined;
  } catch {
    holder = undefined;
  }
  if (holder === undefined || typeof holder.pid !== "number") {
    return { vanished: false, stale: Date.now() - Number(info.mtimeMs) > UNREADABLE_LOCK_STALE_MS, info, text };
  }
  const view = (stale: boolean): LockView => ({ vanished: false, stale, info, text, holder });
  if (holder.hostname !== hostname()) return view(false); // liveness is unknowable across hosts
  // Our own pid in a lock we have not taken yet is a previous life of this process slot (e.g. pid 1 in a container).
  if (holder.pid === process.pid) return view(!ours);
  try {
    process.kill(holder.pid, 0);
    return view(false);
  } catch (error) {
    return view(errnoCode(error) === "ESRCH");
  }
}

/** Removes the stale lock `view` saw, race-free (renamed aside, deleted only if it is the very file judged stale), like the core store. */
function reclaimLock(path: string, view: LockView): boolean {
  const aside = `${path}.stale-${process.pid}-${Date.now()}`;
  try {
    renameSync(path, aside);
  } catch (error) {
    return errnoCode(error) === "ENOENT";
  }
  let same = false;
  try {
    const info = statSync(aside, BIG);
    same = sameFile(info, view.info) && info.mtimeNs === view.info!.mtimeNs && readFileSync(aside, "utf8") === view.text; // mtimeNs: the exact field (mtimeMs of a BigIntStats is whole milliseconds)
  } catch {
    same = false;
  }
  if (!same) {
    try { linkSync(aside, path); } catch { /* a newer lock is in place */ }
  }
  try { unlinkSync(aside); } catch { /* best effort */ }
  return same;
}

export type ServerLock = Readonly<{ path: string; release(): void; stillHeld(): boolean }>;

/**
 * Takes `server.lock` for the life of the process. A lock left by a dead
 * process on this host is reclaimed; a live holder, or one on another host
 * (liveness unknowable), is refused unless `force` (the operator has checked).
 */
export function acquireServerLock(dataDir: string, options: Readonly<{ force?: boolean; warn: Warn }>): ServerLock {
  const path = join(dataDir, LOCK_FILE);
  for (let attempt = 0, transient = 0; attempt < 5; attempt += 1) {
    let fd: number;
    try {
      fd = openSync(path, "wx", 0o600);
    } catch (error) {
      // Windows: a lock just released can be delete-pending (EPERM), or held open by a scanner: retried briefly.
      if (isWindowsTransientError(error) && transient < 100) { transient += 1; attempt -= 1; Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20); continue; }
      if (errnoCode(error) !== "EEXIST") throw new DataError(`cannot create the lock: ${error instanceof Error ? error.message : String(error)}`, LOCK_FILE);
      const view = inspectLock(path);
      if (view.vanished) continue;
      if (view.stale || options.force === true) {
        options.warn(view.stale ? "reclaiming a stale server lock" : "overriding the server lock (--force-unlock)", { file: path, holder: view.holder ?? null });
        if (reclaimLock(path, view)) continue;
      }
      const holder = view.holder === undefined ? "" : ` (pid ${String(view.holder.pid)} on ${String(view.holder.hostname)})`;
      throw new DataError(`another witness server holds the lock${holder}; if it is not running, restart with --force-unlock or remove ${path}`, LOCK_FILE);
    }
    try {
      writeSync(fd, JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: Date.now() }));
      fsyncSync(fd);
    } catch (error) {
      closeSync(fd);
      try { unlinkSync(path); } catch { /* best effort */ }
      throw new DataError(`cannot write the lock: ${error instanceof Error ? error.message : String(error)}`, LOCK_FILE);
    }
    const mine = fstatSync(fd, BIG);
    heldLocks.add(path);
    let released = false;
    return Object.freeze({
      path,
      stillHeld: (): boolean => {
        try {
          return !released && sameFile(mine, statSync(path, BIG));
        } catch {
          return false;
        }
      },
      release: (): void => {
        if (released) return;
        released = true;
        heldLocks.delete(path);
        try { closeSync(fd); } catch { /* already closed */ }
        try {
          if (sameFile(mine, statSync(path, BIG))) unlinkSync(path);
        } catch { /* already gone */ }
      },
    });
  }
  throw new DataError("could not take the lock (it kept changing)", LOCK_FILE);
}
