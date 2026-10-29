/**
 * Portable file-system helpers (docs/PLATFORMS.md): the few places where
 * Windows semantics differ from POSIX in ways that matter to IronTrellis.
 *
 *  - Replacing a file by rename (`write temp + fsync + rename`) fails on
 *    Windows with EPERM, EACCES or EBUSY while another process holds the
 *    target open without FILE_SHARE_DELETE (an antivirus scanner, a search
 *    indexer, a backup agent, an editor), or while it is delete-pending.
 *    Those failures are transient: `replaceFileSync` retries them with a
 *    bounded backoff on win32 only. On POSIX a rename does not fail that way,
 *    so the same codes are real errors there and are thrown at once.
 *  - Directories cannot be fsynced on Windows (opening one for fsync fails
 *    with EPERM or EISDIR; NTFS journals its metadata itself), so
 *    `syncDirectorySync` skips the step on win32 and nowhere else.
 *  - File modes are synthetic on Windows (a readable file reports 0o666, a
 *    directory 0o777; `chmod` only toggles the read-only bit), so checks that
 *    refuse a group- or world-readable secret cannot mean anything there:
 *    `ownerOnlyModeEnforced` is false on win32, and the operator restricts
 *    the files with NTFS ACLs instead (docs/PLATFORMS.md §3, `icacls`).
 *  - `path.isAbsolute` accepts `\dir\file` on Windows, which is relative to
 *    the current drive; `isFullyQualifiedPath` requires a drive letter or a
 *    UNC prefix there.
 *
 * Every helper reads `process.platform` when it is called (not when the
 * module loads) and takes an explicit `platform`, so the win32 branches are
 * unit-tested on any host.
 */
import { closeSync, fsyncSync, openSync, renameSync } from "node:fs";
import { posix as posixPath, win32 as win32Path } from "node:path";

/** The platform the helpers act for; `process.platform` unless a caller (a test) names another. */
export type PlatformOption = Readonly<{ platform?: NodeJS.Platform }>;

const platformOf = (options?: PlatformOption): NodeJS.Platform => options?.platform ?? process.platform;
const errnoOf = (error: unknown): string | undefined => {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
};
const sleepSync = (ms: number): void => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };

/** The error codes Windows returns while another handle blocks a rename, create or delete (sharing violation, delete pending). */
export const WINDOWS_TRANSIENT_ERROR_CODES: readonly string[] = Object.freeze(["EPERM", "EACCES", "EBUSY"]);

/** True for a transient Windows sharing or delete-pending failure (`WINDOWS_TRANSIENT_ERROR_CODES`) on win32; always false elsewhere. */
export function isWindowsTransientError(error: unknown, options?: PlatformOption): boolean {
  return platformOf(options) === "win32" && WINDOWS_TRANSIENT_ERROR_CODES.includes(errnoOf(error) ?? "");
}

/** How long `replaceFileSync` keeps retrying a transient Windows failure, in total (milliseconds). */
export const REPLACE_RETRY_BUDGET_MS = 3000;

export type ReplaceFileOptions = PlatformOption & Readonly<{
  /** Total time spent waiting between attempts before the last error is thrown (default `REPLACE_RETRY_BUDGET_MS`). */
  budgetMs?: number;
  /** For tests: the rename to call (default `fs.renameSync`) and the wait between attempts (default a blocking sleep). */
  rename?: (from: string, to: string) => void;
  sleep?: (ms: number) => void;
}>;

/**
 * `renameSync(from, to)`, replacing `to` when it exists: the commit step of a
 * write-to-temporary-file-then-rename. On win32, EPERM/EACCES/EBUSY (another
 * handle on `to` or `from`, typically an antivirus or indexer scan) are retried
 * with an exponential backoff (5 ms doubling to 250 ms) for at most `budgetMs`
 * in total, then the last error is thrown. Elsewhere there is exactly one
 * attempt. Returns the number of attempts made.
 */
export function replaceFileSync(from: string, to: string, options: ReplaceFileOptions = {}): number {
  const rename = options.rename ?? renameSync, sleep = options.sleep ?? sleepSync;
  const budget = options.budgetMs ?? REPLACE_RETRY_BUDGET_MS;
  let waited = 0;
  for (let attempt = 1, delay = 5; ; attempt += 1, delay = Math.min(delay * 2, 250)) {
    try {
      rename(from, to);
      return attempt;
    } catch (error) {
      if (!isWindowsTransientError(error, options) || waited >= budget) throw error;
      const pause = Math.min(delay, budget - waited);
      sleep(pause);
      waited += pause;
    }
  }
}

export type SyncDirectoryOptions = PlatformOption & Readonly<{
  /** Swallow every error (the step is an optimisation for that caller); by default errors propagate. */
  bestEffort?: boolean;
}>;

/**
 * fsyncs `directory` so a name created, renamed or removed in it survives a
 * crash. Skipped on win32, where a directory cannot be opened for fsync and
 * NTFS journals directory changes itself. Elsewhere any error propagates
 * unless `bestEffort`. Returns false when it did not sync (win32, or a
 * best-effort failure).
 */
export function syncDirectorySync(directory: string, options: SyncDirectoryOptions = {}): boolean {
  if (platformOf(options) === "win32") return false;
  let fd: number | undefined;
  try {
    fd = openSync(directory, "r");
    fsyncSync(fd);
    return true;
  } catch (error) {
    if (options.bestEffort === true) return false;
    throw error;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* already closed */ }
    }
  }
}

/**
 * Whether POSIX permission bits mean anything here: false on win32, where
 * `stat().mode` is synthesised from the read-only attribute and access is
 * governed by ACLs. Checks that refuse a secret file readable (or a policy
 * file writable) by group or others apply only when this is true; on Windows
 * the operator restricts those files with `icacls` (docs/PLATFORMS.md §3).
 */
export function ownerOnlyModeEnforced(options?: PlatformOption): boolean {
  return platformOf(options) !== "win32";
}

/**
 * An absolute path that does not depend on the current directory or drive.
 * POSIX: `path.posix.isAbsolute`. win32: a drive-letter path (`C:\x`, `C:/x`) or a
 * UNC or device path (`\\server\share\x`, `\\?\C:\x`); `\x` (relative to the
 * current drive) and `C:x` (relative to drive C's current directory) are not.
 */
export function isFullyQualifiedPath(path: string, options?: PlatformOption): boolean {
  if (typeof path !== "string" || path.length === 0) return false;
  if (platformOf(options) !== "win32") return posixPath.isAbsolute(path);
  return /^[A-Za-z]:[\\/]/.test(path) || (/^[\\/]{2}[^\\/]/.test(path) && win32Path.isAbsolute(path));
}
