/**
 * Where the hook keeps its state, and how it writes private files.
 *
 * Default layout (`irontrellis-hook init` without `--history`): everything the
 * owner controls lives OUTSIDE the project, in
 *
 *   ~/.irontrellis/projects/<first 16 hex of sha256(project path)>/   (0700)
 *     history.jsonl                  the signed history (+ .head, .writer-lock, .anchors)
 *     history.jsonl.owner-key.json   the owner key (0600)
 *     history.jsonl.sessions/<sha256(host session id)>.json    session keys (0600)
 *     history.jsonl.handovers/<sha256(host session id)>.json   handover records (0600)
 *
 * The project keeps only `irontrellis-hook.json`, which records the history
 * path. Everything else shares the history path as a prefix, so an explicit
 * `--history` moves all of it, and one prefix check covers it.
 */
import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, readlinkSync, openSync, readFileSync, renameSync, unlinkSync, writeSync, realpathSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { replaceFileSync } from "@ramex-labs/irontrellis/platform";

/** Base of the per-user state (`~/.irontrellis`); `IRONTRELLIS_HOME` overrides it for `init` only. */
export const STATE_HOME_ENV = "IRONTRELLIS_HOME";
export const defaultStateHome = (env: Readonly<Record<string, string | undefined>> = {}): string => {
  const fromEnv = env[STATE_HOME_ENV];
  return fromEnv !== undefined && fromEnv !== "" ? resolve(fromEnv) : join(homedir(), ".irontrellis");
};

/** The per-user record of each unconfigured project's install-route choice (route.ts): `<state home>/route-choices.json`. */
export const CHOICE_FILE_NAME = "route-choices.json";
export const choiceFile = (env: Readonly<Record<string, string | undefined>> = {}): string => join(defaultStateHome(env), CHOICE_FILE_NAME);
/**
 * The plugin's runtime pin (`irontrellis-hook pin-runtime`, and every init): two lines, the absolute node and the realpath
 * of this package's launcher, which the plugin's launch.sh runs instead of looking anything up on PATH.
 */
export const RUNTIME_PIN_NAME = "plugin-runtime";
export const runtimePinFile = (env: Readonly<Record<string, string | undefined>> = {}): string => join(defaultStateHome(env), RUNTIME_PIN_NAME);
export function readRuntimePin(env: Readonly<Record<string, string | undefined>> = {}): Readonly<{ node: string; launcher: string }> | undefined {
  let text: string;
  try { text = readFileSync(runtimePinFile(env), "utf8"); } catch { return undefined; }
  const [node, launcher] = text.split("\n");
  return node !== undefined && launcher !== undefined && isAbsolute(node) && isAbsolute(launcher) ? { node, launcher } : undefined;
}
/** Per host session, the route a session was admitted under (route.ts): a config that vanishes later is refused, not "undecided". */
export const routeSessionFile = (env: Readonly<Record<string, string | undefined>>, hostSessionId: string): string => join(defaultStateHome(env), "route-sessions", sessionFileName(hostSessionId));

export const sha256Hex = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

/** The canonical spelling of a project path (symlinks resolved when the directory exists). */
export const canonicalProject = (project: string): string => {
  const abs = resolve(project);
  try { return realpathSync(abs); } catch { return abs; }
};

/** `<stateHome>/projects/<first 16 hex of sha256(project path)>`. */
export const defaultStateDir = (project: string, stateHome: string): string =>
  join(stateHome, "projects", sha256Hex(canonicalProject(project)).slice(0, 16));

export const DEFAULT_HISTORY_NAME = "history.jsonl";
export const ownerKeyPath = (history: string): string => `${history}.owner-key.json`;
export const sessionsDir = (history: string): string => `${history}.sessions`;
/** The hook's own connector session key (docs/API.md §2: agent `hooks:<host>`, admitted by init under the owner key). */
export const connectorKeyFile = (history: string): string => `${history}.connector.json`;
export const CONNECTOR_KEY_VERSION = "irontrellis-hook-connector-key/1";
export const handoversDir = (history: string): string => `${history}.handovers`;
/** File name for a host session id: sha256 hex, so distinct ids never collide and no path character survives. */
export const sessionFileName = (hostSessionId: string): string => `${sha256Hex(hostSessionId)}.json`;

export class PrivateFileError extends Error {
  readonly code = "PRIVATE_FILE_REFUSED" as const;
  constructor(message: string) { super(message); this.name = "PrivateFileError"; }
}

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

/** Create `dir` (and parents) with mode 0700 and refuse it when it is a symlink or not a directory. */
export function ensurePrivateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new PrivateFileError(`${dir} is not a plain directory (symlink or file); refusing to write into it`);
}

/**
 * Write a private file (0600) without following symlinks: the text goes to a
 * fresh temporary file opened with O_CREAT|O_EXCL|O_NOFOLLOW ("wx"), which is
 * then renamed over `path` (on Windows the rename retries the sharing
 * violations of a scanner or a concurrent reader: platform.ts in the core).
 * An existing `path` that is a symlink or not a
 * regular file is refused rather than replaced.
 */
export function writePrivateFile(path: string, text: string): void {
  ensurePrivateDir(dirname(path));
  let existing;
  try { existing = lstatSync(path); } catch { existing = undefined; }
  if (existing !== undefined && (existing.isSymbolicLink() || !existing.isFile())) throw new PrivateFileError(`${path} is a symlink or not a regular file; refusing to write it`);
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW, 0o600);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } catch (error) {
    closeSync(fd);
    try { unlinkSync(tmp); } catch { /* best effort */ }
    throw error;
  }
  closeSync(fd);
  try {
    replaceFileSync(tmp, path);
  } catch (error) {
    try { unlinkSync(tmp); } catch { /* best effort */ }
    throw error;
  }
}

/**
 * Run `run` holding an exclusive lock file (created with O_EXCL, 0600; removed afterwards). Two copies of the guard running
 * the same event (the plugin and the settings hook, or the hook installed twice) serialize on it. `waitMs` 0: when the lock
 * is held, `run` is skipped and `held` returned (the other copy is doing the same work). A lock older than `staleMs` is from
 * a process that died and is taken over by rename: the copy whose rename moves the stale lock (checked by its token) takes it
 * over; one that finds it moved a fresh lock instead puts it back (link, never overwriting). The lock is removed at the end
 * only while it still holds this copy's token. A copy that runs past `staleMs` can still lose its lock to a takeover.
 */
export async function withLockFile<T, H>(lockPath: string, run: () => Promise<T> | T, options: Readonly<{ waitMs: number; staleMs?: number; held?: () => H }>): Promise<T | H> {
  ensurePrivateDir(dirname(lockPath));
  const deadline = Date.now() + options.waitMs, staleMs = options.staleMs ?? 30_000;
  const token = `${process.pid} ${randomBytes(8).toString("hex")}\n`;
  const readToken = (file: string): string | undefined => { try { return readFileSync(file, "utf8"); } catch { return undefined; } };
  for (;;) {
    try {
      const fd = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW, 0o600);
      try { writeSync(fd, token); } finally { closeSync(fd); }
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      let age: number | undefined;
      try { age = Date.now() - lstatSync(lockPath).mtimeMs; } catch { continue; } // released meanwhile: try again
      if (age > staleMs) {
        const seen = readToken(lockPath), aside = `${lockPath}.stale.${randomBytes(8).toString("hex")}`;
        try { renameSync(lockPath, aside); } catch { continue; } // another copy moved it first
        if (readToken(aside) !== seen) { try { linkSync(aside, lockPath); } catch { /* a newer lock exists: leave it */ } }
        try { unlinkSync(aside); } catch { /* best effort */ }
        continue;
      }
      if (Date.now() >= deadline) {
        if (options.held !== undefined) return options.held();
        throw new PrivateFileError(`timed out waiting for ${lockPath} (another copy of the hook holds it)`);
      }
      await new Promise((r) => setTimeout(r, 20));
    }
  }
  try { return await run(); } finally { if (readToken(lockPath) === token) { try { unlinkSync(lockPath); } catch { /* best effort */ } } }
}

/**
 * Read a settings or config file only when it is a regular file (through symlinks, so a dotfile manager's link is fine): it
 * is opened non-blocking and checked with fstat, so a FIFO or a device planted in its place is refused instead of hanging
 * the hook. Throws the open error (ENOENT, EACCES, …) or NOT_A_REGULAR_FILE / TOO_LARGE.
 */
export function readRegularFile(path: string, limit = 4_194_304): string {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw Object.assign(new Error(`${path} is not a regular file`), { code: "NOT_A_REGULAR_FILE" });
    if (st.size > limit) throw Object.assign(new Error(`${path} is larger than ${limit} bytes`), { code: "TOO_LARGE" });
    return readFileSync(fd, "utf8");
  } finally { closeSync(fd); }
}

/** Read a small private JSON file; undefined when absent, a symlink, not a regular file, too large or not JSON. */
export function readPrivateJson(path: string, limit = 65_536): unknown {
  let st;
  try { st = lstatSync(path); } catch { return undefined; }
  if (st.isSymbolicLink() || !st.isFile() || st.size > limit) return undefined;
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | O_NOFOLLOW); } catch { return undefined; }
  try { return JSON.parse(readFileSync(fd, "utf8")); } catch { return undefined; } finally { closeSync(fd); }
}

/** Remove a private file if it is a regular file; symlinks and anything else are left alone. */
export function removePrivateFile(path: string): boolean {
  let st;
  try { st = lstatSync(path); } catch { return false; }
  if (!st.isFile()) return false;
  try { unlinkSync(path); return true; } catch { return false; }
}

/**
 * Where the file system takes `raw` (relative to `base`): its components walked in order, each symlink followed before the
 * next `..` is applied, as the kernel resolves a path (independent review A, RA-01: `link/../x` with `link` a symlink is the
 * x beside the link's target, not the x beside the link, which a lexical `resolve` gives). A missing component is taken as
 * written. At most 40 links are followed; past that, and on win32 (where the system collapses `..` before it looks at the
 * file system), the lexical path through `realpathLoose`.
 */
export function physicalPath(raw: string, base: string): string {
  if (process.platform === "win32") return realpathLoose(resolve(base, raw));
  // Joined as text, not with join/resolve: those collapse `..` lexically, which is the mistake this function avoids.
  const input = isAbsolute(raw) ? raw : `${resolve(base)}/${raw}`;
  const queue = input.split("/").filter((s) => s !== "");
  let cur = "/", links = 0;
  while (queue.length > 0) {
    const segment = queue.shift()!;
    if (segment === ".") continue;
    if (segment === "..") { cur = dirname(cur); continue; }
    const next = cur === "/" ? `/${segment}` : `${cur}/${segment}`;
    let link: string | undefined;
    try { if (lstatSync(next).isSymbolicLink()) link = readlinkSync(next); } catch { /* missing: taken as written */ }
    if (link !== undefined) {
      if ((links += 1) > 40) return realpathLoose(resolve(base, raw));
      if (isAbsolute(link)) cur = "/";
      queue.unshift(...link.split("/").filter((s) => s !== ""));
      continue;
    }
    cur = next;
  }
  return realpathLoose(cur);
}

/**
 * The real path of `p`, resolving symlinks in the longest existing prefix (the rest is appended as is). On win32 the
 * native resolver is used, which also expands 8.3 short names (`C:\\PROJEC~1\\IRONTR~1` → `…\\.irontrellis`): the
 * JavaScript `realpathSync` leaves them as written, so a short name would slip past the protected-path check. A dangling
 * symlink is followed to where it points (a write through it creates its target), at most 40 links deep.
 */
export function realpathLoose(p: string): string {
  const abs = resolve(p);
  const real = process.platform === "win32" ? realpathSync.native : realpathSync;
  let head = abs, links = 0;
  const tail: string[] = [];
  for (;;) {
    if (existsSync(head)) {
      try { return tail.length === 0 ? real(head) : join(real(head), ...tail.reverse()); } catch { return abs; }
    }
    try {
      if (links < 40 && lstatSync(head).isSymbolicLink()) { head = resolve(dirname(head), readlinkSync(head)); links += 1; continue; }
    } catch { /* not there at all */ }
    const parent = dirname(head);
    if (parent === head) return abs;
    tail.push(basename(head));
    head = parent;
  }
}
