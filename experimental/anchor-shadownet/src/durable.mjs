// Run records written so that a crash leaves either no record or the whole record (J-03, kill i=90; the post-send revision
// list, items 1 and 2). The old way opened the final name and then wrote, so a kill between the two left an empty file and
// every resume stopped on it. Now the bytes go to a temporary name, are synced, and are linked to the final name, which
// link() never replaces; then the temporary name goes and the directory is synced. A crash before the link leaves only a
// dot-named .tmp file, which no reader looks at.
import { openSync, writeSync, fsyncSync, closeSync, linkSync, unlinkSync, existsSync, statSync, mkdirSync, readFileSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { randomBytes } from "node:crypto";

function syncDirectory(directory) { const fd = openSync(directory, "r"); try { fsyncSync(fd); } finally { closeSync(fd); } }

/** Writes `text` as the record at `path`, once. Throws EEXIST if a record is already there; never replaces one. */
export function writeRecord(path, text) {
  const bytes = Buffer.from(text, "utf8");
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(temporary, "wx", 0o600);
  try { for (let at = 0; at < bytes.length;) at += writeSync(fd, bytes, at); fsyncSync(fd); } finally { closeSync(fd); }
  try { linkSync(temporary, path); } finally { unlinkSync(temporary); }
  syncDirectory(dirname(path));
}

/** A temporary file of writeRecord's, which readers of a directory skip. */
export const isTemporary = name => name.startsWith(".") && name.endsWith(".tmp");

/** Reads a record; an empty or cut-off one stops with TORN_RECORD and the recovery procedure's name, not a bare parse error. */
export function readRecord(path) {
  const text = readFileSync(path, "utf8");
  try { return JSON.parse(text); }
  catch { throw Object.assign(Error(`TORN_RECORD ${path}: ${text.length === 0 ? "empty" : "not complete JSON"}; stop, follow TORN-JOURNAL-RECOVERY-01 (an older tool's write was cut off)`), { code: "TORN_RECORD" }); }
}

/**
 * An empty record left by an older tool, at a step whose emptiness proves the next step never ran (the caller decides
 * that; only intents and reservations, which are written before anything is signed). It is moved, never deleted, to
 * <directory>/../torn/<name>.torn-<UTC>; true if it was moved.
 */
export function setAsideIfEmpty(path) {
  if (!existsSync(path) || statSync(path).size !== 0) return false;
  const aside = join(dirname(path), "..", "torn");
  mkdirSync(aside, { recursive: true, mode: 0o700 });
  linkSync(path, join(aside, `${basename(path)}.torn-${new Date().toISOString().replace(/[-:.]/g, "")}-${randomBytes(3).toString("hex")}`));
  unlinkSync(path);
  syncDirectory(aside); syncDirectory(dirname(path));
  return true;
}
