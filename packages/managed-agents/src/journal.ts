/** Operational restart/cursor state only. Native Core is the sole findings ledger. */
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { captureData } from "@ramex-labs/irontrellis/adapter";
import { parseStrictJson } from "./strict-json.mjs";
export type Entry = {
  digest: string;
  phase: "BOUND" | "PREPARED" | "DISPATCHED" | "RESULT";
  resultDigest?: `0x${string}`;
};
export type JournalState = {
  version: "irontrellis-adapter-recovery/2";
  binding: string;
  calls: Record<string, Entry>;
  cursors: Record<string, string>;
};
const LIMIT = 4_194_304;
const plain = (v: unknown): v is Record<string, unknown> =>
  !!v &&
  typeof v === "object" &&
  !Array.isArray(v) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(v));
const keys = (
  v: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
) =>
  required.every((k) => Object.hasOwn(v, k)) &&
  Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
const hash = (v: unknown) =>
  typeof v === "string" && /^0x[0-9a-f]{64}$/.test(v);
function privateMode(stat: Stats) {
  if (
    process.platform !== "win32" &&
    ((Number(stat.mode) & 0o077) !== 0 || stat.uid !== process.getuid?.())
  )
    throw Error("JOURNAL_PERMISSIONS");
}
export class RecoveryJournal {
  readonly path: string;
  constructor(
    path: string,
    readonly binding: string,
    initialize = false,
  ) {
    this.path = resolve(path);
    this.directory();
    if (initialize)
      this.lock(() => {
        if (existsSync(this.path)) throw Error("JOURNAL_EXISTS");
        this.save({
          version: "irontrellis-adapter-recovery/2",
          binding,
          calls: {},
          cursors: {},
        });
      });
    this.read();
  }
  private directory() {
    const parent = dirname(this.path),
      stat = lstatSync(parent);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      realpathSync(parent) !== parent
    )
      throw Error("JOURNAL_DIRECTORY");
    privateMode(stat);
  }
  private lock<T>(fn: () => T): T {
    this.directory();
    const lock = this.path + ".lock";
    mkdirSync(lock, { mode: 0o700 });
    try {
      return fn();
    } finally {
      rmSync(lock, { recursive: true });
    }
  }
  read(): JournalState {
    this.directory();
    const fd = openSync(
      this.path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    let bytes: Buffer;
    try {
      const before = fstatSync(fd);
      if (!before.isFile() || before.size > LIMIT)
        throw Error("JOURNAL_SIZE_OR_TYPE");
      privateMode(before);
      bytes = Buffer.alloc(Number(before.size));
      let at = 0;
      while (at < bytes.length) {
        const n = readSync(fd, bytes, at, bytes.length - at, at);
        if (n === 0) throw Error("JOURNAL_TRUNCATED");
        at += n;
      }
      if (fstatSync(fd).size !== before.size) throw Error("JOURNAL_CHANGED");
    } finally {
      closeSync(fd);
    }
    const raw = captureData(
      parseStrictJson(bytes, {
        maxBytes: LIMIT,
        maxNodes: 100_000,
        maxDepth: 16,
      }),
      LIMIT,
      100_000,
      16,
    );
    if (
      !plain(raw) ||
      !keys(raw, ["version", "binding", "calls", "cursors"]) ||
      raw.version !== "irontrellis-adapter-recovery/2" ||
      raw.binding !== this.binding ||
      !plain(raw.calls) ||
      !plain(raw.cursors)
    )
      throw Error("JOURNAL_INVALID");
    for (const [k, e] of Object.entries(raw.calls))
      if (
        !hash(k) ||
        !plain(e) ||
        !keys(e, ["digest", "phase"], ["resultDigest"]) ||
        !hash(e.digest) ||
        !["BOUND", "PREPARED", "DISPATCHED", "RESULT"].includes(
          e.phase as string,
        ) ||
        (e.phase === "RESULT"
          ? !hash(e.resultDigest)
          : Object.hasOwn(e, "resultDigest"))
      )
        throw Error("JOURNAL_INVALID");
    for (const [k, v] of Object.entries(raw.cursors))
      if (typeof v !== "string" || v.length < 1 || v.length > 512 || !hash(k))
        throw Error("JOURNAL_INVALID");
    return raw as JournalState;
  }
  private save(state: JournalState) {
    if(Object.keys(state.calls).length>256||Object.keys(state.cursors).length>256)throw Error("JOURNAL_CAPACITY");
    captureData(state, LIMIT, 100000, 16);
    const body = JSON.stringify(state);
    if (Buffer.byteLength(body) > LIMIT) throw Error("JOURNAL_SIZE");
    const temp = this.path + "." + randomUUID();
    const fd = openSync(temp, "wx", 0o600);
    try {
      writeFileSync(fd, body);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temp, this.path);
    const dir = openSync(dirname(this.path), "r");
    try {
      fsyncSync(dir);
    } finally {
      closeSync(dir);
    }
  }
  retainSource(digest: string, bytes: Buffer): string {
    this.read();
    if (
      !hash(digest) ||
      bytes.length > 131072 ||
      "0x" + createHash("sha256").update(bytes).digest("hex") !== digest
    )
      throw Error("SOURCE_DIGEST");
    const directory = this.path + ".sources";
    try {
      mkdirSync(directory, { mode: 0o700 });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw Error("SOURCE_DIRECTORY");
    privateMode(stat);
    const path = directory + "/" + digest.slice(2) + ".canonical.json";
    if (existsSync(path)) {
      const fd = openSync(
        path,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
      );
      try {
        const st = fstatSync(fd);
        if (!st.isFile() || st.size !== bytes.length)
          throw Error("SOURCE_CONFLICT");
        privateMode(st);
        const existing = Buffer.alloc(bytes.length);
        let at = 0;
        while (at < existing.length) {
          const n = readSync(fd, existing, at, existing.length - at, at);
          if (!n) throw Error("SOURCE_TRUNCATED");
          at += n;
        }
        if (!existing.equals(bytes)) throw Error("SOURCE_CONFLICT");
      } finally {
        closeSync(fd);
      }
    } else {
      if (readdirSync(directory).length >= 4096) throw Error("SOURCE_LIMIT");
      const fd = openSync(path, "wx", 0o600);
      try {
        writeFileSync(fd, bytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    }
    const fd = openSync(directory, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    const parent = openSync(dirname(directory), "r");
    try {
      fsyncSync(parent);
    } finally {
      closeSync(parent);
    }
    return path;
  }
  update<T>(fn: (state: JournalState) => T): T {
    return this.lock(() => {
      const state = JSON.parse(JSON.stringify(this.read())) as JournalState;
      const answer = fn(state);
      this.save(state);
      return answer;
    });
  }
}
