/**
 * Bounded refusal recording for hooks and the gateway (addendum A-38 as modified by G2; A-68).
 *
 * Verdict first: the caller has its decision before any write. Recording a refusal waits about `refusals.recordBudgetMs`
 * (default 250 ms), shared with any drain before it, and not as a hard real-time bound: synchronous file work (reading and
 * rewriting the spool, a side-log line, the write in progress) is not interrupted. If the signed write has not finished
 * by then, the refusal input is appended
 * to a local append-only spool file beside the history (`<history>.refusals.spool`, engine-private, deletable) and the
 * result reports `{recorded: false, reason: "SPOOLED"}`; if the spool cannot be written, `RECORD_DEADLINE`. The write
 * that was too slow keeps running with the same `refusalId` (A-37.2 derived before the race), so a drain of an entry it
 * already recorded is an idempotent no-op, never a second refusal.
 *
 * Draining (A-38.2): the next refusal that a hook process or the gateway records through the actor's own session drains
 * the spool first, and the runtime's `drainRefusals()` drains it on request; an allowed call does not (KNOWN-ISSUES 70). Each entry
 * is recorded as a new refusal at the head then current, re-derived there (A-12.3): `request.claimedAt` is the drain
 * time (A-68: never the original attempt time, which goes to the side log `<history>.refusals.log`, surfaced by
 * `inspect`). An entry whose re-derivation is ALLOW is dropped with `NOT_REPRODUCED_AT_DRAIN` (never a thrown
 * REFUSAL_NOT_REPRODUCED); A-23's coalescing and rate limit apply at drain time. An entry of another actor is left in
 * the spool: a drain by a process that does not hold the actor's session would record it in the CONNECTOR shape
 * (A-38 (i)); that drainer is not built (KNOWN-ISSUES).
 */
import { appendFileSync, closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { IronTrellisError } from "./input.ts";
import type { RefusalInput, RefusalResult } from "./session-writes.ts";

export const REFUSAL_SPOOL_VERSION = "irontrellis-refusal-spool/1";
export const refusalSpoolPathFor = (historyPath: string): string => `${historyPath}.refusals.spool`;
export const refusalSideLogPathFor = (historyPath: string): string => `${historyPath}.refusals.log`;
/** The engine's read-only inspection of the spool (A-179.4, A-196): how many refusal inputs wait in it (torn lines not counted). */
export function spooledRefusalCount(historyPath: string): number {
  let text: string;
  try { text = readFileSync(refusalSpoolPathFor(historyPath), "utf8"); } catch { return 0; }
  return text.split("\n").filter((line) => { try { return (JSON.parse(line) as { version?: unknown })?.version === REFUSAL_SPOOL_VERSION; } catch { return false; } }).length;
}

/** One spooled refusal input (the request without its time) and when it was attempted. */
export type SpoolEntry = Readonly<{
  version: typeof REFUSAL_SPOOL_VERSION; refusalId: string; attemptedAt: number;
  request: Readonly<Omit<RefusalInput["request"], "claimedAt">>; source?: "CORE" | "BUDGET";
}>;
type Writes = Readonly<{ recordRefusal: (input: RefusalInput) => Promise<RefusalResult> }>;

const appendLine = (path: string, value: unknown): void => appendLines(path, [value]);
/** One append and one fsync for all of `values` (a drain puts its kept entries back in one write, not one per entry). */
const appendLines = (path: string, values: readonly unknown[]): void => {
  const fd = openSync(path, "a", 0o600);
  try { appendFileSync(fd, values.map((value) => `${JSON.stringify(value)}\n`).join("")); fsyncSync(fd); } finally { closeSync(fd); }
};

/**
 * A-38.1: waits for `attempt` at most `budgetMs`; past it the entry is spooled (`SPOOLED`) or, when the spool cannot be
 * written, `RECORD_DEADLINE`. The attempt itself is never cancelled (its result is the same refusal id).
 */
export async function boundedRefusal(historyPath: string, attempt: Promise<RefusalResult>, entry: SpoolEntry, budgetMs: number): Promise<RefusalResult> {
  let timer: NodeJS.Timeout | undefined;
  // A budget of 0 never waits (the write still runs and names the same refusal id).
  const deadline = budgetMs <= 0 ? Promise.resolve("DEADLINE" as const) : new Promise<"DEADLINE">((resolve) => { timer = setTimeout(() => resolve("DEADLINE"), budgetMs); });
  attempt.catch(() => undefined); // a late failure of the abandoned write is the drain's to repair
  try {
    const first = await Promise.race([attempt, deadline]);
    if (first !== "DEADLINE") return first;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  try { appendLine(refusalSpoolPathFor(historyPath), entry); } catch { return Object.freeze({ recorded: false as const, reason: "RECORD_DEADLINE" }); }
  return Object.freeze({ recorded: false as const, reason: "SPOOLED" });
}

/** A drained entry's write that outlasted the drain's deadline (it keeps running; the entry stays spooled). */
const OUTLASTED: unique symbol = Symbol("outlasted");
const withinDeadline = <T>(attempt: Promise<T>, ms: number): Promise<T | typeof OUTLASTED> => {
  attempt.catch(() => undefined);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<typeof OUTLASTED>((resolve) => { timer = setTimeout(() => resolve(OUTLASTED), Math.max(0, ms)); });
  return Promise.race([attempt, late]).finally(() => clearTimeout(timer));
};
export type DrainOutcome = Readonly<{ refusalId: string; outcome: "RECORDED" | "ALREADY_RECORDED" | "NOT_REPRODUCED_AT_DRAIN" | "KEPT" | string }>;
/**
 * A-38.2 / A-68: drains the spool through `writes` (a handle of `actorId`'s session) at `now`. The spool is claimed by an
 * atomic rename first, so two drainers never record one entry twice; entries of other actors and entries whose write
 * failed for another reason go back into the spool. Returns what happened to each entry.
 */
/** Filled in by a drain with a deadline: whether the deadline cut it short, and whether a write it started is still running. */
export type DrainReport = { deadlineReached: boolean; writeStillRunning: boolean };
export async function drainRefusalSpool(historyPath: string, writes: Writes, actorId: string, now: () => number, known: (refusalId: string) => boolean,
  options: Readonly<{ deadlineMs?: number; report?: DrainReport }> = {}): Promise<readonly DrainOutcome[]> {
  // A-38.1: a drain run before a bounded caller's own refusal (a hook, a gateway call) shares that caller's budget: past
  // the deadline no entry is started (checked again just before each write), and an entry whose write outlasts it stays
  // spooled (the write keeps running with the same refusalId, so a later drain finds it ALREADY_RECORDED). `report` says
  // so, and the caller's own refusal then waits no further: it is spooled at once, while its write may still start or
  // continue alongside that one (a later drain finds it ALREADY_RECORDED if it lands). An explicit drain
  // passes no deadline. Not a hard real-time bound: reading the claimed spool, a side-log line, putting the kept entries
  // back, and the write in progress are synchronous work the deadline does not interrupt.
  const deadline = options.deadlineMs === undefined ? undefined : performance.now() + Math.max(0, options.deadlineMs);
  const remaining = (): number => deadline === undefined ? Number.POSITIVE_INFINITY : deadline - performance.now();
  const spool = refusalSpoolPathFor(historyPath), claimed = `${spool}.${process.pid}.${randomBytes(4).toString("hex")}.draining`;
  try { renameSync(spool, claimed); } catch { return []; }
  let text: string;
  try { text = readFileSync(claimed, "utf8"); } catch { return []; }
  const outcomes: DrainOutcome[] = [], kept: SpoolEntry[] = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let entry: SpoolEntry;
    try { entry = JSON.parse(line) as SpoolEntry; } catch { continue; } // a torn last line was never acknowledged as SPOOLED
    if (entry?.version !== REFUSAL_SPOOL_VERSION || typeof entry.refusalId !== "string" || entry.request?.actorId === undefined) continue;
    if (entry.request.actorId !== actorId) { kept.push(entry); outcomes.push({ refusalId: entry.refusalId, outcome: "KEPT" }); continue; }
    const pastDeadline = (): boolean => {
      if (remaining() > 0) return false;
      if (options.report !== undefined) options.report.deadlineReached = true;
      kept.push(entry); outcomes.push({ refusalId: entry.refusalId, outcome: "KEPT" });
      return true;
    };
    if (pastDeadline()) continue;
    if (known(entry.refusalId)) { outcomes.push({ refusalId: entry.refusalId, outcome: "ALREADY_RECORDED" }); continue; }
    const drainedAt = now();
    if (pastDeadline()) continue; // known() and now() take time too: checked again just before the write starts
    let outcome: string;
    try {
      const write = writes.recordRefusal({ refusalId: entry.refusalId, request: { ...entry.request, claimedAt: drainedAt }, ...(entry.source === undefined ? {} : { source: entry.source }) });
      const result = deadline === undefined ? await write : await withinDeadline(write, remaining());
      if (result === OUTLASTED) {
        if (options.report !== undefined) { options.report.deadlineReached = true; options.report.writeStillRunning = true; }
        kept.push(entry); outcomes.push({ refusalId: entry.refusalId, outcome: "KEPT" }); continue;
      }
      outcome = "recorded" in result && result.recorded === false ? result.reason : "RECORDED";
      // A-179.4: past the session time horizon the entry stays spooled until an owner event moves ownerTime.
      if (outcome === "SESSION_TIME_HORIZON") { kept.push(entry); outcomes.push({ refusalId: entry.refusalId, outcome }); continue; }
    } catch (error) {
      if (error instanceof IronTrellisError && error.code === "REFUSAL_NOT_REPRODUCED") outcome = "NOT_REPRODUCED_AT_DRAIN";
      else { kept.push(entry); outcomes.push({ refusalId: entry.refusalId, outcome: "KEPT" }); continue; }
    }
    outcomes.push({ refusalId: entry.refusalId, outcome });
    // A-68: the original attempt time is kept here, never in request.claimedAt.
    try { appendLine(refusalSideLogPathFor(historyPath), { version: REFUSAL_SPOOL_VERSION, refusalId: entry.refusalId, attemptedAt: entry.attemptedAt, drainedAt, outcome }); } catch { /* the side log is best effort */ }
  }
  let restored = true;
  if (kept.length > 0) { try { appendLines(spool, kept); } catch { restored = false; } }
  // The claimed file is removed only once every kept entry is back in the spool (else the next drainer finds it here).
  if (restored) { try { unlinkSync(claimed); } catch { /* left behind: harmless */ } }
  return Object.freeze(outcomes);
}
