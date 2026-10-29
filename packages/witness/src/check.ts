/**
 * `irontrellis-witness check-log`: an offline audit of a witness data
 * directory (or a copy of its two log files). Replays `log.jsonl` under the
 * acceptance rules with every owner signature and rotation authorization
 * re-verified, recomputes the Merkle tree, and checks every checkpoint in
 * `checkpoints.jsonl` against the witness verifier key and the recomputed
 * roots. Read-only: it never truncates or locks anything.
 */
import { closeSync, openSync, readSync } from "node:fs";
import { join } from "node:path";
import { MerkleTree, encodeBase64, entryLeafHash, openNote, parseCheckpoint } from "@ramex-labs/irontrellis/transparency";
import type { WitnessEntry } from "@ramex-labs/irontrellis/transparency";
import { CHECKPOINTS_FILE, DataError, LOG_FILE, parseCheckpointLine, parseLogLine, scanLines, type CheckpointRecord } from "./log.ts";
import { applyEntry, emptyState } from "./state.ts";

export type CheckProblem = Readonly<{ file: string; line?: number; message: string }>;
export type CheckReport = Readonly<{
  ok: boolean;
  entries: number;
  histories: number;
  /** Histories with at least one recorded equivocation (evidence only, docs/reference/witness-operations.md). */
  equivocatingHistories: number;
  kinds: Readonly<Record<string, number>>;
  root: string;
  checkpoints: number;
  lastCheckpointSize: number | null;
  problems: readonly CheckProblem[];
  warnings: readonly string[];
}>;

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

export function checkLog(dataDir: string, trust: Readonly<{ verifierKey: string; origin: string }>): CheckReport {
  const problems: CheckProblem[] = [];
  const warnings: string[] = [];
  const state = emptyState();
  const tree = new MerkleTree();
  const logPath = join(dataDir, LOG_FILE);
  const offsets: number[] = [];
  const lengths: number[] = [];
  let fd: number | undefined;
  try {
    fd = openSync(logPath, "r");
  } catch {
    fd = undefined;
    warnings.push(`${LOG_FILE} does not exist (an empty log)`);
  }
  const lookup = (index: number): WitnessEntry => {
    const offset = offsets[index];
    const length = lengths[index];
    if (fd === undefined || offset === undefined || length === undefined) throw new RangeError(`no line ${index}`);
    const buffer = Buffer.alloc(length);
    readSync(fd, buffer, 0, length, offset);
    return parseLogLine({ text: STRICT_UTF8.decode(buffer.subarray(0, length - 1)), offset, length, lineNumber: index + 1 }).entry;
  };
  try {
    if (fd !== undefined) {
      const scan = scanLines(logPath, (line) => {
        if (problems.length > 0) return;
        try {
          const record = parseLogLine(line);
          offsets.push(line.offset);
          lengths.push(line.length);
          const problem = applyEntry(state, record.entry, record.index, { verify: true, lookup });
          if (problem !== null) throw new DataError(problem, LOG_FILE, line.lineNumber);
          tree.append(entryLeafHash(record.entry));
        } catch (error) {
          problems.push(error instanceof DataError ? { file: error.file ?? LOG_FILE, ...(error.line === undefined ? {} : { line: error.line }), message: error.message }
            : { file: LOG_FILE, line: line.lineNumber, message: error instanceof Error ? error.message : String(error) });
        }
      });
      if (scan.tornBytes > 0) warnings.push(`${LOG_FILE} ends in a torn line of ${scan.tornBytes} bytes (never acknowledged; the server cuts it at start-up)`);
    }
  } catch (error) {
    problems.push({ file: LOG_FILE, message: error instanceof Error ? error.message : String(error) });
  } finally {
    if (fd !== undefined) closeSync(fd);
  }

  const records: CheckpointRecord[] = [];
  let checkpointLine = 0;
  try {
    const scan = scanLines(join(dataDir, CHECKPOINTS_FILE), (line) => {
      checkpointLine = line.lineNumber;
      try {
        records.push(parseCheckpointLine(line));
      } catch (error) {
        problems.push({ file: CHECKPOINTS_FILE, line: line.lineNumber, message: error instanceof Error ? error.message : String(error) });
      }
    });
    if (scan.tornBytes > 0) warnings.push(`${CHECKPOINTS_FILE} ends in a torn line of ${scan.tornBytes} bytes`);
  } catch (error) {
    problems.push({ file: CHECKPOINTS_FILE, line: checkpointLine + 1, message: error instanceof Error ? error.message : String(error) });
  }
  const logComplete = !problems.some((problem) => problem.file === LOG_FILE);
  let previousSize = -1;
  records.forEach((record, index) => {
    const line = index + 1;
    const fail = (message: string): void => {
      problems.push({ file: CHECKPOINTS_FILE, line, message });
    };
    let size: number;
    let root: Uint8Array;
    try {
      const checkpoint = parseCheckpoint(openNote(record.note, [trust.verifierKey]).body);
      if (checkpoint.origin !== trust.origin) return fail(`origin ${JSON.stringify(checkpoint.origin)} is not ${JSON.stringify(trust.origin)}`);
      size = checkpoint.size;
      root = checkpoint.root;
    } catch (error) {
      return fail(`the note does not verify with the witness key: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (size !== record.size) return fail("the recorded size differs from the note");
    if (size < previousSize) fail(`size ${size} is below the previous checkpoint's ${previousSize}`);
    previousSize = Math.max(previousSize, size);
    if (size > tree.size) {
      if (logComplete) fail(`the checkpoint covers ${size} entries but ${LOG_FILE} has ${tree.size}: acknowledged entries are missing`);
      return undefined;
    }
    if (encodeBase64(tree.root(size)) !== encodeBase64(root)) fail(`the root of size ${size} does not match the root recomputed from ${LOG_FILE}`);
    return undefined;
  });
  if (records.length === 0) warnings.push(`${CHECKPOINTS_FILE} has no checkpoints`);
  else if ((records.at(-1) as CheckpointRecord).size < tree.size) warnings.push(`the last checkpoint covers ${(records.at(-1) as CheckpointRecord).size} of ${tree.size} entries (the server signs one at start-up)`);

  return Object.freeze({
    ok: problems.length === 0,
    entries: tree.size,
    histories: state.histories.size,
    equivocatingHistories: state.equivocatingHistories,
    kinds: { ...state.kinds },
    root: encodeBase64(tree.root()),
    checkpoints: records.length,
    lastCheckpointSize: records.at(-1)?.size ?? null,
    problems,
    warnings,
  });
}
