/** Private application records for A-163/A-168. Never Core history events or replay inputs. */
import { lstatSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { anchoringProfileClass, type ContentHash, type ExecutionDispatchContext, type HistoryHead } from "@ramex-labs/irontrellis";
import { GatewayError, check, codeOf, data, durableCreate, exact, hash, privateDirectory, readPrivate, same, type HashAlgorithm, type Json } from "./data.ts";

export type DispatchPaths = Readonly<{ attempt: string; report: string; barrier: string }>;
const stem = (operationId: string): string => {
  check(/^mcp(?:-call)?:[0-9a-f]{64}$/.test(operationId), "ADMISSION_MISMATCH");
  return operationId.slice(operationId.indexOf(":") + 1);
};
export function dispatchPaths(storage: string, operationId: string): DispatchPaths {
  const name = stem(operationId);
  return { attempt: join(storage, name + ".attempt.json"), report: join(storage, name + ".report.json"), barrier: join(storage, name + ".barrier.json") };
}
/** Only ENOENT under an intact private storage directory proves absence; links and malformed files count as present. */
export function dispatchStarted(path: string): boolean {
  privateDirectory(dirname(path));
  try { lstatSync(path); return true; } catch (error) { if (codeOf(error) === "ENOENT") return false; throw error; }
}
/** Presence is a stop, including malformed or linked content. The host alone controls the parent directory. */
export function assertNotStopped(path: string): void { check(!dispatchStarted(path), "STOPPED"); }

export type CapturedDispatchRequest = Readonly<{
  version: "irontrellis-mcp-dispatch-request/1"; operationId: string; termsCommitment: ContentHash;
  role: string; tenure: string; upstream: string; terms: Json;
}>;
/** Capture by committed terms before admission. Unadmitted orphan candidates cannot authorize a call. */
export function retainDispatchRequest(storage: string, input: Omit<CapturedDispatchRequest, "version" | "termsCommitment">, algorithm: HashAlgorithm): CapturedDispatchRequest {
  const termsCommitment = hash(input.terms, algorithm), record = data<CapturedDispatchRequest>({ version: "irontrellis-mcp-dispatch-request/1", ...input, termsCommitment });
  const path = join(storage, `${stem(input.operationId)}.request-${termsCommitment.slice(2)}.json`);
  try { durableCreate(path, record); } catch (error) { if (codeOf(error) !== "EEXIST") throw error; }
  const retained = readPrivate<CapturedDispatchRequest>(path);
  check(same(retained, record), "ADMISSION_MISMATCH");
  return data<CapturedDispatchRequest>(retained);
}
export function readDispatchRequest(storage: string, operationId: string, termsCommitment: ContentHash, algorithm: HashAlgorithm): CapturedDispatchRequest {
  check(/^0x[0-9a-f]{64}$/.test(termsCommitment), "ADMISSION_MISMATCH");
  const value = data<CapturedDispatchRequest>(readPrivate(join(storage, `${stem(operationId)}.request-${termsCommitment.slice(2)}.json`)));
  exact(value, ["version", "operationId", "termsCommitment", "role", "tenure", "upstream", "terms"]);
  check(value.version === "irontrellis-mcp-dispatch-request/1" && value.operationId === operationId && value.termsCommitment === termsCommitment && hash(value.terms, algorithm) === termsCommitment, "ADMISSION_MISMATCH");
  check([value.role, value.tenure, value.upstream].every((v) => typeof v === "string" && v.length > 0), "ADMISSION_MISMATCH");
  return value;
}

export type BarrierRecord = Readonly<{
  version: "irontrellis-mcp-barrier/1"; operationId: string; admissionHead: HistoryHead;
  statementDigest: ContentHash; statementHead: Readonly<{ hash: ContentHash; position: number }>;
  profileId: string; chainId: string; label: string; mode: string; reportDigest: ContentHash;
  resumed: boolean; barrierSeq: number; previousBarrierDigest: ContentHash | null;
}>;
export type BarrierEvidence = Pick<BarrierRecord, "statementDigest" | "statementHead" | "profileId" | "chainId" | "label" | "mode" | "reportDigest">;
const isHash = (v: unknown): v is ContentHash => typeof v === "string" && /^0x[0-9a-f]{64}$/.test(v);
const u53 = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
/** The profile pair a barrier record must name, the open trust root's (independent review J77-10), and the open barrier's mode (step 5b review). */
export type BarrierProfile = Readonly<{ profileId: string; chainId: string; mode: "CONSENSUS_VERIFIED" | "TRUSTED_NODE" }>;
function validateBarrier(r: BarrierRecord, context: ExecutionDispatchContext, index: number, previousDigest: ContentHash | null, expected?: BarrierProfile): void {
    exact(r, ["version", "operationId", "admissionHead", "statementDigest", "statementHead", "profileId", "chainId", "label", "mode", "reportDigest", "resumed", "barrierSeq", "previousBarrierDigest"]);
    exact(r.admissionHead, ["hash", "position", "canonicalTime"]); exact(r.statementHead, ["hash", "position"]);
    check(r.version === "irontrellis-mcp-barrier/1" && r.operationId === context.operationId && same(r.admissionHead, context.admissionHead) &&
      r.barrierSeq === index && r.previousBarrierDigest === previousDigest &&
      typeof r.resumed === "boolean" && (index === 0 || r.resumed) &&
      isHash(r.statementDigest) && isHash(r.reportDigest) && isHash(r.statementHead.hash) && u53(r.statementHead.position) &&
      r.statementHead.position >= context.admissionHead.position && typeof r.profileId === "string" && r.profileId.length > 0 &&
      typeof r.chainId === "string" && r.chainId.length > 0 && ["L1_FINAL", "CEMENTED"].includes(r.label) &&
      // A-195.1: a TRUSTED_NODE barrier exists only for a TEST-class pair (the record's own chain and profile, Core's table).
      (r.mode === "CONSENSUS_VERIFIED" || (r.mode === "TRUSTED_NODE" && anchoringProfileClass(r.chainId, r.profileId) === "TEST")), "ADMISSION_MISMATCH");
    check(expected === undefined || (r.profileId === expected.profileId && r.chainId === expected.chainId && r.mode === expected.mode), "ADMISSION_MISMATCH");
}
/** Validate the whole contiguous chain; no first-gap shortcut can hide a later barrier record. */
function readBarrierChainUnsafe(storage: string, context: ExecutionDispatchContext, expected?: BarrierProfile): readonly BarrierRecord[] {
  privateDirectory(storage);
  const name = stem(context.operationId), first = name + ".barrier.json", prefix = name + ".barrier-";
  const indices: Array<{ index: number; path: string }> = [];
  for (const entry of readdirSync(storage)) {
    if (entry === first) indices.push({ index: 0, path: join(storage, entry) });
    else if (entry.startsWith(prefix) && entry.endsWith(".json")) {
      const suffix = entry.slice(prefix.length, -5);
      check(/^[1-9][0-9]*$/.test(suffix) && u53(Number(suffix)), "ADMISSION_MISMATCH");
      indices.push({ index: Number(suffix), path: join(storage, entry) });
    }
  }
  indices.sort((a, b) => a.index - b.index);
  const records: BarrierRecord[] = [];
  for (const [index, entry] of indices.entries()) {
    check(entry.index === index, "ADMISSION_MISMATCH");
    const r = data<BarrierRecord>(readPrivate(entry.path));
    validateBarrier(r, context, index, index === 0 ? null : hash(records[index - 1]), expected);
    records.push(r);
  }
  return Object.freeze(records);
}
export function readBarrierChain(storage: string, context: ExecutionDispatchContext, expected?: BarrierProfile): readonly BarrierRecord[] {
  try { return readBarrierChainUnsafe(storage, context, expected); } catch { throw new GatewayError("ADMISSION_MISMATCH"); }
}
/** Caller holds the history writer lock. A-168 never appends after any dispatch-start file exists. */
export function appendBarrier(storage: string, context: ExecutionDispatchContext, evidence: BarrierEvidence, expected?: BarrierProfile): BarrierRecord {
  const paths = dispatchPaths(storage, context.operationId);
  check(!dispatchStarted(paths.attempt), "DISPATCH_STARTED");
  const chain = readBarrierChain(storage, context, expected), barrierSeq = chain.length;
  check(barrierSeq === 0 || context.resumed, "ADMISSION_MISMATCH");
  const next = data<BarrierRecord>({ version: "irontrellis-mcp-barrier/1", operationId: context.operationId, admissionHead: context.admissionHead,
    ...evidence, resumed: context.resumed, barrierSeq, previousBarrierDigest: barrierSeq === 0 ? null : hash(chain[barrierSeq - 1]) });
  try { validateBarrier(next, context, barrierSeq, barrierSeq === 0 ? null : hash(chain[barrierSeq - 1]), expected); } catch { throw new GatewayError("ADMISSION_MISMATCH"); }
  durableCreate(barrierSeq === 0 ? paths.barrier : join(storage, `${stem(context.operationId)}.barrier-${barrierSeq}.json`), next);
  return next;
}
