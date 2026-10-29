/** Installer-selected report custody and dispatch checks. Structural codecs do not qualify node evidence. */
import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { performance } from "node:perf_hooks";
import { anchoringProfileClass, eventHash, historyIdOfGenesis, PRODUCTION_ANCHORING_PROFILE, TEST_PROFILE_LABEL, TEST_TRUSTED_NODE_BARRIER_LABEL, type AnchoringProfileClass, type ContentHash, type ExecutionDispatchContext, type ReplayState } from "@ramex-labs/irontrellis";
import { encodeTrustRoot, decodeCanonicalAnchorVerifyReport, type ProfileTrustRoot, type AnchorVerifyReport, type AnchorVerificationMode } from "./anchor-profile/index.ts";
import { GatewayError, check, codeOf, data, durableCreate, exact, hash, privateDirectory, privateFileBytes, readPrivate, same } from "./data.ts";
import { assertNotStopped, type BarrierEvidence } from "./dispatch-files.ts";

export type ResumeHorizon = Readonly<{ kind: "HEAD_POSITIONS"; limit: number }>;
export type AnchorInstanceObservation = Readonly<{ destination: string; namespaceId: ContentHash; publisher: string; chainId: string; mode: AnchorVerificationMode }>;
/** Privileged host configuration. The report directory is written only by the installer-selected verifyAnchor integration. */
export type LiveAnchoringOptions = Readonly<{
  trustRootBytes: string | Uint8Array;
  reportDirectory: string;
  stopFile: string;
  /** One instance-immutables read at load. Supplying an observation does not authenticate consensus evidence. */
  readInstanceImmutables(request: Readonly<{ destination: string; chainId: string }>): Promise<AnchorInstanceObservation>;
  waitMs?: number;
  pollMs?: number;
  resumeHorizon?: ResumeHorizon;
  resumeUndispatched?: boolean;
  /** A-183.2 (i): a TEST-class profile (Etherlink Shadownet) is opened only with `true`; logged on every open. */
  allowTestProfile?: boolean;
  /**
   * A-195.1: the mode a TEST profile's barrier is measured in. `"TRUSTED_NODE"` is admitted only for a TEST-class profile with
   * `allowTestProfile: true` (where no independently administered validating Shadownet L1 node exists); default `"CONSENSUS_VERIFIED"`.
   */
  testBarrierMode?: "CONSENSUS_VERIFIED" | "TRUSTED_NODE";
}>;
export type SelectedAnchorReport = Readonly<{ report: AnchorVerifyReport; evidence: BarrierEvidence }>;
const bound = (value: unknown, minimum: number, maximum: number): value is number => Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
const TRUST_MODES = new Set(["CONSENSUS_VERIFIED", "TRUSTED_NODE", "UNVERIFIED"]);
/**
 * The production chain, from Core's class table (A-183.1, A-195.2: the table is the one place the literal lives). A TEST
 * profile is opened only by `allowTestProfile` and is never classed PRODUCTION; no caller flag changes a class.
 */
export const LIVE_ANCHOR_CHAIN = PRODUCTION_ANCHORING_PROFILE.chainId;

export async function openAnchorBarrier(options: LiveAnchoringOptions, state: ReplayState, storage: string) {
  let trustRoot: ProfileTrustRoot;
  try { trustRoot = encodeTrustRoot(options.trustRootBytes).value; } catch { throw new GatewayError("TRUST_ROOT_INVALID", false, "T1–T4 profile validation failed"); }
  const manifest = trustRoot.manifest;
  // T6 (A-195.2): the pair is in the class table; then the TEST opt-in (A-183.2 (i)); the class is checked before the
  // barrier mode, so TRUSTED_NODE never reaches a PRODUCTION profile (A-195.1).
  const profileClass: AnchoringProfileClass | undefined = anchoringProfileClass(manifest.chain.id, manifest.id);
  check(profileClass !== undefined, "TRUST_ROOT_INVALID", "T6: (chain.id, profile id) is not a pair of the anchoring class table (A-183.1)");
  check(options.allowTestProfile === undefined || typeof options.allowTestProfile === "boolean", "INVALID_INPUT");
  check(options.testBarrierMode === undefined || options.testBarrierMode === "CONSENSUS_VERIFIED" || options.testBarrierMode === "TRUSTED_NODE", "INVALID_INPUT");
  check(profileClass !== "TEST" || options.allowTestProfile === true, "TRUST_ROOT_INVALID", "TEST_PROFILE_NOT_ALLOWED: a TEST-class profile needs anchoring.allowTestProfile: true (A-183.2)");
  const barrierMode = options.testBarrierMode ?? "CONSENSUS_VERIFIED";
  check(barrierMode === "CONSENSUS_VERIFIED" || profileClass === "TEST", "TRUST_ROOT_INVALID", "TRUSTED_NODE_BARRIER_NOT_ALLOWED: a trusted-node barrier is for a TEST-class profile only (A-195.1)");
  const classLabel = profileClass === "PRODUCTION" ? null : barrierMode === "TRUSTED_NODE" ? TEST_TRUSTED_NODE_BARRIER_LABEL : TEST_PROFILE_LABEL;
  if (profileClass === "TEST") process.stderr.write(`irontrellis-mcp: anchoring.allowTestProfile is set: profile ${manifest.id} on ${manifest.chain.id}, barrier mode ${barrierMode}; ${classLabel} (A-183.2, A-195.1)\n`);
  /**
   * The report and instance-observation modes that satisfy the barrier: CONSENSUS_VERIFIED under the default barrier; under a
   * TEST profile's trusted-node barrier TRUSTED_NODE alone (A-195.1; A-207.1 "(i) alone"). The independence pin is not asked
   * there, so a report claiming CONSENSUS_VERIFIED cannot have been qualified and is not eligible (independent review J77-01).
   */
  const barrierModes: ReadonlySet<string> = new Set(barrierMode === "TRUSTED_NODE" ? ["TRUSTED_NODE"] : ["CONSENSUS_VERIFIED"]);
  check(state.format === "irontrellis-event/2" && same(manifest.domain, state.genesis.domain) &&
    manifest.historyId === historyIdOfGenesis(state.events[0]!) && manifest.genesisEventHash === eventHash(state.events[0]!), "TRUST_ROOT_INVALID", "History identity mismatch");
  // A-150.2 (ii): a consensus-verified barrier needs an independently administered L1 node. A TEST profile runs TRUSTED_NODE
  // exactly where no such node exists (A-183.2 (ii), A-195.1), so the independence pin is not asked of that mode.
  check(barrierMode === "TRUSTED_NODE" || (manifest.nodes.evm.operator !== manifest.nodes.l1.operator &&
    (manifest.nodes.ownRollup === null || manifest.nodes.ownRollup.operator !== manifest.nodes.l1.operator)), "TRUST_ROOT_INVALID", "Independent node administration is required");
  const directory = privateDirectory(options.reportDirectory), stopFile = join(privateDirectory(dirname(options.stopFile)), options.stopFile.split(/[\\/]/).at(-1)!);
  const waitMs = options.waitMs ?? 1000, pollMs = options.pollMs ?? 100;
  check(bound(waitMs, 0, 3_600_000) && bound(pollMs, 1, 60_000));
  check(options.resumeUndispatched === undefined || typeof options.resumeUndispatched === "boolean");
  const resumeUndispatched = options.resumeUndispatched !== false;
  const resumeHorizon = options.resumeHorizon === undefined ? undefined : data<ResumeHorizon>(options.resumeHorizon);
  if (resumeHorizon !== undefined) {
    exact(resumeHorizon, ["kind", "limit"]);
    check(resumeHorizon.kind === "HEAD_POSITIONS" && bound(resumeHorizon.limit, 0, Number.MAX_SAFE_INTEGER));
  }
  check(typeof options.readInstanceImmutables === "function", "TRUST_ROOT_INVALID");
  let observation: AnchorInstanceObservation;
  try { observation = data<AnchorInstanceObservation>(await options.readInstanceImmutables(Object.freeze({ destination: trustRoot.destination, chainId: manifest.chain.id }))); }
  catch { throw new GatewayError("TRUST_ROOT_INVALID", false, "T5 instance observation unavailable"); }
  exact(observation, ["destination", "namespaceId", "publisher", "chainId", "mode"]);
  check(observation.destination === trustRoot.destination && observation.namespaceId === trustRoot.namespaceId &&
    observation.publisher === manifest.publisher && observation.chainId === manifest.chain.id && TRUST_MODES.has(observation.mode), "TRUST_ROOT_INVALID", "T5 instance immutables mismatch");
  // Evidence retains the actual observation and its reported mode, with no upgrade to consensus qualification.
  const observationPath = join(storage, `anchor-instance-${hash(observation).slice(2)}.json`);
  try { durableCreate(observationPath, observation); } catch (error) { if (codeOf(error) !== "EEXIST") throw error; }
  check(same(readPrivate(observationPath), observation), "TRUST_ROOT_INVALID");
  const rootPath = join(directory, "trust-root.json");
  try { readPrivate(rootPath); } catch (error) {
    if (codeOf(error) !== "ENOENT") throw error;
    check(!readdirSync(directory).some((name) => /^[0-9a-f]{64}\.json$/.test(name)), "TRUST_ROOT_INVALID", "A report directory must be bound to its trust root before its first report");
    try { durableCreate(rootPath, trustRoot); } catch (createError) { if (codeOf(createError) !== "EEXIST") throw createError; }
  }
  check(same(readPrivate(rootPath), trustRoot), "TRUST_ROOT_INVALID", "Report directory belongs to a different trust root");
  const seen = new Map<string, ContentHash>();
  const openWaits = new Set<string>(), lastReasons = new Map<string, string>();
  const assertRunning = () => assertNotStopped(stopFile);
  const horizon = (context: ExecutionDispatchContext, current: ReplayState, now: number) => {
    if (!context.resumed || resumeHorizon === undefined) return;
    const elapsed = current.head.position - context.admissionHead.position;
    check(bound(now, 0, Number.MAX_SAFE_INTEGER) && elapsed >= 0 && elapsed <= resumeHorizon.limit, "RESUME_HORIZON");
  };
  /** Reads protected report bytes only. It never calls a node or infers chain finality from a clock. */
  function eligible(context: ExecutionDispatchContext, current: ReplayState, wanted?: ContentHash): SelectedAnchorReport | undefined {
    privateDirectory(directory);
    check(same(readPrivate(rootPath), trustRoot), "TRUST_ROOT_INVALID");
    const names = readdirSync(directory).filter((name) => /^[0-9a-f]{64}\.json$/.test(name)).sort();
    check(names.length <= 4096, "STORAGE_UNAVAILABLE");
    const reports = new Map<ContentHash, AnchorVerifyReport>(), consistent = new Set<ContentHash>();
    for (const name of names) {
      let result;
      try { result = decodeCanonicalAnchorVerifyReport(privateFileBytes(join(directory, name), 131072)); } catch { throw new GatewayError("STORAGE_UNAVAILABLE"); }
      check(name === result.reportDigest.slice(2) + ".json", "STORAGE_UNAVAILABLE");
      check(!seen.has(name) || seen.get(name) === result.reportDigest, "STORAGE_UNAVAILABLE");
      seen.set(name, result.reportDigest);
      reports.set(result.reportDigest, result.claimedReport);
      if (result.claimConsistency.status === "NO_LISTED_CLAIM_CONTRADICTION") consistent.add(result.reportDigest);
    }
    // Once observed, a report's disappearance is an incident, never a way to clear a contradiction.
    check([...seen.keys()].every((name) => reports.has(("0x" + name.slice(0, -5)) as ContentHash)), "STORAGE_UNAVAILABLE");
    let administrationChanged = false;
    const contradicted = new Set<ContentHash>(), first = new Map<ContentHash, AnchorVerifyReport>();
    for (const report of reports.values()) {
      if (report.profileId !== manifest.id || report.chainId !== manifest.chain.id || report.statement.historyId !== manifest.historyId) continue;
      const pins = manifest.nodes, nodes = report.nodes;
      if (nodes.evm.operator !== pins.evm.operator || nodes.l1.operator !== pins.l1.operator ||
        (pins.ownRollup === null ? nodes.ownRollup !== null : nodes.ownRollup === null || nodes.ownRollup.operator !== pins.ownRollup.operator)) administrationChanged = true;
      const previous = report.continuity.previousReportDigest;
      check(previous === null || reports.has(previous), "STORAGE_UNAVAILABLE");
      const prior = first.get(report.statement.digest);
      // A-161.2 with A-181.3 (J77-08): a different block or operation hash for one statement contradicts, and so does a different
      // block time for the same block hash (same l1BlockHash ⇒ same time; a null time, outside CONSENSUS_VERIFIED, states none).
      const blockTimeDiffers = prior !== undefined && prior.finality.l1BlockHash === report.finality.l1BlockHash &&
        prior.finality.l1BlockTime !== null && report.finality.l1BlockTime !== null && prior.finality.l1BlockTime !== report.finality.l1BlockTime;
      if (report.continuity.contradiction || blockTimeDiffers || (prior !== undefined && (prior.finality.l1BlockHash !== report.finality.l1BlockHash || prior.finality.operationHash !== report.finality.operationHash))) contradicted.add(report.statement.digest);
      if (prior === undefined) first.set(report.statement.digest, report);
    }
    const latestL1 = Math.max(0, ...[...reports.values()].filter((r) => r.profileId === manifest.id && r.chainId === manifest.chain.id && r.nodes.l1.operator === manifest.nodes.l1.operator).map((r) => r.nodes.l1.headLevel));
    const candidates = [...reports].filter(([digest, report]) => {
      const nodes = report.nodes, pins = manifest.nodes;
      return !administrationChanged && (wanted === undefined || digest === wanted) && consistent.has(digest) && barrierModes.has(observation.mode) && report.profileId === manifest.id && report.chainId === manifest.chain.id &&
        report.statement.historyId === manifest.historyId && report.statement.head.position >= context.admissionHead.position &&
        current.eventHistoryHashes[report.statement.head.position] === report.statement.head.hash &&
        ["L1_FINAL", "CEMENTED"].includes(report.finality.label) && barrierModes.has(report.finality.mode) &&
        !contradicted.has(report.statement.digest) && nodes.evm.operator === pins.evm.operator && nodes.evm.chainId === pins.evm.chainId &&
        nodes.l1.operator === pins.l1.operator && nodes.l1.chainId === pins.l1.chainId &&
        (pins.ownRollup === null ? nodes.ownRollup === null : nodes.ownRollup !== null && nodes.ownRollup.operator === pins.ownRollup.operator && nodes.ownRollup.chainId === pins.ownRollup.chainId) &&
        (manifest.maxL1HeadLag === null || latestL1 - nodes.l1.headLevel <= manifest.maxL1HeadLag);
    });
    candidates.sort(([a, x], [b, y]) => y.statement.head.position - x.statement.head.position || y.observedAt - x.observedAt || a.localeCompare(b));
    const chosen = candidates[0];
    if (chosen === undefined) return undefined;
    const [reportDigest, report] = chosen;
    return Object.freeze({ report, evidence: Object.freeze({ statementDigest: report.statement.digest, statementHead: report.statement.head,
      profileId: report.profileId, chainId: report.chainId, label: report.finality.label, mode: report.finality.mode, reportDigest }) });
  }
  // J77-10: every barrier record this gateway writes or reads must name the open trust root's pair, and (step 5b review,
  // defence in depth) the open barrier's mode, the only mode eligible() admits (A-195.1, A-207.1).
  const profile = Object.freeze({ profileId: manifest.id, chainId: manifest.chain.id, mode: barrierMode });
  return Object.freeze({ trustRoot, profile, profileClass, barrierMode, classLabel, resumeUndispatched, resumeHorizon, waitMs, assertRunning, horizon, eligible,
    deadline: () => performance.now() + waitMs,
    remember(operationId: string, reason: string) { lastReasons.set(operationId, reason); },
    status(operationId: string) { return { status: openWaits.has(operationId) ? "DELAYED" : "NOT_DISPATCHED", reason: lastReasons.get(operationId) ?? "NOT_STARTED", dispatchPerformed: false,
      resumeHorizon: resumeHorizon ?? null, resumeUndispatched, profileClass, barrierMode, classLabel }; },
    async wait(context: ExecutionDispatchContext, read: () => ReplayState, assertCurrent: () => void, deadline: number, now: () => number): Promise<SelectedAnchorReport | undefined> {
      openWaits.add(context.operationId);
      try {
        for (;;) {
          assertRunning(); assertCurrent(); const current = read(); horizon(context, current, now());
          const selected = eligible(context, current);
          if (selected !== undefined) return selected;
          lastReasons.set(context.operationId, "DELAYED");
          const remaining = deadline - performance.now();
          if (remaining <= 0) return undefined;
          await new Promise<void>((resolve) => setTimeout(resolve, Math.min(pollMs, remaining)));
        }
      } finally { openWaits.delete(context.operationId); }
    },
    timeRemaining(deadline: number) { return performance.now() < deadline; },
  });
}
export type AnchorBarrier = Awaited<ReturnType<typeof openAnchorBarrier>>;
