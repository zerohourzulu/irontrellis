#!/usr/bin/env node
/**
 * conformance/connector — external connector-profile vectors for the gateway's pre-dispatch barrier (A-161 negatives,
 * A-183.2 TEST opt-in, A-195.1 trusted-node barrier). Builder-produced; the independent checker reproduces them. They are
 * not Core vectors: no replay rule, refusal code or frozen suite depends on them.
 *
 * Every vector runs the gateway's own code (packages/mcp-gateway/dist): `openAnchorBarrier` over the pinned format-2
 * history conformance/v2-regenerated/histories/rotation-v2.json, then `eligible` against one report in a private report
 * directory, and, where a report is eligible, `appendBarrier` for the barrier record bytes. Each outcome must equal the
 * hand-written expectation in EXPECT below, so a change of gateway behaviour fails the generator before any byte is written.
 *
 * All inputs are SYNTHETIC: no node, chain, contract or key is contacted or used; node operators and Tezos hashes are
 * placeholders. Two A-161 negatives are listed as not produced (NOT_PRODUCED): they need a connector inclusion check and a
 * report producer, which this release does not build (STEP5-PLAN-01 S5-33, §9 Q7).
 *
 *   node conformance/connector/generate.mjs           # write vectors.json
 *   node conformance/connector/generate.mjs --check   # exit 1 when a fresh generation differs from vectors.json
 */
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const load = (path) => import(pathToFileURL(join(ROOT, path)).href);
const core = await load("packages/core/dist/index.js");
const { deriveNamespace, encodeAnchorVerifyReport } = await load("packages/mcp-gateway/dist/anchor-profile/index.js");
const { openAnchorBarrier } = await load("packages/mcp-gateway/dist/anchor-barrier.js");
const { appendBarrier } = await load("packages/mcp-gateway/dist/dispatch-files.js");
const CHECK = process.argv.includes("--check");
if (!process.argv.slice(2).every((a) => a === "--check")) { console.error("connector: only --check is supported"); process.exit(2); }
const fail = (message) => { console.error(`connector: ${message}`); process.exit(1); };
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = (v) => core.canonicalEncode(v);

// ------------------------------------------------------------------ the pinned history and the shared synthetic values
const HISTORY_REF = "conformance/v2-regenerated/histories/rotation-v2.json";
const historyBytes = readFileSync(join(ROOT, HISTORY_REF));
const replayed = core.replay(JSON.parse(historyBytes.toString("utf8")));
if (replayed.status !== "ACCEPTED") fail(`source history rejected: ${replayed.code}`);
const state = replayed.state, e0 = state.events[0];
const head = { hash: replayed.head.hash, position: replayed.head.position, canonicalTime: replayed.head.canonicalTime };
const { PRODUCTION_ANCHORING_PROFILE: PRODUCTION, TEST_ANCHORING_PROFILE: TEST } = core;
const BLOCK = "BKiHLREqU3JkXfzEDYAkmmfX48gBDtYhMrpA98s7Aq4SzbUAB6M", OPERATION = "oneev3QMfQJd2fEM3zQPdFwwPY1aohkxffttrK8Qrswemnh2nML";
const SENTENCE = "Synthetic offline vector; not a statement of actual chain finality.";
const OPERATION_ID = `mcp:${"ab".repeat(32)}`;

function manifestOf({ chainId, profileId, l1Operator = "synthetic-l1", l1SameAsEvm = false }) {
  const evm = { chainId, operator: "synthetic-evm" };
  return { version: "irontrellis-profile-manifest/1", id: profileId, domain: state.genesis.domain, historyId: core.historyIdOfGenesis(e0), genesisEventHash: core.eventHash(e0),
    chain: { id: chainId }, publisher: `0x${"44".repeat(20)}`, operatorKeys: [{ keyId: "public-test-base-point", scheme: "ed25519", credential: `0x58${"66".repeat(31)}` }],
    // A-207.1: under a TEST profile's trusted-node barrier the l1 pin may name the same node as evm (no independent L1 node exists).
    nodes: { evm, l1: l1SameAsEvm ? { ...evm } : { chainId: "synthetic-tezos", operator: l1Operator }, ownRollup: null }, bodyStore: null, maxL1HeadLag: null, supersedes: null };
}
function trustRootOf(manifest) {
  const n = deriveNamespace(canonical(manifest));
  return { version: "irontrellis-profile-trust-root/1", manifest, manifestHash: n.manifestHash, namespaceId: n.namespaceId, destination: `0x${"55".repeat(20)}` };
}
function reportOf(manifest, finality) {
  return { version: "irontrellis-anchor-verify-report/1", profileId: manifest.id, chainId: manifest.chain.id,
    statement: { digest: `0x${"11".repeat(32)}`, historyId: manifest.historyId, head: { hash: head.hash, position: head.position } },
    tx: { hash: `0x${"22".repeat(32)}`, l2Block: 0, l2BlockHash: "SYNTHETIC" },
    nodes: { evm: { ...manifest.nodes.evm, protocol: "synthetic", softwareCommit: "vector", headLevel: 0 }, l1: { ...manifest.nodes.l1, protocol: "synthetic", softwareCommit: "vector", headLevel: 102 }, ownRollup: null },
    finality: { label: "L1_FINAL", mode: "CONSENSUS_VERIFIED", l1Level: 100, l1BlockHash: BLOCK, l1BlockTime: 1_760_000_000_000, operationHash: OPERATION, refutationResidual: "OPEN", cementedAt: null, ...finality },
    sentence: SENTENCE, observedAt: 0, continuity: { previousReportDigest: null, contradiction: false } };
}
const CV = {}, TN = { mode: "TRUSTED_NODE", l1BlockTime: null };

// ------------------------------------------------------------------ the vectors and their expectations
const PREFIX = "connector/etherlink/";
const VECTORS = [
  { id: "l1-final-consensus-verified", rulings: ["A-161", "A-150.1"], pair: PRODUCTION, options: {}, observed: "CONSENSUS_VERIFIED", finality: CV },
  { id: "trusted-node-not-final", rulings: ["A-161", "A-150.1"], pair: PRODUCTION, options: {}, observed: "CONSENSUS_VERIFIED", finality: TN },
  { id: "same-administration-nodes", rulings: ["A-161", "A-150.2"], pair: PRODUCTION, l1Operator: "synthetic-evm", options: {}, observed: "CONSENSUS_VERIFIED", finality: CV },
  { id: "shadownet-chain-refused", rulings: ["A-161", "A-183.1"], pair: { chainId: TEST.chainId, profileId: PRODUCTION.profileId }, options: { allowTestProfile: true }, observed: "CONSENSUS_VERIFIED", finality: CV },
  { id: "test-profile-refused-without-opt-in", rulings: ["A-183.2"], pair: TEST, options: {}, observed: "CONSENSUS_VERIFIED", finality: CV },
  { id: "test-profile-accepted-with-opt-in", rulings: ["A-183.2"], pair: TEST, options: { allowTestProfile: true }, observed: "CONSENSUS_VERIFIED", finality: CV },
  { id: "test-profile-trusted-node-barrier-eligible", rulings: ["A-195.1", "A-207.1"], pair: TEST, l1SameAsEvm: true, options: { allowTestProfile: true, testBarrierMode: "TRUSTED_NODE" }, observed: "TRUSTED_NODE", finality: TN },
  { id: "test-profile-trusted-node-barrier-refuses-consensus-claim", rulings: ["A-195.1", "A-207.1"], pair: TEST, l1SameAsEvm: true, options: { allowTestProfile: true, testBarrierMode: "TRUSTED_NODE" }, observed: "TRUSTED_NODE", finality: CV },
  { id: "production-profile-trusted-node-barrier-refused", rulings: ["A-195.1"], pair: PRODUCTION, options: { allowTestProfile: true, testBarrierMode: "TRUSTED_NODE" }, observed: "TRUSTED_NODE", finality: TN },
];
const opened = (profileClass, barrierMode, classLabel, eligible, evidenceMode) => ({ open: "OPENED", profileClass, barrierMode, classLabel, eligible, ...(eligible ? { evidenceMode } : {}) });
const refused = (reason) => ({ open: "TRUST_ROOT_INVALID", reason });
const EXPECT = {
  "l1-final-consensus-verified": opened("PRODUCTION", "CONSENSUS_VERIFIED", null, true, "CONSENSUS_VERIFIED"),
  "trusted-node-not-final": opened("PRODUCTION", "CONSENSUS_VERIFIED", null, false),
  "same-administration-nodes": refused(null),
  "shadownet-chain-refused": refused("T6"),
  "test-profile-refused-without-opt-in": refused("TEST_PROFILE_NOT_ALLOWED"),
  "test-profile-accepted-with-opt-in": opened("TEST", "CONSENSUS_VERIFIED", core.TEST_PROFILE_LABEL, true, "CONSENSUS_VERIFIED"),
  "test-profile-trusted-node-barrier-eligible": opened("TEST", "TRUSTED_NODE", core.TEST_TRUSTED_NODE_BARRIER_LABEL, true, "TRUSTED_NODE"),
  "test-profile-trusted-node-barrier-refuses-consensus-claim": opened("TEST", "TRUSTED_NODE", core.TEST_TRUSTED_NODE_BARRIER_LABEL, false),
  "production-profile-trusted-node-barrier-refused": refused("TRUSTED_NODE_BARRIER_NOT_ALLOWED"),
};
const NOT_PRODUCED = [
  { id: `${PREFIX}substring-not-inclusion`, rulings: ["A-161"], reason: "needs the connector's inclusion check (statement bytes found as a substring of calldata are not inclusion); no connector producer is built in this release" },
  { id: `${PREFIX}cemented-by-elapsed-time-refused`, rulings: ["A-161", "A-150.0"], reason: "needs a report producer that could infer CEMENTED from elapsed time; the gateway only reads reports and no producer is built in this release" },
];

// ------------------------------------------------------------------ run one vector through the gateway
async function run(v) {
  const manifest = manifestOf({ ...v.pair, l1Operator: v.l1Operator, l1SameAsEvm: v.l1SameAsEvm }), root = trustRootOf(manifest), report = reportOf(manifest, v.finality);
  const encoded = encodeAnchorVerifyReport(canonical(report));
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-connector-vector-")));
  const writeStderr = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => (/allowTestProfile/.test(String(chunk)) ? true : writeStderr.call(process.stderr, chunk, ...rest)); // the per-open TEST log line
  try {
    const reports = join(dir, "reports"), storage = join(dir, "storage"), stop = join(dir, "stop");
    for (const d of [reports, storage, stop]) mkdirSync(d, { mode: 0o700 });
    const options = { trustRootBytes: canonical(root), reportDirectory: reports, stopFile: join(stop, "stop.json"), waitMs: 0, pollMs: 1, ...v.options,
      async readInstanceImmutables() { return { destination: root.destination, namespaceId: root.namespaceId, publisher: manifest.publisher, chainId: manifest.chain.id, mode: v.observed }; } };
    let barrier;
    try { barrier = await openAnchorBarrier(options, state, storage); }
    catch (error) {
      if (error?.code !== "TRUST_ROOT_INVALID") throw error;
      const reason = /^([A-Z0-9_]+):/.exec(error.detail ?? "")?.[1] ?? null;
      return { report, encoded, root, outcome: { open: "TRUST_ROOT_INVALID", reason }, detail: error.detail ?? null };
    }
    writeFileSync(join(reports, `${encoded.reportDigest.slice(2)}.json`), encoded.canonicalText, { mode: 0o600, flag: "wx" });
    const context = { operationId: OPERATION_ID, intentId: OPERATION_ID, admissionEventId: "synthetic-admission", admissionHead: head, submissionIdentity: null, resumed: false };
    const selected = barrier.eligible(context, state);
    const outcome = { open: "OPENED", profileClass: barrier.profileClass, barrierMode: barrier.barrierMode, classLabel: barrier.classLabel, eligible: selected !== undefined,
      ...(selected === undefined ? {} : { evidenceMode: selected.evidence.mode }) };
    const record = selected === undefined ? undefined : appendBarrier(storage, context, selected.evidence);
    return { report, encoded, root, outcome, record };
  } finally {
    process.stderr.write = writeStderr;
    rmSync(dir, { recursive: true, force: true });
  }
}

// ------------------------------------------------------------------ generate, compare with EXPECT, write or check
const vectors = [];
for (const v of VECTORS) {
  const r = await run(v);
  if (JSON.stringify(r.outcome) !== JSON.stringify(EXPECT[v.id])) fail(`${PREFIX}${v.id}: gateway gave ${JSON.stringify(r.outcome)}, expected ${JSON.stringify(EXPECT[v.id])}${r.detail ? ` (${r.detail})` : ""}`);
  const reportBytes = Buffer.from(r.encoded.canonicalText, "utf8");
  vectors.push({
    id: `${PREFIX}${v.id}`, rulings: v.rulings,
    input: { trustRoot: r.root, options: v.options, instanceObservationMode: v.observed, report: r.report },
    derived: { manifestHash: r.root.manifestHash, namespaceId: r.root.namespaceId, profileClass: core.anchoringProfileClass(v.pair.chainId, v.pair.profileId) ?? null,
      report: { canonicalHex: reportBytes.toString("hex"), bytes: reportBytes.length, reportDigest: r.encoded.reportDigest, sha256: `0x${sha(reportBytes)}` },
      ...(r.record === undefined ? {} : { barrierRecord: { canonicalHex: Buffer.from(canonical(r.record)).toString("hex"), digest: core.hashCanonical(r.record, "sha256") } }) },
    expect: EXPECT[v.id],
  });
}
// The report digest is hashCanonical(report): recompute it with node:crypto over the recorded bytes.
for (const v of vectors) if (v.derived.report.reportDigest !== v.derived.report.sha256) fail(`${v.id}: reportDigest is not sha256 of the canonical bytes`);
const out = {
  version: "irontrellis-connector-vectors/1",
  scope: "SYNTHETIC_GATEWAY_BARRIER_VECTORS",
  note: "Synthetic inputs over a pinned history. Not chain evidence, not node qualification, not a live-anchoring claim; a TEST-class result supports no production claim (A-183.2 (iv)).",
  source: { history: HISTORY_REF, sha256: sha(historyBytes), head },
  classTable: core.ANCHORING_PROFILE_CLASSES,
  operationId: OPERATION_ID,
  vectors,
  notProduced: NOT_PRODUCED,
};
const bytes = Buffer.from(`${JSON.stringify(out, null, 2)}\n`, "utf8"), target = join(HERE, "vectors.json");
if (CHECK) {
  let current;
  try { current = readFileSync(target); } catch { fail("vectors.json is missing"); }
  if (!current.equals(bytes)) fail("vectors.json differs from a fresh generation");
  console.log(`connector: ok (${vectors.length} vectors, ${NOT_PRODUCED.length} not produced; vectors.json sha256 ${sha(bytes)})`);
} else {
  writeFileSync(target, bytes);
  console.log(`connector: wrote vectors.json (${vectors.length} vectors, ${NOT_PRODUCED.length} not produced; sha256 ${sha(bytes)})`);
}
