#!/usr/bin/env node
/**
 * Builds a large, realistic format-1 history for the scale benchmarks.
 *
 *   node bench/generate.mjs --events 100000 --out /tmp/it-100k            # owner API only
 *   node bench/generate.mjs --events 1000000 --out /tmp/it-1m --owner-events 20000
 *   node bench/generate.mjs --events 1000000 --out /tmp/it-1m --extend-from /tmp/it-100k
 *
 * The OWNER phase comes first. It writes through the real public API, the way a
 * deployment does: `createLocalOwner` (owner key file, pre-rotation next-key
 * file, attested pinned head, fsync on every write), then per "unit" an agent,
 * a role, an appointment, a runtime session admission, a root grant, a
 * delegation from the previous agent, a ROOT prohibition, a revocation every
 * 4th unit, an epoch advance every 5th, an unappointment every 7th, and every
 * `--job-every` units a job by a long-lived worker runtime: two task grants,
 * `openLocalSimulation().run()` (intent declared, runtime-signed admission,
 * consumption), `recordReceipt()` and `openLocalRuntime().obligate()` (a
 * session-signed duty). Every `--anchor-every` events the head is anchored in
 * the local anchor log (`anchorHead`, `<history>.anchors`).
 *
 * The DIRECT phase comes next (only when `--events` exceeds `--owner-events`):
 * the owner API pays three fsyncs per write and every open handle (owner,
 * simulation, runtime, anchor) re-validates the others' appends, so a million
 * events through it would take hours and four copies of the state in memory.
 * The direct phase continues the SAME file through one `HistoryStore` handle
 * (fsync off, pinned head still attested on every append) with the same unit
 * mix: control events built with the owner API's event shapes and signed with
 * the core's own `signControlEvent`, the owner-API data builders' output
 * reproduced field for field; jobs become an unsigned intent declaration plus a
 * runtime-signed `TRANSACTION_INTENT_ADMITTED` whose proof comes from
 * `authorizeState` (the path the admission coordinator uses); anchors still go
 * through `anchorHead`. Every event is validated by the store on append (full
 * replay rules: signatures, prefix hashes, transitions) and the generator ends
 * with `verifyHistory` on the finished file unless `--no-verify`, so the result
 * is a genuine history, not a synthetic byte stream.
 *
 * Output directory: `history.jsonl` and its side files (`.head`, `.anchors`,
 * `.owner-key.json`, `.owner-next-key.json`, key-event bundle) plus
 * `manifest.json` (counts by type, phases, sizes, timings, the worker runtime
 * key so benchmarks can sign as it). Deterministic ids and clock; the owner
 * keys are fresh per run (as `irontrellis init` makes them).
 */
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { benchRoot, fmtMs, load, parseArgs, peakRss } from "./lib.mjs";

const args = parseArgs(process.argv.slice(2), {
  events: { type: "number", default: 10_000 },
  out: { type: "string", default: undefined },
  "owner-events": { type: "number", default: 200_000 },
  "extend-from": { type: "string", default: undefined },
  "job-every": { type: "number", default: 4 },
  "anchor-every": { type: "number", default: 5_000 },
  root: { type: "string", default: undefined },
  "no-verify": { type: "boolean", default: false },
  "until-limit": { type: "boolean", default: false },
  quiet: { type: "boolean", default: false },
});
if (args.out === undefined) throw new Error("--out <dir> is required");
const ROOT = benchRoot(args.root);
const core = await load(ROOT, "packages/core/dist/index.js");
const internal = await load(ROOT, "packages/core/dist/internal-format1.js"); // A-185.3: the format-1 writer is test tooling
const signerLib = await load(ROOT, "packages/core/dist/signer.js");

const TARGET = args.events;
const OWNER_LIMIT = Math.min(TARGET, args["owner-events"]);
const FAR = 4_000_000_000_000; // expiries/deadlines beyond the scripted clock
const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: "deployment:bench" });
const OWNER = "operations", CONTROLLER = "operator";
const log = (...parts) => { if (!args.quiet) console.error(`[generate ${new Date().toISOString().slice(11, 19)}]`, ...parts); };

mkdirSync(args.out, { recursive: true });
const historyFile = join(args.out, "history.jsonl");
const manifestFile = join(args.out, "manifest.json");

/** Deterministic Ed25519 key pairs (runtime sessions, the worker): seed = 0x5eed…n. */
const runtimeKey = (keyId, n) => {
  const pair = core.keyPairFromPrivateKey("ed25519", keyId, `0x${(0x5eed0000n * 0x100000000n + BigInt(n)).toString(16).padStart(64, "0")}`);
  return { pair, credential: pair.credential, signHash: core.signHashWith(pair), privateKey: pair.privateKey };
};

// ---------------------------------------------------------------- resumable counters (persisted in the manifest)

let manifest;
if (args["extend-from"] !== undefined) {
  // Copy a finished smaller history (same generator) and continue it: saves rebuilding the owner phase.
  const from = args["extend-from"];
  const base = JSON.parse(readFileSync(join(from, "manifest.json"), "utf8"));
  if (existsSync(historyFile)) throw new Error(`${historyFile} exists`);
  for (const name of readdirSync(from)) if (name.startsWith("history.jsonl") || name === "manifest.json") copyFileSync(join(from, name), join(args.out, name));
  manifest = { ...base, extendedFrom: { dir: from, events: base.events } };
  log(`extending ${from} (${base.events} events) to ${TARGET}`);
} else {
  if (existsSync(historyFile)) throw new Error(`${historyFile} exists (use an empty --out directory)`);
  manifest = { version: "irontrellis-bench-history/1", events: 0, unit: 0, job: 0, anchor: 0, id: 0, tick: 1_000, byType: {}, phases: [] };
}
const ids = () => `g:${(manifest.id += 1)}`;
const now = () => manifest.tick;
const worker = runtimeKey("key:worker", 0);
manifest.worker = { agent: "worker", session: "session:worker", role: "desk", tenure: "desk:1", credential: worker.credential, privateKey: worker.privateKey };
manifest.domain = DOMAIN;
manifest.owner = OWNER;
manifest.controller = CONTROLLER;
const config = { historyFile, domain: DOMAIN, owner: OWNER, controller: CONTROLLER, now, ids, format: core.TRELLIS_FORMAT, [internal.FORMAT1_TEST_TOOLING]: true };
// The raw store opens below append to this format-1 file too, so they name the format-1 test writer as well (A-185.3);
// without it the store opens the file read only (FORMAT_READ_ONLY).
const FORMAT1_WRITER = { readOnlyFormats: false, [internal.FORMAT1_TEST_TOOLING]: true };

// ---------------------------------------------------------------- owner phase: the owner API

async function ownerPhase() {
  const started = performance.now();
  const startEvents = manifest.events;
  let owner;
  if (manifest.events === 0) {
    owner = await core.createLocalOwner(config);
    manifest.tick += 1;
  } else {
    owner = core.openLocalOwner(config);
  }
  const count = () => owner.exportHistory().length;
  const step = async (promise) => { const result = await promise; manifest.tick += 1; return result; };
  if (manifest.unit === 0) {
    // The long-lived worker runtime that performs the jobs, and its successor.
    await step(owner.createAgent({ id: "worker" }));
    await step(owner.createAgent({ id: "backup" }));
    await step(owner.createRole({ id: "desk", exclusive: true }));
    await step(owner.declareSuccession({ id: "desk-handover", from: "worker", to: "backup", role: "desk" }));
    await step(owner.appoint({ agent: "worker", role: "desk", tenure: "desk:1", number: 1, succession: "desk-handover" }));
    await step(owner.admitRuntime({ session: "session:worker", agent: "worker", epoch: 1, key: "key:worker", credential: worker.credential, expiresAt: FAR }));
  }
  const ownerKey = signerLib.loadOwnerKeyFile(signerLib.ownerKeyPathFor(historyFile));
  const sim = core.openLocalSimulation({ ...config, session: "session:worker", signHash: worker.signHash });
  const runtime = core.openLocalRuntime({ ...config, session: "session:worker", signHash: worker.signHash });
  const anchorStore = core.openHistoryStore(historyFile, { signer: ownerKey, ...FORMAT1_WRITER });
  let events = count();
  let nextAnchor = (Math.floor(events / args["anchor-every"]) + 1) * args["anchor-every"];
  let lastReport = performance.now();
  while (events < OWNER_LIMIT) {
    const i = manifest.unit;
    const agent = `agent:${i}`, role = `role:${i}`;
    await step(owner.createAgent({ id: agent }));
    await step(owner.createRole({ id: role, exclusive: true }));
    await step(owner.appoint({ agent, role, tenure: `tenure:${i}:1`, number: 1 }));
    await step(owner.admitRuntime({ session: `session:${i}`, agent, epoch: 1, key: `key:${i}`, credential: runtimeKey(`key:${i}`, i + 1).credential, expiresAt: FAR }));
    await step(owner.grant({ id: `root:${i}`, to: agent, actions: ["read", "write"], resources: [`doc:${i}`, "doc:shared"], expiresAt: FAR, delegable: 2 }));
    if (i > 0) await step(owner.delegate({ id: `deleg:${i}`, parent: `root:${i - 1}`, from: `agent:${i - 1}`, to: agent, actions: ["read"], resources: [`doc:${i - 1}`], expiresAt: FAR, delegable: 1 }));
    await step(owner.prohibit({ id: `prohibit:${i}`, root: `root:${i}`, subject: agent, actions: ["write"], resources: ["doc:shared"], expiresAt: FAR }));
    if (i % 4 === 3 && i > 1) await step(owner.revoke(`deleg:${i - 1}`));
    if (i % 5 === 4) await step(owner.advanceEpoch({ agent, from: 1, to: 2 }));
    if (i % 7 === 6) await step(owner.unappoint({ agent: `agent:${i - 1}`, role: `role:${i - 1}`, tenure: `tenure:${i - 1}:1` }));
    if (i % args["job-every"] === 0) {
      const j = (manifest.job += 1);
      await step(owner.grant({ id: `job:${j}`, to: "worker", actions: ["read", "OBLIGATE"], resources: [`doc:job:${j}`], expiresAt: FAR }));
      await step(owner.grant({ id: `review:${j}`, to: "worker", actions: ["record-collection-disposition"], resources: [`duty:${j}`], expiresAt: FAR }));
      const op = { id: `operation:${j}`, action: "read", resource: `doc:job:${j}`, role: "desk", tenure: "desk:1", termsCommitment: core.commitTerms({ job: j }) };
      const run = await step(sim.run(op));
      if (run.invocation?.status !== "SUBMITTED") throw new Error(`job ${j}: run() did not submit: ${JSON.stringify(run).slice(0, 400)}`);
      const receipt = await step(sim.recordReceipt(op));
      if (receipt.recording?.status !== "ADMITTED") throw new Error(`job ${j}: receipt not admitted`);
      await step(runtime.obligate({ id: `duty:${j}`, operation: op.id, description: `Follow up job ${j}.`, deadline: FAR, succession: "desk-handover", reviewAuthority: `review:${j}` }));
    }
    manifest.unit += 1;
    events = count();
    if (events >= nextAnchor && events < OWNER_LIMIT) {
      manifest.anchor += 1;
      await core.anchorHead(anchorStore, ownerKey, core.localAnchorLog(core.anchorsPathFor(historyFile)), { id: `anchor:${manifest.anchor}`, anchoredAt: now() });
      manifest.tick += 1;
      nextAnchor += args["anchor-every"];
      events = count();
    }
    if (performance.now() - lastReport > 15_000) {
      lastReport = performance.now();
      log(`owner phase: ${events} events, ${((events - startEvents) / ((performance.now() - started) / 1000)).toFixed(0)} events/s, rss ${(process.memoryUsage().rss / 1048576).toFixed(0)} MiB`);
    }
  }
  await owner.flush();
  owner.close();
  anchorStore.close();
  manifest.events = events;
  manifest.phases.push({ phase: "owner-api", fromEvents: startEvents, toEvents: events, seconds: (performance.now() - started) / 1000 });
  log(`owner phase done: ${events} events in ${fmtMs(performance.now() - started)}`);
}

// ---------------------------------------------------------------- direct phase: direct appends (same unit mix)

async function directPhase() {
  const started = performance.now();
  const startEvents = manifest.events;
  const ownerKey = signerLib.loadOwnerKeyFile(signerLib.ownerKeyPathFor(historyFile));
  log(`direct phase: opening ${historyFile} (${manifest.events} events)`);
  const store = core.openHistoryStore(historyFile, { signer: ownerKey, fsync: false, ...FORMAT1_WRITER });
  log(`opened in ${fmtMs(performance.now() - started)}`);
  const state = () => store.state();
  const genesis = state().genesis;
  const algorithm = state().hashAlgorithm;
  const event = (type, data) => Object.freeze({ id: `event:${ids()}`, type, timestamp: now(), data });
  const append = (signed) => {
    if (args["until-limit"]) {
      // Stop at the format's file cap: the append that would cross it must be refused whole, leaving the file as it was.
      const before = { size: statSync(historyFile).size, head: store.head() };
      try {
        store.append(signed);
      } catch (error) {
        if (error?.code !== "HISTORY_FILE_LIMIT") throw error;
        const after = { size: statSync(historyFile).size, head: store.head() };
        if (after.size !== before.size || after.head.hash !== before.head.hash) throw new Error("a refused append changed the file");
        throw Object.assign(new Error("limit"), { limitHit: { events: before.head.position + 1, bytes: before.size, cap: core.HISTORY_FILE_LIMITS[core.TRELLIS_FORMAT], refusedEvent: signed.type, message: error.message } });
      }
    } else store.append(signed);
    manifest.tick += 1;
  };
  const control = async (type, data) => append(await core.signControlEvent(ownerKey, event(type, data), DOMAIN, store.head(), algorithm));
  const constraints = (actions, resources, delegable = 0) => ({ actions, resources, quantitative: false, expiresAt: FAR, maxDelegationDepth: delegable, requiredIntersectionIds: [] });
  let events = store.head().position + 1;
  let nextAnchor = (Math.floor(events / args["anchor-every"]) + 1) * args["anchor-every"];
  let lastReport = performance.now();
  const sessions = new Map();
  try {
  while (events < TARGET) {
    const i = manifest.unit;
    const agent = `agent:${i}`, role = `role:${i}`;
    await control("AGENT_CREATED", { agentId: agent, principalId: OWNER, controllerId: CONTROLLER, initialControlEpoch: 1 });
    await control("ROLE_CREATED", { roleId: role, principalId: OWNER, exclusive: true });
    await control("AGENT_APPOINTED", { agentId: agent, roleId: role, roleTenureId: `tenure:${i}:1`, tenureNumber: 1, principalId: OWNER });
    const key = runtimeKey(`key:${i}`, i + 1);
    sessions.set(i, key);
    await control("RUNTIME_SESSION_ADMITTED", { sessionId: `session:${i}`, agentId: agent, controllerId: CONTROLLER, controlEpoch: 1, credentialKeyId: `key:${i}`, credentialScheme: "ed25519", credentialPublicKey: key.credential, expiresAt: FAR });
    await control("AUTHORITY_GRANTED", { grant: { kind: "PERMISSION", authorityId: `root:${i}`, grantorId: OWNER, granteeId: agent, rootAuthorityId: `root:${i}`, independent: true, constraints: constraints(["read", "write"], [`doc:${i}`, "doc:shared"].sort(), 2) } });
    if (i > 0) {
      await control("AUTHORITY_GRANTED", { grant: { kind: "PERMISSION", authorityId: `deleg:${i}`, grantorId: `agent:${i - 1}`, granteeId: agent, rootAuthorityId: `root:${i - 1}`, parentAuthorityId: `root:${i - 1}`, independent: true, constraints: constraints(["read"], [`doc:${i - 1}`], 1) } });
    }
    await control("AUTHORITY_GRANTED", { grant: { kind: "PROHIBITION", scope: "ROOT", authorityId: `prohibit:${i}`, grantorId: OWNER, rootAuthorityId: `root:${i}`, subjectActorId: agent, constraints: constraints(["write"], ["doc:shared"]) } });
    if (i % 4 === 3 && i > 1) await control("AUTHORITY_REVOKED", { authorityId: `deleg:${i - 1}`, revokerId: OWNER });
    if (i % args["job-every"] === 0) {
      // A job by this unit's own runtime session: declared intent, then a runtime-signed admission whose proof the engine derives.
      const j = (manifest.job += 1);
      const intentId = `intent:${j}`, nonce = `nonce:${j}`, termsCommitment = core.commitTerms({ job: j });
      append(event("TRANSACTION_INTENT_DECLARED", {
        intentId, nonce, actorId: agent, action: "read", resource: `doc:${i}`, roleId: role, roleTenureId: `tenure:${i}:1`,
        adapterProfile: core.approvedAdapterProfile(core.SIMULATED_ADAPTER_ID), termsCommitment,
      }));
      const s = state(), clock = now();
      const request = { actorId: agent, action: "read", resource: `doc:${i}`, claimedAt: clock, termsCommitment };
      const binding = { runtimeSessionId: `session:${i}`, credentialKeyId: `key:${i}`, controlEpoch: 1, roleId: role, roleTenureId: `tenure:${i}:1`, intentId, nonce };
      const challenge = core.createRuntimeAuthorizationChallenge({ domain: DOMAIN, request, evaluationTime: clock, policyVersion: genesis.policyVersion, historyHead: s.head, binding });
      const hash = core.hashRuntimeAuthorizationChallenge(challenge, algorithm);
      const runtimeSignature = await key.signHash(hash);
      const result = core.authorizeState(s, {
        expectedHistoryHead: s.head, domain: DOMAIN, policyVersion: genesis.policyVersion, rootRecognitionPolicy: genesis.rootRecognitionPolicy,
        request, evaluationTime: clock, consequential: true, binding: { ...binding, runtimeSignature },
      });
      if (result.decision !== "ALLOW") throw new Error(`job ${j}: authorize ${result.decision} ${result.code}`);
      append(Object.freeze({ id: `event:${ids()}`, type: "TRANSACTION_INTENT_ADMITTED", timestamp: clock,
        data: { intentId, evaluationTime: clock, expectedHistoryHead: s.head, authorizationProof: result.proof, runtimeAuthorizationHash: hash, runtimeSignature } }));
    }
    if (i % 5 === 4) await control("CONTROL_EPOCH_ADVANCED", { agentId: agent, controllerId: CONTROLLER, fromEpoch: 1, toEpoch: 2 });
    if (i % 7 === 6) await control("AGENT_UNAPPOINTED", { agentId: `agent:${i - 1}`, roleId: `role:${i - 1}`, roleTenureId: `tenure:${i - 1}:1`, principalId: OWNER });
    manifest.unit += 1;
    events = store.head().position + 1;
    if (events >= nextAnchor && events < TARGET) {
      manifest.anchor += 1;
      await core.anchorHead(store, ownerKey, core.localAnchorLog(core.anchorsPathFor(historyFile)), { id: `anchor:${manifest.anchor}`, anchoredAt: now() });
      manifest.tick += 1;
      nextAnchor += args["anchor-every"];
      events = store.head().position + 1;
    }
    if (performance.now() - lastReport > 15_000) {
      lastReport = performance.now();
      log(`direct phase: ${events} events, ${((events - startEvents) / ((performance.now() - started) / 1000)).toFixed(0)} events/s, rss ${(process.memoryUsage().rss / 1048576).toFixed(0)} MiB, ${(statSync(historyFile).size / 1048576).toFixed(0)} MiB on disk`);
    }
  }
  } catch (error) {
    if (error?.limitHit === undefined) throw error;
    manifest.limitHit = error.limitHit;
    events = store.head().position + 1;
    log(`HISTORY_FILE_LIMIT at ${events} events, ${error.limitHit.bytes} bytes (cap ${error.limitHit.cap}): ${error.limitHit.message}`);
  }
  await store.flush();
  store.close();
  manifest.events = events;
  manifest.phases.push({ phase: "direct", fromEvents: startEvents, toEvents: events, seconds: (performance.now() - started) / 1000 });
  log(`direct phase done: ${events} events in ${fmtMs(performance.now() - started)}`);
}

// ---------------------------------------------------------------- run

const t0 = performance.now();
if (manifest.events < OWNER_LIMIT) await ownerPhase();
if (manifest.events < TARGET) await directPhase();

// Counts by type (streamed line by line: the file may be larger than a string).
{
  const byType = {};
  const bytes = readFileSync(historyFile);
  let start = 0, lines = 0;
  for (let end = bytes.indexOf(10); end !== -1; end = bytes.indexOf(10, start)) {
    const line = bytes.subarray(start, end);
    const m = /"type":"([A-Z_]+)"/.exec(line.toString("latin1", 0, Math.min(line.length, 4096)).replace(/"event":\{/, ""));
    const type = m?.[1] ?? "?";
    byType[type] = (byType[type] ?? 0) + 1;
    start = end + 1;
    lines += 1;
  }
  manifest.byType = Object.fromEntries(Object.entries(byType).sort(([, a], [, b]) => b - a));
  manifest.lines = lines;
  manifest.bytes = bytes.length;
}
manifest.generatorSeconds = (manifest.generatorSeconds ?? 0) + (performance.now() - t0) / 1000;
manifest.generatorPeakRssMiB = Math.round(peakRss() / 1048576);

if (!args["no-verify"]) {
  // The finished file must be a genuine history: a fresh verifier replays every line (signatures, chain, prefix
  // hashes, transitions), checks the attested pin and the local anchor log.
  const t = performance.now();
  const report = core.verifyHistory(historyFile, {});
  const seconds = (performance.now() - t) / 1000;
  if (!report.ok || report.pinnedHeadStatus !== "MATCHES" || report.rollback) throw new Error(`generated history does not verify: ${JSON.stringify(report).slice(0, 600)}`);
  manifest.verified = { at: new Date().toISOString(), seconds, head: report.head, controlSignatures: report.controlSignatures, pinnedHeadStatus: report.pinnedHeadStatus, anchorLogStatus: report.anchorLogStatus };
  log(`verifyHistory: OK in ${seconds.toFixed(1)} s`);
}
writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
log(`${manifest.events} events, ${(manifest.bytes / 1048576).toFixed(1)} MiB, ${manifest.generatorSeconds.toFixed(0)} s, peak rss ${manifest.generatorPeakRssMiB} MiB -> ${args.out}`);
if (process.env.BENCH_CLEAN_ON_FAIL === "1") process.on("uncaughtException", () => rmSync(args.out, { recursive: true, force: true }));
