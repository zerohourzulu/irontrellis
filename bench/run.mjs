#!/usr/bin/env node
/**
 * Scale and performance benchmarks (docs/PERFORMANCE.md).
 *
 *   node bench/run.mjs --quick                         # CI regression check: small history, generous budgets, < 60 s
 *   node bench/run.mjs --histories DIR --sizes 10k,100k,1m [--runs 3] [--out results.json]
 *   node bench/run.mjs --histories DIR --sizes 100k --only open,verify,queries
 *
 * `--histories DIR` holds one directory per size, as written by
 * `node bench/generate.mjs --events N --out DIR/<size>` (see docs/PERFORMANCE.md
 * for the exact commands). Every measurement runs in a fresh child process (so
 * peak RSS is that measurement's own, and no JIT or cache state carries over),
 * `--runs` times (default 3); the table shows the median over runs, and for
 * latency distributions the median of each run's p50 / p99 / mean.
 *
 * Measurements ("tasks"):
 *   open        openHistoryStore (full replay: every line parsed, record and prefix hashes, every signature, every
 *               transition), then store.verify() on the open handle; heap and peak RSS
 *   verify      verifyHistory (a fresh open + verify, what `irontrellis verify` does)
 *   queries     through openLocalOwner: authorize (first and warm), observe, why, responsible, survives
 *   append      on a copy: store.append with fsync off and on, owner grant() (Ed25519 signature, fsync, attested pin)
 *   witness     owner grant() on a fresh history bound to a real irontrellis-witness server on loopback (sync mode),
 *               against the same without a witness
 *   cli         `irontrellis --version`, `status --json`, `verify --json` (cold processes)
 *   python      `python -m irontrellis verify`
 *   witness-scale  a witness data directory with --witness-entries entries over --witness-histories histories:
 *               server start-up (log replay), RSS, inclusion and consistency proof latency, head POST latency
 *
 * `--root TREE` (or IRONTRELLIS_BENCH_ROOT) measures another checkout's build on the same files (before/after).
 * `--quick` exits 1 when a result exceeds its budget (QUICK_BUDGETS below: deliberately generous, catching order-of-
 * magnitude regressions, not noise).
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { availableParallelism, cpus, tmpdir, totalmem } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { benchRoot, fmtMs, load, mean, median, parseArgs, peakRss, percentile, REPO, summary } from "./lib.mjs";

const SELF = fileURLToPath(import.meta.url);
const args = parseArgs(process.argv.slice(2), {
  quick: { type: "boolean", default: false },
  histories: { type: "string", default: undefined },
  sizes: { type: "string", default: "10k,100k" },
  runs: { type: "number", default: 3 },
  only: { type: "string", default: undefined },
  skip: { type: "string", default: undefined },
  root: { type: "string", default: undefined },
  out: { type: "string", default: undefined },
  work: { type: "string", default: undefined },
  "witness-entries": { type: "number", default: 100_000 },
  "witness-histories": { type: "number", default: 1_000 },
  "append-samples": { type: "number", default: 300 },
  "append-sizes": { type: "string", default: "10k,100k" },
  "python-sizes": { type: "string", default: "10k,100k" },
  "cli-sizes": { type: "string", default: "10k,100k" },
  "query-sizes": { type: "string", default: undefined },
  label: { type: "string", default: undefined },
  // child mode
  task: { type: "string", default: undefined },
  file: { type: "string", default: undefined },
  dir: { type: "string", default: undefined },
  samples: { type: "number", default: 200 },
});
const ROOT = benchRoot(args.root);

// ================================================================ child tasks (one measurement per process)

const result = (value) => { process.stdout.write(`\nRESULT ${JSON.stringify({ ...value, peakRssMiB: Math.round(peakRss() / 1048576) })}\n`); };
const time = (fn) => { const t = performance.now(); const out = fn(); return [performance.now() - t, out]; };
const timeAsync = async (fn) => { const t = performance.now(); const out = await fn(); return [performance.now() - t, out]; };
const manifestOf = (dir) => JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));

async function taskOpen() {
  const core = await load(ROOT, "packages/core/dist/index.js");
  const file = join(args.dir, "history.jsonl");
  const [openMs, store] = time(() => core.openHistoryStore(file));
  const events = store.head().position + 1;
  const heap = process.memoryUsage();
  const [verifyMs, report] = time(() => store.verify());
  if (!report.ok) throw new Error(`verify failed: ${report.failures.join("; ")}`);
  // Differential check between trees (before/after): every prefix hash (so every event, byte for byte in canonical
  // form) and the size of every derived map must be identical.
  const state = store.state();
  const digest = createHash("sha256");
  for (const hash of state.eventHistoryHashes) digest.update(hash);
  const sizes = Object.fromEntries(Object.entries(state).filter(([, v]) => v instanceof Map || Array.isArray(v)).map(([k, v]) => [k, v instanceof Map ? v.size : v.length]).sort(([a], [b]) => (a < b ? -1 : 1)));
  digest.update(JSON.stringify(sizes));
  digest.update(JSON.stringify({ head: report.head, pinnedHeadStatus: report.pinnedHeadStatus, pinnedAttestation: report.pinnedAttestation, anchors: report.anchors.length, anchorLogStatus: report.anchorLogStatus }));
  store.close();
  result({ events, bytes: statSync(file).size, openMs, verifyOpenMs: verifyMs, heapUsedMiB: Math.round(heap.heapUsed / 1048576), rssAfterOpenMiB: Math.round(heap.rss / 1048576), stateDigest: digest.digest("hex") });
}

async function taskVerify() {
  const core = await load(ROOT, "packages/core/dist/index.js");
  const [ms, report] = time(() => core.verifyHistory(join(args.dir, "history.jsonl")));
  if (!report.ok) throw new Error(`verifyHistory failed: ${report.failures.join("; ")}`);
  const { path: _path, ...comparable } = report;
  result({ events: report.eventCount, verifyHistoryMs: ms, reportDigest: createHash("sha256").update(core.jsonStringifyWithBigints(comparable)).digest("hex") });
}

const ownerConfig = (core, dir, manifest, extra = {}) => {
  let tick = manifest.tick + 10;
  return { historyFile: join(dir, "history.jsonl"), domain: manifest.domain, owner: manifest.owner, controller: manifest.controller, now: () => (tick += 1), ...extra };
};

/** Grants whose grantee is the long-lived worker (only the owner-API phase gives it jobs). */
const workerGrants = (owner) => {
  let n = 0;
  for (const event of owner.exportHistory()) if (event.type === "AUTHORITY_GRANTED" && event.data.grant?.granteeId === "worker") n += 1;
  return n;
};

async function taskQueries() {
  const core = await load(ROOT, "packages/core/dist/index.js");
  const manifest = manifestOf(args.dir);
  const [openMs, owner] = time(() => core.openLocalOwner(ownerConfig(core, args.dir, manifest)));
  const k = Math.max(1, manifest.unit - 3);
  const at = manifest.tick + 5;
  const allow = { actor: `agent:${k}`, action: "read", resource: `doc:${k}` };
  const deny = { actor: `agent:${k}`, action: "write", resource: "doc:shared" };
  const busy = { actor: "worker", action: "read", resource: "doc:job:1" };
  const options = { at };
  const [firstMs, first] = time(() => owner.authorize(allow, options));
  if (first.decision !== "ALLOW") throw new Error(`expected ALLOW, got ${first.decision} ${first.code ?? ""}`);
  const sample = (n, fn) => { const out = []; for (let i = 0; i < n; i += 1) out.push(time(fn)[0]); return out; };
  const warm = sample(args.samples, () => owner.authorize(allow, options));
  const denied = owner.authorize(deny, options);
  const warmDeny = sample(args.samples, () => owner.authorize(deny, options));
  const [busyFirstMs, busyDecision] = time(() => owner.authorize(busy, options));
  const warmBusy = sample(args.samples, () => owner.authorize(busy, options));
  const observe = sample(Math.max(5, args.samples / 10), () => owner.observe(options));
  const why = sample(Math.max(5, args.samples / 10), () => owner.why(allow, options));
  const responsible = sample(Math.max(5, args.samples / 10), () => owner.responsible(allow, options));
  const survives = sample(Math.max(3, args.samples / 20), () => owner.survives("worker", options));
  const grantsOfWorker = workerGrants(owner);
  owner.close();
  result({
    events: manifest.events, openMs, authorizeFirstMs: firstMs, authorizeWarm: summary(warm), denyDecision: `${denied.decision}/${denied.code ?? ""}`, authorizeDenyWarm: summary(warmDeny),
    workerGrants: grantsOfWorker, authorizeWorkerFirstMs: busyFirstMs, workerDecision: busyDecision.decision, authorizeWorkerWarm: summary(warmBusy),
    observe: summary(observe), why: summary(why), responsible: summary(responsible), survivesWorker: summary(survives),
  });
}

/** Copies a history directory's files (the history and its side files) into a fresh directory next to `work`. */
function copyHistory(dir, work) {
  const target = mkdtempSync(join(work, "copy-"));
  for (const name of readdirSync(dir)) if (name.startsWith("history.jsonl") || name === "manifest.json") copyFileSync(join(dir, name), join(target, name));
  return target;
}

async function taskAppend() {
  const core = await load(ROOT, "packages/core/dist/index.js");
  const signerLib = await load(ROOT, "packages/core/dist/signer.js");
  const manifest = manifestOf(args.dir);
  const work = args.work ?? tmpdir();
  const copy = copyHistory(args.dir, work);
  try {
    const file = join(copy, "history.jsonl");
    const ownerKey = signerLib.loadOwnerKeyFile(signerLib.ownerKeyPathFor(file));
    const n = args.samples;
    let seq = 0, tick = manifest.tick + 100;
    const grantEvent = (store) => core.signControlEvent(ownerKey, {
      id: `event:bench-append:${(seq += 1)}`, type: "AUTHORITY_GRANTED", timestamp: (tick += 1),
      data: { grant: { kind: "PERMISSION", authorityId: `bench-append:${seq}`, grantorId: manifest.owner, granteeId: "worker", rootAuthorityId: `bench-append:${seq}`, independent: true,
        constraints: { actions: ["read"], resources: [`doc:bench:${seq}`], quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [] } } },
    }, manifest.domain, store.head(), "sha256");
    const storeLevel = async (fsync) => {
      const [openMs, store] = time(() => core.openHistoryStore(file, { signer: ownerKey, fsync }));
      const times = [];
      for (let i = 0; i < n; i += 1) {
        const event = await grantEvent(store);
        times.push(time(() => store.append(event))[0]);
      }
      await store.flush();
      store.close();
      return { openMs, ...summary(times) };
    };
    const plain = await storeLevel(false);
    const fsync = await storeLevel(true);
    const config = ownerConfig(core, copy, manifest);
    config.now = () => (tick += 1);
    const [ownerOpenMs, owner] = time(() => core.openLocalOwner(config));
    const grants = [];
    for (let i = 0; i < n; i += 1) {
      const id = `bench-owner:${i}`;
      grants.push((await timeAsync(() => owner.grant({ id, to: "worker", actions: ["read"], resources: [`doc:bench-owner:${i}`], expiresAt: 4_000_000_000_000 })))[0]);
    }
    await owner.flush();
    owner.close();
    result({ events: manifest.events, samples: n, storeAppend: plain, storeAppendFsync: fsync, ownerOpenMs, ownerGrant: summary(grants) });
  } finally {
    rmSync(copy, { recursive: true, force: true });
  }
}

/** Starts the real `irontrellis-witness` bin on a fresh data dir (loopback, port 0, rate limits off); resolves { url, verifierKey, token, child, dataDir }. */
async function startWitnessServer(dataDir, { init = true } = {}) {
  const witnessLib = await load(ROOT, "packages/witness/dist/index.js");
  const bin = join(ROOT, "packages/witness/bin/irontrellis-witness.mjs");
  const token = "itw_bench-admin-token-0123456789abcdef";
  if (init) {
    const out = spawnSync(process.execPath, [bin, "init", "--data", dataDir, "--name", "bench.witness", "--json"], { encoding: "utf8" });
    if (out.status !== 0) throw new Error(`witness init failed: ${out.stderr}`);
    const configPath = join(dataDir, "config.json");
    const config = JSON.parse(readFileSync(configPath, "utf8"));
    config.adminTokenHashes = [witnessLib.hashToken(token)];
    config.rateLimit = { perIpPerMinute: 0, perHistoryPerMinute: 0, monitoringPerIpPerMinute: 0 };
    config.maxHistories = 1_000_000;
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
  }
  const started = performance.now();
  const child = spawn(process.execPath, [bin, "serve", "--data", dataDir, "--listen", "127.0.0.1:0"], { stdio: ["ignore", "ignore", "pipe"] });
  let log = "";
  const ready = await new Promise((resolveReady, reject) => {
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      log += chunk;
      for (const line of log.split("\n")) {
        if (!line.includes('"listening"')) continue;
        try { resolveReady(JSON.parse(line)); } catch { /* partial line */ }
      }
    });
    child.on("exit", (code) => reject(new Error(`witness server exited (${code}): ${log.slice(-800)}`)));
  });
  const startupMs = performance.now() - started;
  const fields = ready.fields ?? ready;
  return { url: fields.url, verifierKey: fields.verifierKey, entries: fields.entries, token, child, startupMs, pid: child.pid };
}
const stopServer = async (server) => {
  const exited = new Promise((r) => server.child.once("exit", r));
  server.child.kill("SIGTERM");
  await exited;
};
const procStatus = (pid) => {
  try {
    const text = readFileSync(`/proc/${pid}/status`, "utf8");
    const kb = (key) => Number(new RegExp(`${key}:\\s+(\\d+) kB`).exec(text)?.[1] ?? NaN);
    return { rssMiB: Math.round(kb("VmRSS") / 1024), peakRssMiB: Math.round(kb("VmHWM") / 1024) };
  } catch {
    return { rssMiB: NaN, peakRssMiB: NaN };
  }
};

async function taskWitnessAppend() {
  const core = await load(ROOT, "packages/core/dist/index.js");
  const work = mkdtempSync(join(args.work ?? tmpdir(), "witness-append-"));
  const n = args.samples;
  try {
    const server = await startWitnessServer(join(work, "witness-data"));
    const run = async (name, witness) => {
      let tick = 1_000, id = 0;
      const owner = await core.createLocalOwner({
        historyFile: join(work, `${name}.jsonl`), domain: { protocol: "irontrellis", version: "1", deploymentId: `deployment:${name}` }, owner: "operations", controller: "operator",
        now: () => (tick += 1), ids: () => `${name}:${(id += 1)}`, ...(witness === undefined ? { witness: false } : { witness }),
      });
      await owner.createAgent({ id: "worker" });
      const times = [];
      for (let i = 0; i < n; i += 1) times.push((await timeAsync(() => owner.grant({ id: `g:${i}`, to: "worker", actions: ["read"], resources: [`doc:${i}`], expiresAt: 4_000_000_000_000 })))[0]);
      await owner.flush();
      const status = owner.witnessStatus();
      owner.close();
      // After flush() nothing may be left unwitnessed: the writes were really witnessed.
      if (status !== undefined && status.unwitnessedEvents !== 0) throw new Error(`${name}: ${status.unwitnessedEvents} events unwitnessed after flush()`);
      return { ...summary(times), unwitnessedEvents: status?.unwitnessedEvents };
    };
    const baseline = await run("plain", undefined);
    const witness = { witnesses: [{ url: server.url, verifierKey: server.verifierKey, name: "bench", token: server.token }], quorum: 1 };
    const witnessed = await run("witnessed", { ...witness, mode: "sync" });
    // async (the default mode): writes return at local speed; flush() (inside run) waits for the witness to hold the head.
    const background = await run("witnessed-async", { ...witness, mode: "async" });
    const serverRss = procStatus(server.pid);
    await stopServer(server);
    result({ samples: n, ownerGrant: baseline, ownerGrantSyncWitness: witnessed, ownerGrantAsyncWitness: background, witnessServerRssMiB: serverRss.rssMiB });
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** Builds (or reuses) a witness data directory with `entries` entries over `histories` histories, through the witness library. */
async function buildWitnessData(dataDir, histories, entries) {
  const marker = join(dataDir, "bench-built.json");
  if (existsSync(marker)) {
    const built = JSON.parse(readFileSync(marker, "utf8"));
    if (built.histories === histories && built.entries === entries) return built;
    throw new Error(`${dataDir} holds another witness build (${built.histories} histories, ${built.entries} entries)`);
  }
  const core = await load(ROOT, "packages/core/dist/index.js");
  const t = await load(ROOT, "packages/core/dist/transparency/index.js");
  const witnessLib = await load(ROOT, "packages/witness/dist/index.js");
  const server = await startWitnessServer(dataDir);
  const started = performance.now();
  const perHistory = Math.max(1, Math.floor(entries / histories) - 2);
  const sha = (text) => core.sha256Hex(new TextEncoder().encode(text));
  const specs = [];
  for (let h = 0; h < histories; h += 1) {
    const pair = core.keyPairFromPrivateKey("ed25519", `owner:${h}`, `0x${(0xb0000000 + h).toString(16).padStart(64, "0")}`);
    const signer = { keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, signHash: core.signHashWith(pair) };
    const domain = { protocol: "irontrellis", version: "1", deploymentId: `deployment:witness-bench:${h}` };
    const genesis = {
      id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
      data: {
        domain, versions: { ...core.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: [{ keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential }],
        adapterPolicyHash: core.ADAPTER_POLICY_HASHES.E1, canonicalLineageId: `lineage:${h}`, policyVersion: `policy:${h}/1`,
        rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: `policy-source:${h}`, timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
      },
    };
    const hasher = new core.HistoryHasher("irontrellis-event/1");
    const genesisHead = { hash: hasher.push(genesis), position: 0, canonicalTime: 0 };
    specs.push({ h, signer, domain, genesis, historyId: genesisHead.hash, last: genesisHead, genesisHead });
  }
  const post = async (path, body, headers = {}) => {
    const response = await fetch(`${server.url}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
    const text = await response.text();
    if (response.status >= 300) throw new Error(`${path}: ${response.status} ${text.slice(0, 300)}`);
    return JSON.parse(text);
  };
  // Registrations, then heads in rounds (every history advances by one head per round), 16 requests in flight.
  const pool = async (items, fn, width = 16) => { let next = 0; await Promise.all(Array.from({ length: width }, async () => { while (next < items.length) { const item = items[next++]; await fn(item); } })); };
  await pool(specs, async (s) => {
    await post("/v1/histories", { genesis: s.genesis }, { authorization: `Bearer ${server.token}` });
    await post(`/v1/histories/${s.historyId}/heads`, await t.signHeadStatement(s.signer, { version: t.HEAD_STATEMENT_VERSION, historyId: s.historyId, domain: s.domain, head: s.genesisHead, previous: null }));
  });
  for (let round = 1; round <= perHistory; round += 1) {
    await pool(specs, async (s) => {
      const head = { hash: sha(`${s.historyId}:${round}`), position: round * 3, canonicalTime: round * 3 };
      const statement = await t.signHeadStatement(s.signer, { version: t.HEAD_STATEMENT_VERSION, historyId: s.historyId, domain: s.domain, head, previous: { hash: s.last.hash, position: s.last.position } });
      await post(`/v1/histories/${s.historyId}/heads`, statement);
      s.last = head;
    });
  }
  const buildSeconds = (performance.now() - started) / 1000;
  await stopServer(server);
  const built = { histories, entries: histories * (perHistory + 2), requestedEntries: entries, perHistory, buildSeconds, logBytes: statSync(join(dataDir, "log.jsonl")).size, witness: witnessLib.WITNESS_PROTOCOL_VERSION };
  // The owner keys are deterministic (seeded by history number), so a benchmark can continue any history.
  writeFileSync(marker, `${JSON.stringify(built, null, 2)}\n`);
  return built;
}

async function taskWitnessScale() {
  const core = await load(ROOT, "packages/core/dist/index.js");
  const t = await load(ROOT, "packages/core/dist/transparency/index.js");
  const dataDir = args.dir;
  const built = await buildWitnessData(dataDir, args["witness-histories"], args["witness-entries"]);
  // A copy for the head POSTs, so every run (and every tree) starts from the same data directory.
  const work = mkdtempSync(join(args.work ?? dirname(dataDir), "witness-scale-run-"));
  try {
    for (const name of readdirSync(dataDir)) if (!name.startsWith("server.lock")) copyFileSync(join(dataDir, name), join(work, name));
    const server = await startWitnessServer(work, { init: false });
    const afterStart = procStatus(server.pid);
    const get = async (path) => { const r = await fetch(`${server.url}${path}`); const text = await r.text(); if (r.status !== 200) throw new Error(`${path}: ${r.status} ${text.slice(0, 200)}`); return JSON.parse(text); };
    const size = server.entries;
    let seed = 12345;
    const rand = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const n = args.samples;
    const inclusion = [], consistency = [], heads = [];
    for (let i = 0; i < n; i += 1) inclusion.push((await timeAsync(() => get(`/v1/proofs/inclusion?index=${rand(size)}&size=${size}`)))[0]);
    for (let i = 0; i < n; i += 1) consistency.push((await timeAsync(() => get(`/v1/proofs/consistency?from=${1 + rand(size - 1)}&to=${size}`)))[0]);
    // Head POSTs continue random histories (the owner keys are deterministic): one sequential client.
    const sha = (text) => core.sha256Hex(new TextEncoder().encode(text));
    const state = new Map();
    for (let i = 0; i < n; i += 1) {
      const h = rand(built.histories);
      const pair = core.keyPairFromPrivateKey("ed25519", `owner:${h}`, `0x${(0xb0000000 + h).toString(16).padStart(64, "0")}`);
      const signer = { keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, signHash: core.signHashWith(pair) };
      const domain = { protocol: "irontrellis", version: "1", deploymentId: `deployment:witness-bench:${h}` };
      let s = state.get(h);
      if (s === undefined) {
        const info = await get(`/v1/histories/${await historyIdOf(core, domain, pair, h)}`);
        s = { historyId: info.historyId, last: info.latest.head, round: info.latest.head.position / 3 };
        state.set(h, s);
      }
      s.round += 1;
      const head = { hash: sha(`${s.historyId}:${s.round}`), position: s.round * 3, canonicalTime: s.round * 3 };
      const statement = await t.signHeadStatement(signer, { version: t.HEAD_STATEMENT_VERSION, historyId: s.historyId, domain, head, previous: { hash: s.last.hash, position: s.last.position } });
      const [ms, response] = await timeAsync(() => fetch(`${server.url}/v1/histories/${s.historyId}/heads`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(statement) }).then(async (r) => ({ status: r.status, body: await r.text() })));
      if (response.status !== 201) throw new Error(`head POST ${response.status}: ${response.body.slice(0, 200)}`);
      heads.push(ms);
      s.last = head;
    }
    const end = procStatus(server.pid);
    await stopServer(server);
    result({
      entries: size, histories: built.histories, logMiB: Math.round(built.logBytes / 1048576), buildSeconds: built.buildSeconds, startupMs: server.startupMs,
      serverRssAfterStartMiB: afterStart.rssMiB, serverPeakRssMiB: end.peakRssMiB, inclusion: summary(inclusion), consistency: summary(consistency), headPost: summary(heads),
    });
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
async function historyIdOf(core, domain, pair, h) {
  const genesis = {
    id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
    data: {
      domain, versions: { ...core.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: [{ keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential }],
      adapterPolicyHash: core.ADAPTER_POLICY_HASHES.E1, canonicalLineageId: `lineage:${h}`, policyVersion: `policy:${h}/1`,
      rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: `policy-source:${h}`, timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
    },
  };
  return new core.HistoryHasher("irontrellis-event/1").push(genesis);
}

const TASKS = { open: taskOpen, verify: taskVerify, queries: taskQueries, append: taskAppend, witness: taskWitnessAppend, "witness-scale": taskWitnessScale };

if (args.task !== undefined) {
  const task = TASKS[args.task];
  if (task === undefined) throw new Error(`unknown task ${args.task}`);
  await task();
  process.exit(0);
}

// ================================================================ parent: orchestration

const log = (...parts) => console.error(`[bench ${new Date().toISOString().slice(11, 19)}]`, ...parts);
const RSS_PY = join(dirname(SELF), "rss.py");
const hasPython = spawnSync("python3", ["--version"]).status === 0;

/** Runs one child task; returns its RESULT object. */
function child(task, extra = []) {
  const argv = [SELF, "--task", task, "--root", ROOT, ...extra];
  const out = spawnSync(process.execPath, argv, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env: { ...process.env, NODE_OPTIONS: "" } });
  const line = out.stdout.split("\n").reverse().find((l) => l.startsWith("RESULT "));
  if (out.status !== 0 || line === undefined) throw new Error(`task ${task} failed (${out.status}): ${out.stderr.slice(-2000)}`);
  return JSON.parse(line.slice(7));
}

/** A cold external command: wall time and peak RSS (through bench/rss.py when python3 is present). */
function external(argv, env = {}) {
  // Every measured process runs with Node's default heap (an inherited NODE_OPTIONS such as --max-old-space-size is dropped).
  env = { NODE_OPTIONS: "", ...env };
  if (hasPython) {
    const out = spawnSync("python3", [RSS_PY, "--", ...argv], { encoding: "utf8", env: { ...process.env, ...env } });
    const value = JSON.parse(out.stdout.trim().split("\n").at(-1));
    if (value.code !== 0) throw new Error(`${argv.join(" ")} exited ${value.code}: ${value.stderrTail}`);
    return { ms: value.ms, peakRssMiB: Math.round(value.maxRssKiB / 1024), outputDigest: value.stdoutDigest };
  }
  const t = performance.now();
  const out = spawnSync(argv[0], argv.slice(1), { encoding: "utf8", env: { ...process.env, ...env } });
  if (out.status !== 0) throw new Error(`${argv.join(" ")} exited ${out.status}: ${out.stderr}`);
  return { ms: performance.now() - t, peakRssMiB: NaN };
}

/** Median over runs of every numeric leaf (nested objects kept), plus the per-run values of the headline metric. */
function combine(runs) {
  const merge = (values) => {
    const first = values[0];
    if (typeof first === "number") return median(values);
    if (first !== null && typeof first === "object" && !Array.isArray(first)) return Object.fromEntries(Object.keys(first).map((key) => [key, merge(values.map((v) => v?.[key]))]));
    return first;
  };
  return { ...merge(runs), runs: runs.length };
}

const sizeList = (text) => text.split(",").map((s) => s.trim()).filter(Boolean);
const selected = (name) => (args.only === undefined || sizeList(args.only).includes(name)) && !(args.skip !== undefined && sizeList(args.skip).includes(name));

async function main() {
  const quick = args.quick;
  const runs = quick ? 1 : args.runs;
  const work = args.work ?? mkdtempSync(join(tmpdir(), "irontrellis-bench-"));
  mkdirSync(work, { recursive: true });
  const cleanupWork = args.work === undefined;
  const results = {
    version: "irontrellis-bench-results/1", label: args.label ?? null, root: ROOT, quick, runs, date: new Date().toISOString(),
    machine: { cpus: cpus().length, cpu: cpus()[0]?.model, parallelism: availableParallelism(), memoryGiB: Math.round(totalmem() / 2 ** 30), node: process.version, platform: `${process.platform} ${process.arch}` },
    sizes: {}, witnessAppend: undefined, witnessScale: undefined,
  };
  try {
    let histories = args.histories, sizes = sizeList(args.sizes);
    if (quick) {
      histories = join(work, "histories");
      sizes = ["quick"];
      log("quick: generating a 1,500-event history through the owner API");
      const out = spawnSync(process.execPath, [join(dirname(SELF), "generate.mjs"), "--events", "1500", "--out", join(histories, "quick"), "--root", ROOT, "--quiet", "--anchor-every", "500"], { encoding: "utf8" });
      if (out.status !== 0) throw new Error(`generate failed: ${out.stderr}`);
    }
    if (histories === undefined) throw new Error("--histories DIR (or --quick) is required");
    const cli = join(ROOT, "packages/cli/bin/irontrellis.mjs");
    for (const size of sizes) {
      const dir = join(histories, size);
      if (!existsSync(join(dir, "manifest.json"))) throw new Error(`${dir} has no generated history (node bench/generate.mjs --out ${dir} ...)`);
      const manifest = manifestOf(dir);
      const entry = { events: manifest.events, bytes: statSync(join(dir, "history.jsonl")).size, byType: manifest.byType };
      results.sizes[size] = entry;
      const inList = (list) => quick || sizeList(list).includes(size);
      const repeat = (label, fn) => { const out = []; for (let r = 0; r < runs; r += 1) { log(`${size} ${label} run ${r + 1}/${runs}`); out.push(fn()); } return combine(out); };
      if (selected("open")) entry.open = repeat("open", () => child("open", ["--dir", dir]));
      if (selected("verify")) entry.verify = repeat("verifyHistory", () => child("verify", ["--dir", dir]));
      if (selected("queries") && (args["query-sizes"] === undefined || inList(args["query-sizes"]))) {
        // Fewer samples at 500k+ events, where one survives() or why() is itself seconds long.
        entry.queries = repeat("queries", () => child("queries", ["--dir", dir, "--samples", String(quick ? 50 : manifest.events >= 500_000 ? 20 : 200)]));
      }
      if (selected("append") && inList(args["append-sizes"])) {
        entry.append = repeat("append", () => child("append", ["--dir", dir, "--work", work, "--samples", String(quick ? 40 : args["append-samples"])]));
      }
      if (selected("cli") && inList(args["cli-sizes"])) {
        const history = join(dir, "history.jsonl");
        const cliRuns = (argv, n) => {
          const out = [];
          for (let r = 0; r < n; r += 1) out.push(external([process.execPath, cli, ...argv]));
          return { ms: median(out.map((o) => o.ms)), peakRssMiB: median(out.map((o) => o.peakRssMiB)), runs: n, outputDigests: [...new Set(out.map((o) => o.outputDigest))] };
        };
        log(`${size} cli`);
        entry.cli = {
          version: cliRuns(["--version"], quick ? 3 : 5),
          status: cliRuns(["status", "--history", history, "--json"], runs),
          verify: cliRuns(["verify", "--history", history, "--json"], runs),
        };
      }
      if (selected("python") && hasPython && inList(args["python-sizes"])) {
        log(`${size} python verify`);
        const out = [];
        for (let r = 0; r < runs; r += 1) out.push(external(["python3", "-m", "irontrellis", "verify", join(dir, "history.jsonl")], { PYTHONPATH: join(ROOT, "python/src") }));
        entry.python = { ms: median(out.map((o) => o.ms)), peakRssMiB: median(out.map((o) => o.peakRssMiB)), runs, outputDigests: [...new Set(out.map((o) => o.outputDigest))] };
      }
    }
    if (selected("witness")) {
      results.witnessAppend = (() => { const out = []; for (let r = 0; r < runs; r += 1) { log(`witness (sync, loopback) run ${r + 1}/${runs}`); out.push(child("witness", ["--work", work, "--samples", String(quick ? 30 : 200)])); } return combine(out); })();
    }
    if (selected("witness-scale")) {
      const entries = quick ? 400 : args["witness-entries"], count = quick ? 20 : args["witness-histories"];
      const dataDir = join(quick ? work : (args.histories ?? work), `witness-${count}x${entries}`);
      if (!existsSync(join(dataDir, "bench-built.json"))) log(`building a witness data directory: ${entries} entries over ${count} histories (${dataDir})`);
      const out = [];
      for (let r = 0; r < runs; r += 1) {
        log(`witness-scale run ${r + 1}/${runs}`);
        out.push(child("witness-scale", ["--dir", dataDir, "--work", work, "--witness-entries", String(entries), "--witness-histories", String(count), "--samples", String(quick ? 30 : 300)]));
      }
      results.witnessScale = combine(out);
    }
  } finally {
    if (cleanupWork) rmSync(work, { recursive: true, force: true });
  }
  if (args.out !== undefined) writeFileSync(args.out, `${JSON.stringify(results, null, 2)}\n`);
  console.log(table(results));
  if (quick) {
    const failures = checkBudgets(results);
    for (const failure of failures) console.error(`BUDGET EXCEEDED: ${failure}`);
    if (failures.length > 0) process.exit(1);
    console.error("quick benchmark: every result within its budget");
  }
}

// ================================================================ report

function table(results) {
  const lines = [`IronTrellis benchmarks (${results.quick ? "quick" : `median of ${results.runs} runs`}), ${results.machine.cpu} x${results.machine.cpus}, ${results.machine.memoryGiB} GiB, node ${results.machine.node}`];
  const row = (label, value) => lines.push(`  ${label.padEnd(44)} ${value}`);
  const dist = (s) => (s === undefined ? "n/a" : `p50 ${fmtMs(s.p50)}  p99 ${fmtMs(s.p99)}  mean ${fmtMs(s.mean)}`);
  for (const [size, e] of Object.entries(results.sizes)) {
    lines.push(`\n${size}: ${e.events} events, ${(e.bytes / 1048576).toFixed(1)} MiB`);
    if (e.open) { row("open (full replay)", `${fmtMs(e.open.openMs)}  (${(e.open.openMs * 1000 / e.events).toFixed(0)} µs/event), peak RSS ${e.open.peakRssMiB} MiB, heap ${e.open.heapUsedMiB} MiB`); row("store.verify() on the open handle", fmtMs(e.open.verifyOpenMs)); }
    if (e.verify) row("verifyHistory (open + verify)", `${fmtMs(e.verify.verifyHistoryMs)}, peak RSS ${e.verify.peakRssMiB} MiB`);
    if (e.queries) {
      const q = e.queries;
      row("authorize, first on the handle", fmtMs(q.authorizeFirstMs));
      row("authorize ALLOW, warm", dist(q.authorizeWarm));
      row(`authorize ${q.denyDecision}, warm`, dist(q.authorizeDenyWarm));
      row(`authorize worker (${q.workerGrants} grants), first / warm`, `${fmtMs(q.authorizeWorkerFirstMs)} / ${dist(q.authorizeWorkerWarm)}`);
      row("observe()", dist(q.observe));
      row("why / responsible", `${fmtMs(q.why.p50)} / ${fmtMs(q.responsible.p50)}`);
      row("survives (worker)", dist(q.survivesWorker));
    }
    if (e.append) {
      row("store.append, fsync off", dist(e.append.storeAppend));
      row("store.append, fsync on", dist(e.append.storeAppendFsync));
      row("owner grant() (sign, fsync, attested pin)", dist(e.append.ownerGrant));
      row("append peak RSS", `${e.append.peakRssMiB} MiB`);
    }
    if (e.cli) {
      row("cli --version", `${fmtMs(e.cli.version.ms)}, RSS ${e.cli.version.peakRssMiB} MiB`);
      row("cli status --json", `${fmtMs(e.cli.status.ms)}, RSS ${e.cli.status.peakRssMiB} MiB`);
      row("cli verify --json", `${fmtMs(e.cli.verify.ms)}, RSS ${e.cli.verify.peakRssMiB} MiB`);
    }
    if (e.python) row("python -m irontrellis verify", `${fmtMs(e.python.ms)}, RSS ${e.python.peakRssMiB} MiB`);
  }
  if (results.witnessAppend) {
    const w = results.witnessAppend;
    lines.push("\nowner grant() on a fresh history, with and without a sync witness on loopback");
    row("no witness", dist(w.ownerGrant));
    row("sync witness (irontrellis-witness, loopback)", dist(w.ownerGrantSyncWitness));
    if (w.ownerGrantAsyncWitness) row("async witness (the default mode)", dist(w.ownerGrantAsyncWitness));
  }
  if (results.witnessScale) {
    const w = results.witnessScale;
    lines.push(`\nwitness server: ${w.entries} entries, ${w.histories} histories, log ${w.logMiB} MiB`);
    row("start-up (log replay, until listening)", fmtMs(w.startupMs));
    row("RSS after start-up / peak", `${w.serverRssAfterStartMiB} / ${w.serverPeakRssMiB} MiB`);
    row("GET inclusion proof", dist(w.inclusion));
    row("GET consistency proof", dist(w.consistency));
    row("POST head (sync, fsync)", dist(w.headPost));
  }
  return lines.join("\n");
}

/**
 * Quick-mode budgets (1,500-event history). Set 5-20x above what a 2-vCPU CI runner measures, so only an
 * order-of-magnitude regression (an accidental O(n²), a lost cache, a replay on every write) fails the job.
 */
const QUICK_BUDGETS = [
  ["open: µs per event", (r) => (r.sizes.quick.open.openMs * 1000) / r.sizes.quick.events, 3_000],
  ["store.verify() on the open handle, ms", (r) => r.sizes.quick.open.verifyOpenMs, 3_000],
  ["verifyHistory, ms", (r) => r.sizes.quick.verify.verifyHistoryMs, 8_000],
  ["authorize warm p50, ms", (r) => r.sizes.quick.queries.authorizeWarm.p50, 5],
  ["why p50, ms", (r) => r.sizes.quick.queries.why.p50, 100],
  ["survives p50, ms", (r) => r.sizes.quick.queries.survivesWorker.p50, 500],
  ["store.append fsync off p50, ms", (r) => r.sizes.quick.append.storeAppend.p50, 25],
  ["owner grant() p50, ms", (r) => r.sizes.quick.append.ownerGrant.p50, 100],
  ["owner grant() with a sync witness p50, ms", (r) => r.witnessAppend.ownerGrantSyncWitness.p50, 250],
  ["owner grant() with an async witness p50, ms", (r) => r.witnessAppend.ownerGrantAsyncWitness.p50, 100],
  ["cli --version, ms", (r) => r.sizes.quick.cli.version.ms, 3_000],
  ["cli verify (1,500 events), ms", (r) => r.sizes.quick.cli.verify.ms, 10_000],
  ["python verify (1,500 events), ms", (r) => r.sizes.quick.python?.ms ?? 0, 30_000],
  ["witness start-up, ms", (r) => r.witnessScale.startupMs, 5_000],
  ["witness inclusion proof p50, ms", (r) => r.witnessScale.inclusion.p50, 50],
  ["witness head POST p50, ms", (r) => r.witnessScale.headPost.p50, 250],
];
function checkBudgets(results) {
  const failures = [];
  for (const [label, get, budget] of QUICK_BUDGETS) {
    let value;
    try { value = get(results); } catch { continue; } // a measurement that was skipped (--skip) has no budget to meet
    if (!(value <= budget)) failures.push(`${label}: ${Number.isFinite(value) ? value.toFixed(2) : value} > ${budget}`);
  }
  return failures;
}

await main();
