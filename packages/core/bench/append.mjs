// Append benchmark. Two views of the write path:
//   1. store level: `HistoryStore.append` of pre-signed scenario events (lock, CAS, incremental
//      validation, line write, pinned head) with and without fsync, at the tail of an N-event file;
//   2. owner level: `createLocalOwner(...).grant()` and friends (input capture, capacity check,
//      Ed25519 control signature, then the store path with fsync and an attested pin), reported at
//      several history sizes, plus `authorize()` / `why()` through the same handle.
//   node --experimental-strip-types bench/append.mjs [eventCount] [tmpDir]
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scenario, median, fmt } from "./scenario.mjs";
const { createHistoryStore } = await import("../src/store.ts");
const { createLocalOwner } = await import("../src/owner.ts");

const TARGET = Number(process.argv[2] ?? 10_000);
const dir = mkdtempSync(join(process.argv[3] ?? tmpdir(), "irontrellis-bench-"));
process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
const SAMPLE = 200;

// ---------------------------------------------------------------- store level
for (const [format, target] of [["irontrellis-event/1", TARGET], ["continuity-event/0.2", Math.min(TARGET, 4096)]]) {
  const { history } = await scenario(format, target);
  const prefix = history.slice(0, history.length - SAMPLE), tail = history.slice(history.length - SAMPLE);
  console.log(`\n${format}: ${history.length} events; store.append of the last ${SAMPLE} events onto a ${prefix.length}-event file`);
  for (const fsync of [true, false]) {
    const path = join(dir, `${format.replace(/[^a-z0-9]/g, "-")}-${fsync ? "fsync" : "nofsync"}.jsonl`);
    const store = createHistoryStore(path, prefix, { fsync });
    const times = [];
    for (const event of tail) {
      const t = performance.now();
      store.append(event);
      times.push(performance.now() - t);
    }
    console.log(`  fsync ${fsync ? "on " : "off"}: median ${fmt(median(times))}, p90 ${fmt([...times].sort((a, b) => a - b)[Math.floor(times.length * 0.9)])}, best ${fmt(Math.min(...times))}`);
  }
}

// ---------------------------------------------------------------- owner level
// Legacy owner histories keep the Core 0.3 managed-capacity budget of 96 events, so that run stops at 90.
for (const [format, target] of [["irontrellis-event/1", TARGET], ["continuity-event/0.2", Math.min(TARGET, 90)]]) {
  const trellis = format === "irontrellis-event/1";
  let tick = 1_000;
  const owner = await createLocalOwner({
    historyFile: join(dir, `${trellis ? "owner-v1" : "owner-legacy"}.jsonl`), owner: "owner", controller: "controller", now: () => (tick += 1), format,
    domain: trellis ? { protocol: "irontrellis", version: "1", deploymentId: "deployment:bench" }
      : { protocol: "continuity", version: "0.2", deploymentId: "deployment:bench", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000001" },
  });
  console.log(`\n${format}: owner API (fsync on, ${trellis ? "Ed25519 control signatures + attested pin" : "unsigned legacy control events"})`);
  const checkpoints = new Set([90, 100, 1_000, 2_000, 4_000, 10_000].filter((n) => n <= target));
  const samples = new Map();
  let n = 0, count = 2;
  const record = (kind, ms) => { if (!samples.has(kind)) samples.set(kind, []); samples.get(kind).push(ms); };
  const timed = async (kind, fn) => { const t = performance.now(); await fn(); record(kind, performance.now() - t); count += 1; };
  const report = async () => {
    const at = count;
    const grantTimes = samples.get("grant") ?? [];
    const recent = grantTimes.slice(-50);
    const sample = (fn) => { const times = []; let out; for (let i = 0; i < 20; i += 1) { const t = performance.now(); out = fn(); times.push(performance.now() - t); } return [median(times), out]; };
    const [authorizeMs, decision] = sample(() => owner.authorize({ actor: `agent:${n - 1}`, action: "read", resource: "doc:*" }));
    const [whyMs] = sample(() => owner.why({ actor: `agent:${n - 1}`, action: "read", resource: "doc:*" }));
    console.log(`  at ${String(at).padStart(6)} events: grant median (last 50) ${fmt(median(recent))}; authorize median ${fmt(authorizeMs)} (${decision.decision}); why median ${fmt(whyMs)}`);
  };
  while (count < target) {
    const agent = `agent:${n}`;
    await timed("createAgent", () => owner.createAgent({ id: agent }));
    await timed("createRole", () => owner.createRole({ id: `role:${n}` }));
    await timed("appoint", () => owner.appoint({ agent, role: `role:${n}`, tenure: `tenure:${n}`, number: 1 }));
    await timed("grant", () => owner.grant({ id: `root:${n}`, to: agent, actions: ["read", "write"], resources: ["doc:*"], expiresAt: 10_000_000, delegable: 3 }));
    if (n > 0) {
      await timed("delegate", () => owner.delegate({ id: `delegated:${n}`, parent: `root:${n - 1}`, from: `agent:${n - 1}`, to: agent, actions: ["read"], resources: ["doc:*"], expiresAt: 10_000_000, delegable: 1 }));
      await timed("prohibit", () => owner.prohibit({ id: `prohibit:${n}`, root: `root:${n}`, subject: agent, actions: ["write"], resources: ["doc:*"], expiresAt: 10_000_000 }));
      if (n % 4 === 0) await timed("revoke", () => owner.revoke(`delegated:${n - 1}`));
    }
    for (let k = 0; k < 2; k += 1) await timed("grant", () => owner.grant({ id: `extra:${n}:${k}`, to: agent, actions: ["read"], resources: [`doc:${k}`], expiresAt: 10_000_000 }));
    n += 1;
    for (const c of checkpoints) if (count >= c) { checkpoints.delete(c); await report(); }
  }
  for (const [kind, times] of samples) console.log(`  ${kind.padEnd(12)} ${String(times.length).padStart(5)} calls: median ${fmt(median(times))}, p90 ${fmt([...times].sort((a, b) => a - b)[Math.floor(times.length * 0.9)])}`);
  console.log(`  verify(): ${(() => { const t = performance.now(); const r = owner.verify(); return `${fmt(performance.now() - t)} (${r.pinnedHeadStatus}, ${r.controlSignatures})`; })()}`);
}
