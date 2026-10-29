// Before/after on the scenario from the Continuity evaluation: one agent, 85
// grants, through the frozen Core 0.3 SDK (packages/reference-0.2, legacy
// format, whole-history replay on every write) and through the IronTrellis
// owner API (legacy format and format 1). Reports per-grant latency at the
// start and the end, and the total wall time for the 85 grants.
//   node --experimental-strip-types bench/reference-grants.mjs
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { median, fmt } from "./scenario.mjs";
const { createLocalOwner } = await import("../src/owner.ts");
const reference = await import(pathToFileURL(new URL("../../reference-0.2/core-0.3/src/local-owner.ts", import.meta.url).pathname).href);

const GRANTS = 85;
const dir = mkdtempSync(join(tmpdir(), "irontrellis-refbench-"));
process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
const LEGACY_DOMAIN = { protocol: "continuity", version: "0.2", deploymentId: "bench", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000000" };
const TRELLIS_DOMAIN = { protocol: "irontrellis", version: "1", deploymentId: "bench" };

async function run(label, create, awaits) {
  let tick = 1_000;
  const owner = await create(() => (tick += 1));
  const call = async (fn) => (awaits ? fn() : Promise.resolve(fn()));
  await call(() => owner.createAgent({ id: "bea" }));
  const times = [];
  const t0 = performance.now();
  for (let i = 0; i < GRANTS; i += 1) {
    const t = performance.now();
    await call(() => owner.grant({ id: `g${i}`, to: "bea", actions: ["read"], resources: [`doc:${i}`], expiresAt: 10_000_000 }));
    times.push(performance.now() - t);
  }
  const total = performance.now() - t0;
  const decision = owner.authorize({ actor: "bea", action: "read", resource: "doc:84" });
  console.log(`${label}: ${GRANTS} grants in ${fmt(total)}; per grant: first ${fmt(times[0])}, median ${fmt(median(times))}, last ${fmt(times[GRANTS - 1])} (history ${owner.exportHistory().length} events); authorize ${decision.decision}`);
}

await run("reference Core 0.3 SDK (legacy format)", (now) => reference.createLocalOwner({ historyFile: join(dir, "reference.jsonl"), domain: LEGACY_DOMAIN, owner: "operations", controller: "operator", now }), false);
await run("IronTrellis owner API (legacy format)", (now) => createLocalOwner({ historyFile: join(dir, "legacy.jsonl"), domain: LEGACY_DOMAIN, owner: "operations", controller: "operator", now, format: "continuity-event/0.2" }), true);
await run("IronTrellis owner API (format 1)   ", (now) => createLocalOwner({ historyFile: join(dir, "v1.jsonl"), domain: TRELLIS_DOMAIN, owner: "operations", controller: "operator", now }), true);
