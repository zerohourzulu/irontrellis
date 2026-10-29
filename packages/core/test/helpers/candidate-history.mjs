/**
 * Seeded random format-1 histories for the candidate-index differentials (review block 3, M3): many overlapping grants
 * to one actor `w` (with random ids, so a late grant can become the winner), notBefore/expiresAt, transaction and amount
 * caps, delegations, non-independent grants, `requires`, ROOT and GLOBAL prohibitions and revocations, all written by the
 * owner API (every event is a valid, owner-signed one).
 *
 * Used by packages/core/test/candidate-index.test.mjs (with the TypeScript sources) and, run as a script, by
 * python/tests/test_candidate_index.py (with the built dist):
 *
 *   node packages/core/test/helpers/candidate-history.mjs <seed> <operations>   → the events, JSON with bigint markers
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const ACTIONS = ["read", "write", "pay"];
export const RESOURCES = ["r0", "r1", "r2", "r3"];

/** mulberry32: a seeded PRNG, so a failure names a reproducible seed. */
export const prng = (seed) => {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

/** `api`: { createLocalOwner, keyPairFromPrivateKey, signerFromKeyPair, openHistoryStore, TRELLIS_FORMAT, FORMAT1_TEST_TOOLING }. */
export async function generateCandidateHistory(api, seed, operations) {
  const rnd = prng(seed);
  const pick = (list) => list[Math.floor(rnd() * list.length)];
  const some = (list) => { const chosen = list.filter(() => rnd() < 0.5); return chosen.length > 0 ? chosen : [pick(list)]; };
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-candidate-index-"));
  try {
    let tick = 100, counter = 0;
    const config = {
      historyFile: join(dir, "history.jsonl"), domain: { protocol: "irontrellis", version: "1", deploymentId: `index-${seed}` }, owner: "operations",
      // A-185.3 / A-194 / A-206.1: format 1 is test tooling; the mark is internal-format1's FORMAT1_TEST_TOOLING, passed in `api`
      // from the same copy of core as the API (an unregistered symbol).
      controller: "operator", format: api.TRELLIS_FORMAT, [api.FORMAT1_TEST_TOOLING]: true, now: () => tick, ids: () => `e:${(counter += 1)}`, nextKey: false,
      signer: api.signerFromKeyPair(api.keyPairFromPrivateKey("ed25519", "owner:1", `0x${(0x9001 + seed).toString(16).padStart(64, "0")}`)),
    };
    const owner = await api.createLocalOwner(config);
    // An operation the engine refuses (a delegation that does not attenuate, a revoked parent, ...) is simply skipped.
    const step = async (operation) => {
      try { await operation(); } catch (error) { if (typeof error?.code !== "string") throw error; }
      tick += 1 + Math.floor(rnd() * 3);
    };
    for (const agent of ["w", "a1", "a2"]) await step(() => owner.createAgent({ id: agent }));
    const permissions = [], roots = [];
    for (let i = 0; i < operations; i += 1) {
      const r = rnd();
      // Random ids: the winner is the candidate with the smallest root id, so a grant added late must be able to sort
      // first (with increasing ids a missing index entry would rarely change a decision). The suffix keeps them unique.
      const id = `g:${Math.floor(rnd() * 1e6).toString(36)}.${i}`;
      const c = { actions: some(ACTIONS), resources: some(RESOURCES), expiresAt: tick + 20 + Math.floor(rnd() * 400) };
      if (rnd() < 0.2) c.notBefore = tick + Math.floor(rnd() * 200);
      if (rnd() < 0.2) c.maxTransactions = 1 + Math.floor(rnd() * 3);
      if (rnd() < 0.2) c.maxAmount = BigInt(1 + Math.floor(rnd() * 200));
      if (r < 0.45) { await step(() => owner.grant({ id, to: "w", ...c, ...(rnd() < 0.3 ? { delegable: 1 } : {}) })); permissions.push(id); roots.push(id); }
      else if (r < 0.55) { await step(() => owner.grant({ id, to: pick(["a1", "a2"]), ...c, delegable: 2 })); permissions.push(id); roots.push(id); }
      else if (r < 0.7 && permissions.length > 0) { const parent = pick(permissions); await step(() => owner.delegate({ id, parent, from: pick(["a1", "a2", "w"]), to: pick(["w", "w", "a1"]), ...c })); permissions.push(id); }
      else if (r < 0.77 && permissions.length > 0) { await step(() => owner.grant({ id, to: "w", ...c, independent: false })); permissions.push(id); }
      else if (r < 0.83 && permissions.length > 0) { await step(() => owner.grant({ id, to: "w", ...c, requires: [pick(permissions)] })); permissions.push(id); roots.push(id); }
      else if (r < 0.9 && roots.length > 0) {
        await step(() => owner.prohibit({ id, root: pick(roots), subject: pick(["w", "a1"]), actions: some(ACTIONS), resources: some(RESOURCES),
          ...(rnd() < 0.5 ? { expiresAt: tick + Math.floor(rnd() * 200) } : {}), ...(rnd() < 0.3 ? { maxAmount: 50n } : {}) }));
      } else if (r < 0.92) await step(() => owner.prohibit({ id, global: true, actions: [pick(ACTIONS)], resources: [pick(RESOURCES)], expiresAt: tick + Math.floor(rnd() * 100) }));
      else if (permissions.length > 0) await step(() => owner.revoke(pick(permissions)));
    }
    const store = api.openHistoryStore(config.historyFile, { inspect: true });
    try { return store.readAll().slice(); } finally { store.close(); }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  const dist = new URL("../../dist/", import.meta.url);
  const core = await import(new URL("index.js", dist).href);
  const { signerFromKeyPair } = await import(new URL("signer.js", dist).href);
  const events = await generateCandidateHistory({ ...core, signerFromKeyPair }, Number(process.argv[2] ?? 1), Number(process.argv[3] ?? 90));
  process.stdout.write(core.jsonStringifyWithBigints(events));
}
