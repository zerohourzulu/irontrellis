// G6 round 1 (A-91, A-96.4): `owner rotate-key` / `owner commit-next-key` under an owner approval policy, and
// `owner status` showing it. Build first (`pnpm build`).
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const BIN = resolve(here, "../bin/irontrellis.mjs");
assert.ok(existsSync(resolve(here, "../dist/cli.js")), "build the package first: pnpm build");
const core = await import("@ramex-labs/irontrellis");

const json = (args) => {
  const r = spawnSync(process.execPath, [BIN, ...args, "--json"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  return { code: r.status, value: JSON.parse(r.stdout), stdout: r.stdout, stderr: r.stderr };
};

test("owner rotate-key under a policy: refused without --owner-policy or --reset-policy (POLICY_RESET); both flags work; owner status shows it", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g6-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const history = join(dir, "history.jsonl");
  assert.equal(json(["init", "--history", history, "--owner", "operations", "--controller", "operator"]).code, 0);
  const state = core.openHistoryStore(history).state();
  const owner = core.openLocalOwner({ historyFile: history, domain: state.genesis.domain, owner: "operations", controller: "operator", now: () => Date.now() });
  const policy = { threshold: 1, labels: { "owner:1": "laptop" } };
  await owner.rotateOwnerPolicy({ ownerPolicy: policy });
  await owner.flush();
  owner.close();

  const status = json(["owner", "status", "--history", history]);
  assert.equal(status.code, 0, status.stderr);
  assert.deepEqual([status.value.ownerPolicy, status.value.policyRotations], [policy, 1]);

  const refused = json(["owner", "rotate-key", "--history", history]);
  assert.equal(refused.code, 1);
  assert.equal(refused.value.error.code, "INVALID_INPUT");
  assert.match(refused.value.error.message, /--owner-policy <file>.*--reset-policy/);
  assert.equal(json(["owner", "rotate-key", "--history", history, "--reset-policy", "--owner-policy", "x.json"]).value.error.code, "USAGE");

  // Restated for the new key id: the policy follows the keys.
  const file = join(dir, "policy.json");
  writeFileSync(file, JSON.stringify({ threshold: 1, labels: { "owner:2": "laptop" } }));
  const kept = json(["owner", "rotate-key", "--history", history, "--owner-policy", file]);
  assert.equal(kept.code, 0, kept.stdout);
  assert.deepEqual(json(["owner", "status", "--history", history]).value.ownerPolicy, { threshold: 1, labels: { "owner:2": "laptop" } });
  assert.equal(core.openHistoryStore(history).state().events.at(-1).data.ownerPolicy.labels["owner:2"], "laptop");

  const reset = json(["owner", "rotate-key", "--history", history, "--reset-policy"]);
  assert.equal(reset.code, 0, reset.stdout);
  const after = json(["owner", "status", "--history", history]).value;
  assert.equal(after.ownerPolicy, null);
  assert.equal(json(["verify", "--history", history]).code, 0);
});
