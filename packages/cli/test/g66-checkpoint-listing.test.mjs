import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createLocalOwner, createLocalDomain, keyPairFromPrivateKey, signHashWith } from "@ramex-labs/irontrellis";
const BIN = fileURLToPath(new URL("../bin/irontrellis.mjs", import.meta.url));
// Public, synthetic test-only seeds. No user key or live service is used.
const pair = (id, n) => keyPairFromPrivateKey("ed25519", id, `0x${n.toString(16).padStart(64, "0")}`);
const publicKey = ({ keyId, scheme, credential }) => ({ keyId, scheme, credential });

test("verify lists a valid committee-dependent checkpoint policy without changing verdict or history bytes", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-a151-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const history = join(dir, "history.jsonl");
  const h1 = pair("h1", 0x15101), h2 = pair("h2", 0x15102), committee = pair("committee", 0x15103);
  const policy = { threshold: 1, keyClasses: { committee: "AGENT" }, byType: { STATE_CHECKPOINT: 3 } };
  const owner = await createLocalOwner({ historyFile: history, domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => 1000,
    signer: { ...publicKey(h1), signHash: signHashWith(h1) }, coOwnerKeys: [publicKey(h2), publicKey(committee)], ownerPolicy: policy });
  await owner.flush(); owner.close();
  const before = readFileSync(history);
  const result = spawnSync(process.execPath, [BIN, "verify", "--history", history, "--no-remote", "--json"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, true); assert.equal(report.checkpointPolicies.status, "LISTED");
  assert.deepEqual(report.checkpointPolicies.policies, [{ fromPosition: 0, policy, checkpointThreshold: 3, nonAgentCredentials: 2 }]);
  assert.deepEqual(readFileSync(history), before);
  const human = spawnSync(process.execPath, [BIN, "verify", "--history", history, "--no-remote"], { encoding: "utf8" });
  assert.equal(human.status, 0, human.stdout + human.stderr); assert.match(human.stdout, /Checkpoint policy at position 0/);
});
