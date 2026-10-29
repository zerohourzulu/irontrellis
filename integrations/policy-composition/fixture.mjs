import { preserveHistories } from './tests/preserve.mjs';
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  realpathSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import {
  createLocalDomain,
  createLocalOwner,
} from "@ramex-labs/irontrellis/local";
import {
  openLocalEvidenceTool,
  selectEvidence,
} from "@ramex-labs/irontrellis/evidence";
import {
  openLocalExecution,
  commitTerms,
} from "@ramex-labs/irontrellis/local";
import { generateKeyPair, signHashWith } from "@ramex-labs/irontrellis";
const code = (value) => (e) => e.code === value;
export async function setup(t) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-evidence-")));
  t.after(() => { preserveHistories(dir); rmSync(dir, { recursive: true, force: true }); });
  const inputDirectory = join(dir, "source"),
    outputDirectory = join(dir, "packets");
  mkdirSync(inputDirectory, { mode: 0o700 });
  mkdirSync(outputDirectory, { mode: 0o700 });
  writeFileSync(
    join(inputDirectory, "incident.txt"),
    "Synthetic event: review this.\n",
    { mode: 0o600 },
  );
  const pair = generateKeyPair("ed25519", "key"),
    config = {
      historyFile: join(dir, "history.jsonl"),
      domain: createLocalDomain(),
      owner: "operations",
      controller: "operator",
      now: () => 100,
    };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift", number: 1 });
  await owner.admitRuntime({
    session: "session",
    agent: "bea",
    epoch: 1,
    key: "key",
    credential: pair.credential,
    expiresAt: 200,
  });
  await owner.grant({
    id: "collect",
    to: "bea",
    actions: ["collect-evidence-packet"],
    resources: ["incident:42"],
    expiresAt: 200,
  });
  const options = {
    ...config,
    session: "session",
    signHash: signHashWith(pair),
    inputDirectory,
    outputDirectory,
    selection: selectEvidence(inputDirectory),
    resource: "incident:42",
    role: "reviewer",
    tenure: "shift",
  };
  const tool = openLocalEvidenceTool(options),
    request = { operationId: "collect:42", resource: "incident:42" };
  return { tool, owner, options, request, config };
}
