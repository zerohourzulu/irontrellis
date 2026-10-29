#!/usr/bin/env node
import { mkdirSync, writeFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair } from "@ramex-labs/irontrellis";
import { createLocalOwner, createLocalDomain } from "@ramex-labs/irontrellis/local";
import { selectEvidence } from "@ramex-labs/irontrellis/evidence";
export async function createDemo(target) {
  mkdirSync(resolve(target), { mode: 0o700 });
  const dir = realpathSync(target),
    inputDirectory = join(dir, "source"),
    outputDirectory = join(dir, "packets");
  mkdirSync(inputDirectory, { mode: 0o700 });
  mkdirSync(outputDirectory, { mode: 0o700 });
  writeFileSync(
    join(inputDirectory, "incident.txt"),
    "Synthetic example: unusual access requires review.\n",
    { mode: 0o600 },
  );
  const pair = generateKeyPair("ed25519", "key:bea"),
    key = pair.privateKey,
    keyFile = join(dir, "runtime.key");
  writeFileSync(keyFile, key + "\n", { mode: 0o600 });
  const ownerConfig = {
    historyFile: join(dir, "history.jsonl"),
    domain: createLocalDomain(),
    owner: "operations",
    controller: "operator",
  };
  const owner = await createLocalOwner({ ...ownerConfig, now: Date.now });
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({
    agent: "bea",
    role: "reviewer",
    tenure: "first-shift",
    number: 1,
  });
  await owner.admitRuntime({
    session: "session:bea",
    agent: "bea",
    epoch: 1,
    key: "key:bea",
    credential: pair.credential,
    expiresAt: Date.now() + 3600_000,
  });
  await owner.grant({
    id: "collect",
    to: "bea",
    actions: ["collect-evidence-packet"],
    resources: ["incident:42"],
    expiresAt: Date.now() + 3600_000,
  });
  const config = {
    ...ownerConfig,
    session: "session:bea",
    role: "reviewer",
    tenure: "first-shift",
    resource: "incident:42",
    inputDirectory,
    outputDirectory,
    selection: selectEvidence(inputDirectory),
    keyFile,
  };
  const configFile = join(dir, "gateway.json");
  writeFileSync(configFile, JSON.stringify(config, null, 2) + "\n", {
    mode: 0o600,
  });
  return { configFile, config, ownerConfig, owner };
}
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    if (process.argv.length !== 3) throw Error("TARGET_REQUIRED");
    const demo = await createDemo(process.argv[2]);
    console.log("Fresh synthetic case created. Keep this directory private.");
    console.log("Configuration:", demo.configFile);
  } catch {
    console.error(
      "Setup failed. Use a new target directory whose parent exists.",
    );
    process.exitCode = 2;
  }
}
