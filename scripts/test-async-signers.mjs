#!/usr/bin/env node
// Every owner code path works with an asynchronous-only signer (an ssh-agent, a command signer, a KMS).
// Runs the owner, rotation, two-phase and witness suites (core, the witness server's end-to-end tests, the CLI and the
// hooks) with IRONTRELLIS_TEST_ASYNC_SIGNERS=1: every signer built from local key material then has no `signHashSync`
// and answers after a macrotask. Child processes (the CLI, the hook, the witness server) inherit the switch.
// Build first (pnpm -r build): the witness, CLI and hooks suites run the built packages.
//
//   node scripts/test-async-signers.mjs [core|witness|cli|hooks …]
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const SUITES = {
  core: ["owner", "owner-key-rotation", "pre-rotation", "two-phase-rotation", "witness-integration", "witness-hardening", "witness-review", "witness-client", "migrate", "lifecycle", "runtime", "custody", "custody-examples"]
    .map((name) => `test/${name}.test.mjs`),
  // fuzz-smoke is left out: its harness signs statements with signHeadStatementSync on purpose (it drives the wire format).
  witness: ["cli", "crash", "differential", "e2e-availability", "e2e-equivocation", "e2e-network", "e2e-prerotation", "e2e-rollback", "e2e-rotation", "e2e-custody", "http", "key-events", "local-owner", "persistence", "platform", "state"]
    .map((name) => `test/${name}.test.mjs`),
  cli: ["cli", "witness", "custody", "doctor"].map((name) => `test/${name}.test.mjs`),
  hooks: ["hook", "platform", "tripwire", "witness", "custody"].map((name) => `test/${name}.test.mjs`),
};
const chosen = process.argv.slice(2).length > 0 ? process.argv.slice(2) : Object.keys(SUITES);
let failed = false;
for (const name of chosen) {
  const files = SUITES[name];
  if (files === undefined) { console.error(`unknown suite ${name} (${Object.keys(SUITES).join(", ")})`); process.exit(2); }
  console.log(`\n== ${name} with IRONTRELLIS_TEST_ASYNC_SIGNERS=1`);
  const result = spawnSync(process.execPath, ["--test", "--experimental-strip-types", ...files], {
    cwd: join(root, "packages", name), stdio: "inherit", env: { ...process.env, IRONTRELLIS_TEST_ASYNC_SIGNERS: "1" },
  });
  if (result.status !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
