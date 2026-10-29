// Remote witnesses through the CLI (docs/WITNESS.md §5): witness add / status / sync / remove, verify asking the
// witnesses (--no-remote, --allow-unreachable-witness), and the rc.1 residual attack refused by verify, readers and
// writers. The witness is the core's in-test fake (packages/core/test/helpers/fake-witness.mjs); the CLI runs as a
// child process, asynchronously, so the fake in this process can answer it. Build first (`pnpm build`).
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeWitness } from "../../core/test/helpers/fake-witness.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const BIN = resolve(here, "../bin/irontrellis.mjs");
assert.ok(existsSync(resolve(here, "../dist/cli.js")), "build the package first: pnpm build");

const run = (args, env = {}) => new Promise((done) => {
  const child = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: "1", ...env } });
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("close", (code) => done({ code, stdout, stderr }));
});
const json = async (args, env) => {
  const r = await run([...args, "--json"], env);
  let value;
  try { value = JSON.parse(r.stdout); } catch (error) { assert.fail(`not one JSON document (${error.message}):\n${r.stdout}\n${r.stderr}`); }
  return { ...r, value };
};
const ok = (r, message) => assert.equal(r.code, 0, `${message ?? "expected exit 0"}\n${r.stdout}\n${r.stderr}`);
const SUFFIXES = ["", ".head", ".anchors", ".witness.json"];
const snapshot = (h) => Object.fromEntries(SUFFIXES.map((x) => [x, existsSync(h + x) ? readFileSync(h + x) : undefined]));
const restore = (h, snap) => { for (const [x, bytes] of Object.entries(snap)) { if (bytes === undefined) rmSync(h + x, { force: true }); else writeFileSync(h + x, bytes, { mode: 0o600 }); } };

test("witness add / status / sync / remove, and verify asking the witness", async (t) => {
  const w = await startFakeWitness({ name: "cli-witness" });
  t.after(() => w.close());
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-cli-witness-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const history = join(dir, "history.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(await run(["init", "--owner", "ops"], env));
  assert.equal((await json(["witness", "status"], env)).value.error.code, "NO_WITNESS");

  const added = await json(["witness", "add", w.url, "--verifier-key", w.verifierKey, "--mode", "sync"], env);
  ok(added);
  assert.equal(added.value.submitted, true);
  assert.ok(added.value.eventId);
  const human = await run(["witness", "add", w.url, "--verifier-key", w.verifierKey, "--help"], env);
  assert.match(human.stdout, /--verifier-key <key>/);

  ok(await run(["agent", "create", "agent:a"], env));
  const status = await json(["witness", "status"], env);
  ok(status);
  assert.equal(status.value.remoteStatus, "OK");
  assert.equal(status.value.unwitnessedEvents, 0);
  assert.equal(status.value.witnesses[0].bound, true);
  assert.equal(status.value.remote[0].receiptVerified, true);
  const text = await run(["witness", "status"], env);
  ok(text);
  assert.match(text.stdout, /WITNESSED/);
  assert.match(text.stdout, /bound in the history/);
  assert.match(text.stdout, /verified with the configured key/);

  const verified = await json(["verify"], env);
  ok(verified);
  assert.equal(verified.value.report.remoteWitnessStatus, "OK");
  const offline = await json(["verify", "--no-remote"], env);
  ok(offline);
  assert.equal(offline.value.report.remoteWitnessStatus, "NOT_CONSULTED");

  // Witness down: the write is recorded and queued, verify fails closed unless allowed, sync submits once it is back.
  w.down = true;
  ok(await run(["agent", "create", "agent:b"], env));
  const down = await json(["verify"], env);
  assert.equal(down.code, 1);
  assert.ok(down.value.failures.some((f) => f.startsWith("REMOTE_WITNESS_UNREACHABLE")));
  ok(await run(["verify", "--allow-unreachable-witness"], env));
  const queued = await json(["witness", "sync"], env);
  assert.equal(queued.code, 1);
  assert.equal(queued.value.synced, false);
  w.down = false;
  const synced = await json(["witness", "sync"], env);
  ok(synced);
  assert.equal(synced.value.status.unwitnessedEvents, 0);

  const removed = await json(["witness", "remove", w.url], env);
  ok(removed);
  assert.ok(removed.value.eventId);
  assert.equal((await json(["witness", "status", "--no-remote"], env)).value.error.code, "NO_WITNESS");
});

test("the rc.1 residual attack through the CLI: verify, readers with --require-on-open and the next write refuse the restored copy", async (t) => {
  const w = await startFakeWitness({ name: "cli-attack" });
  t.after(() => w.close());
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-cli-witness-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const history = join(dir, "history.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(await run(["init", "--owner", "ops"], env));
  ok(await run(["witness", "add", w.url, "--verifier-key", w.verifierKey, "--mode", "sync", "--require-on-open", "--cache-ms", "0"], env));
  ok(await run(["agent", "create", "agent:a"], env));
  ok(await run(["anchor"], env));
  const old = snapshot(history);
  for (const id of ["agent:b", "agent:c", "agent:d"]) ok(await run(["agent", "create", id], env));
  restore(history, old);

  const offline = await run(["verify", "--no-remote"], env);
  ok(offline, "the copy is flawless on its own");
  const verdict = await json(["verify"], env);
  assert.equal(verdict.code, 1);
  assert.equal(verdict.value.error.code, "ROLLBACK_DETECTED");
  assert.ok(verdict.value.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")));
  const reader = await json(["status"], env);
  assert.equal(reader.value.error.code, "ROLLBACK_DETECTED");
  assert.equal(reader.value.error.context.reason, "WITNESS_AHEAD");
  const statements = w.state.statements.length;
  const writer = await run(["agent", "create", "agent:on-old-branch"], env);
  assert.equal(writer.code, 1);
  assert.match(writer.stderr, /ROLLBACK_DETECTED/);
  assert.match(writer.stderr, /past the end of this history file/);
  assert.equal(w.state.statements.length, statements, "no statement for the rolled-back copy");
  const status = await json(["witness", "status"], env);
  assert.equal(status.code, 1);
  assert.equal(status.value.remoteStatus, "ROLLBACK");
});

test("a recorded equivocation (§9.1) is a warning in verify and witness status, not a failure: the owner key signed a conflicting head", async (t) => {
  const { loadOwnerKeyFile, ownerKeyPathFor, openHistoryStore } = await import("@ramex-labs/irontrellis");
  const { signHeadStatement, HEAD_STATEMENT_VERSION } = await import("@ramex-labs/irontrellis/transparency");
  const w = await startFakeWitness({ name: "cli-equivocation" });
  t.after(() => w.close());
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-cli-witness-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const history = join(dir, "history.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(await run(["init", "--owner", "ops"], env));
  ok(await run(["witness", "add", w.url, "--verifier-key", w.verifierKey, "--mode", "sync"], env));
  for (const id of ["agent:a", "agent:b"]) ok(await run(["agent", "create", id], env));
  // Someone holding the owner key states another head at a position the witness holds, with a stale previous.
  const state = openHistoryStore(history, { witness: false, inspect: true }).state();
  const held = state.head.position - 1;
  const signer = loadOwnerKeyFile(ownerKeyPathFor(history));
  const conflicting = await signHeadStatement(signer, {
    version: HEAD_STATEMENT_VERSION, historyId: state.eventHistoryHashes[0], domain: state.genesis.domain,
    head: { hash: `0x${"5a".repeat(32)}`, position: held, canonicalTime: state.events[held].timestamp },
    previous: { hash: state.eventHistoryHashes[1], position: 1 },
  });
  const answer = await fetch(`${w.url}/v1/histories/${state.eventHistoryHashes[0]}/heads`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(conflicting) });
  assert.equal(answer.status, 409);
  assert.equal((await answer.json()).error.code, "EQUIVOCATION");

  const verified = await json(["verify"], env);
  ok(verified, "the file is on the witness chain: verify passes");
  assert.equal(verified.value.report.remoteWitnessStatus, "OK");
  assert.ok(verified.value.notes.some((n) => n.startsWith("REMOTE_WITNESS_EQUIVOCATION_RECORDED 1:")));
  assert.equal(verified.value.warnings.length, 1);
  const [warning] = verified.value.warnings;
  assert.equal(warning.code, "REMOTE_WITNESS_EQUIVOCATION_RECORDED");
  assert.equal(warning.witness, w.url);
  assert.equal(warning.equivocations, 1);
  assert.equal(warning.lastEquivocation.position, held);
  assert.match(warning.message, /the owner key signed a conflicting head; if you did not restore or roll back this history, treat the owner key as compromised and rotate it/);
  const text = await run(["verify"], env);
  ok(text);
  assert.match(text.stdout, /^VERIFIED/m);
  assert.match(text.stdout, /^WARNING {2}remote witness .* recorded 1 conflicting owner-signed head statement for this history/m);
  assert.match(text.stdout, /If you did not restore or roll back this history, treat the owner key as compromised and rotate it: irontrellis owner rotate-key\./);

  const status = await json(["witness", "status"], env);
  ok(status);
  assert.equal(status.value.ok, true);
  assert.equal(status.value.remote[0].equivocations, 1);
  assert.equal(status.value.warnings[0].code, "REMOTE_WITNESS_EQUIVOCATION_RECORDED");
  const statusText = await run(["witness", "status"], env);
  ok(statusText);
  assert.match(statusText.stdout, /equivocations +1 recorded/);
  assert.match(statusText.stdout, /^WARNING {2}/m);
  // The owner writes on: the history is not frozen.
  ok(await run(["agent", "create", "agent:c"], env));
  assert.equal(w.latest(state.eventHistoryHashes[0]).position, state.head.position + 1);
  // Clean histories carry no warnings.
  const clean = mkdtempSync(join(tmpdir(), "irontrellis-cli-witness-"));
  t.after(() => rmSync(clean, { recursive: true, force: true, maxRetries: 10 }));
  const cleanEnv = { IRONTRELLIS_HISTORY: join(clean, "history.jsonl") };
  ok(await run(["init", "--owner", "ops"], cleanEnv));
  ok(await run(["witness", "add", w.url, "--verifier-key", w.verifierKey, "--mode", "sync"], cleanEnv));
  const cleanVerify = await json(["verify"], cleanEnv);
  ok(cleanVerify);
  assert.deepEqual(cleanVerify.value.warnings, []);
  assert.doesNotMatch((await run(["verify"], cleanEnv)).stdout, /WARNING/);
});

test("owner rotate-key with a witness down: the output says to keep the retired key until every witness has recorded the rotation (never to destroy it); witness status shows the rotation pending, then recorded", async (t) => {
  const w = await startFakeWitness({ name: "cli-rotation-witness", seed: 51 });
  t.after(() => w.close());
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-cli-witness-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const history = join(dir, "history.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(await run(["init", "--owner", "ops", "--witness", w.url, "--verifier-key", w.verifierKey, "--mode", "sync"], env));
  // A-39.3: init --witness turns requireOnOpen on unless --no-require-on-open.
  assert.equal((await json(["witness", "status"], env)).value.policy.requireOnOpen, true);
  w.down = true;
  // WITNESS-DESIGN §11.2: the default two-phase rotation needs every bound witness; it aborts and writes nothing.
  const aborted = await json(["owner", "rotate-key", "--reason", "scheduled"], env);
  assert.equal(aborted.value.error.code, "WITNESS_UNAVAILABLE");
  assert.match(aborted.value.error.message, /rotation needs every bound witness; retry, or rotate with --emergency/);
  assert.equal(existsSync(`${history}.rotation.pending.json`), false);
  const rotated = await run(["owner", "rotate-key", "--reason", "scheduled", "--emergency"], env);
  ok(rotated);
  assert.match(rotated.stdout, /ROTATION INCOMPLETE/);
  assert.match(rotated.stdout, /bundle\s+.*key-event-\d+\.bundle\.json/);
  assert.doesNotMatch(rotated.stdout, /destroy it[,.]/i);
  assert.match(rotated.stdout, /Do not destroy it yet/);
  assert.match(rotated.stdout, /offline and backed up until every witness bound to the history has recorded the rotation \(irontrellis witness status shows it per witness\)/);
  w.down = false;
  const pending = await json(["witness", "status"], env);
  assert.deepEqual([pending.value.keyRotations, pending.value.commitmentRotations], [1, 0]);
  assert.equal(pending.value.witnesses[0].pendingRotations, 1, JSON.stringify(pending.value.witnesses[0]));
  const text = await run(["witness", "status"], env);
  assert.match(text.stdout, /rotations\s+PENDING: 1 of 1 not recorded yet: until it records them this witness still accepts heads signed by the retired key \(a leaked key can still fork it\); run irontrellis witness sync\. The retired key file\(s\) are still needed/);
  assert.match(text.stdout, /signed minimum\s+quorum 1 of the 1 bound witness/);
  assert.match(text.stdout, /Keep each retired owner key file/);
  ok(await run(["witness", "sync"], env));
  const recorded = await json(["witness", "status"], env);
  ok(recorded);
  assert.equal(recorded.value.witnesses[0].pendingRotations, 0);
  assert.match((await run(["witness", "status"], env)).stdout, /rotations\s+recorded \(every owner key rotation\)/);
  const offline = await json(["witness", "status", "--no-remote"], env);
  assert.equal(offline.value.witnesses[0].pendingRotations, null, "not asked: unknown");
});
