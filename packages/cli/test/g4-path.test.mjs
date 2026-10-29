// The G4 install-rehearsal path (BUILD-INSTRUCTIONS §2 G4) as a test, through the built binaries: the CLI
// `init → grant → budget declare → authorize → (refusal recorded) → checkpoint → verify → export → migrate --status`,
// one hook dry-run, and one duty `describe → activate → dispose → inspect` on the gateway's investigation demo case.
// RESULTS-DRAFT/INSTALL-REHEARSAL.md lists the same commands. Plus the other format-2 commands (budget update/close,
// counterparties, export verify on a tampered view, duty contest). Build first: pnpm -r build.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const CLI = resolve(here, "../bin/irontrellis.mjs");
const HOOK = resolve(here, "../../hooks/bin/irontrellis-hook.mjs");
const GATEWAY = resolve(here, "../../mcp-gateway/dist/cli.js");
for (const bin of [CLI, HOOK, GATEWAY]) assert.ok(existsSync(bin), `build first (pnpm -r build): ${bin}`);
const core = await import("@ramex-labs/irontrellis");

const spawn = (bin, args, options = {}) => {
  const r = spawnSync(process.execPath, [bin, ...args], { encoding: "utf8", cwd: options.cwd, input: options.input, env: { ...process.env, NO_COLOR: "1", ...options.env } });
  let json;
  try { json = JSON.parse(r.stdout); } catch { json = undefined; }
  return { code: r.status, stdout: r.stdout, stderr: r.stderr, json };
};
const ok = (r, what) => { assert.equal(r.code, 0, `${what ?? "expected exit 0"}\n${r.stdout}\n${r.stderr}`); return r; };
const scratch = (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g4-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  return dir;
};

test("G4: init → grant → budget declare → authorize → refusal recorded → checkpoint → verify → export → migrate --status", (t) => {
  const dir = scratch(t), history = join(dir, "history.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  const it = (args, extra = {}) => spawn(CLI, [...args, "--json"], { env, ...extra });
  const init = ok(it(["init", "--owner", "ops"]));
  assert.equal(init.json.format, "irontrellis-event/2");
  ok(it(["agent", "create", "bea"]));
  const session = ok(it(["session", "admit", "s:bea", "--agent", "bea", "--epoch", "1", "--key", "k:bea", "--expires", "+1d", "--new-key", join(dir, "bea.key")]));
  assert.equal(session.json.keyFile, join(dir, "bea.key"));
  ok(it(["grant", "pay", "--to", "bea", "--actions", "pay", "--resources", "vendor:1", "--expires", "+1d"]));
  const budget = ok(it(["budget", "declare", "spend", "--actors", "bea", "--amount-cap", "100", "--per-operation-cap", "60"]));
  assert.ok(budget.json.warnings.some((w) => w.startsWith("NO_WITNESS")), "A-39.3: no witness is bound");
  assert.ok(budget.json.warnings.some((w) => w.startsWith("ADMITTED_ONLY")), "A-25.1");
  // Within the budget: ALLOW, nothing written.
  const within = it(["authorize", "--actor", "bea", "--action", "pay", "--resource", "vendor:1", "--amount", "50"]);
  assert.equal(within.code, 0, within.stdout);
  assert.equal(within.json.decision, "ALLOW");
  // Over the per-request cap: DENY by the budget, recorded as a BUDGET refusal signed by bea's session.
  const before = core.openHistoryStore(history).state().events.length;
  const over = it(["authorize", "--actor", "bea", "--action", "pay", "--resource", "vendor:1", "--amount", "80", "--record-refusal", "--session", "s:bea", "--session-key", join(dir, "bea.key")]);
  assert.equal(over.code, 2, over.stdout + over.stderr);
  assert.equal(over.json.evidence.code, "BUDGET_PER_OPERATION_EXCEEDED");
  assert.equal(over.json.refusal.recorded, true);
  const refusal = core.openHistoryStore(history).state().events.at(-1);
  assert.equal(core.openHistoryStore(history).state().events.length, before + 1);
  assert.deepEqual([refusal.type, refusal.data.refusalSource, refusal.data.budgetId, refusal.data.runtimeSessionId], ["REQUEST_REFUSED", "BUDGET", "spend", "s:bea"]);
  // An ALLOW is never recorded as a refusal; --record-refusal needs the writer's own time.
  assert.equal(it(["authorize", "--actor", "bea", "--action", "pay", "--resource", "vendor:1", "--amount", "10", "--record-refusal", "--session", "s:bea", "--session-key", join(dir, "bea.key")]).json.refusal, undefined);
  assert.equal(it(["authorize", "--actor", "bea", "--action", "pay", "--resource", "vendor:1", "--record-refusal", "--session", "s:bea", "--session-key", join(dir, "bea.key"), "--at", "1"]).json.error.code, "USAGE");
  // Checkpoint, list, verify against a full replay.
  const checkpoint = ok(it(["checkpoint", "create"]));
  assert.match(checkpoint.json.stateRoot, /^0x[0-9a-f]{64}$/);
  const listed = ok(it(["checkpoint", "list"]));
  assert.equal(listed.json.checkpoints.length, 1);
  assert.equal(listed.json.checkpoints[0].stateRoot, checkpoint.json.stateRoot);
  const checked = ok(it(["checkpoint", "verify"]));
  assert.deepEqual([checked.json.ok, checked.json.mode, checked.json.checkpoints[0].ok], [true, "FULL_REPLAY", true]);
  // status: the state root, its record count, the projection head and the latest checkpoint.
  const status = ok(it(["status"]));
  assert.match(status.json.stateRoot, /^0x[0-9a-f]{64}$/);
  assert.equal(typeof status.json.recordCount, "number");
  assert.match(status.json.projectionHead, /^0x[0-9a-f]{64}$/);
  assert.equal(status.json.checkpoint.checkpointId, listed.json.checkpoints[0].checkpointId);
  assert.equal(status.json.refusals, 1);
  // verify: the replay's root, and the pin's /2 attestation names it.
  const verified = ok(it(["verify"]));
  assert.equal(verified.json.report.stateRoot, status.json.stateRoot);
  const pin = JSON.parse(readFileSync(`${history}.head`, "utf8"));
  assert.equal(pin.attestation.version, "irontrellis-head-attestation/2");
  assert.equal(pin.attestation.stateRoot, status.json.stateRoot);
  assert.match(spawn(CLI, ["verify"], { env }).stdout, /pin state root\s+MATCHES at position/);
  // export: the view of a range with the records at both ends, checked on its own.
  const head = status.json.head.position;
  const view = spawn(CLI, ["export", "--from", "2", "--to", String(head), "--records"], { env });
  ok(view);
  const file = join(dir, "view.json");
  writeFileSync(file, view.stdout);
  assert.equal(JSON.parse(view.stdout).version, "irontrellis-export/2");
  const exported = ok(it(["export", "verify", file]));
  assert.equal(exported.json.ok, true);
  assert.equal(exported.json.to.verified, true);
  // Plain export still prints the events.
  assert.equal(JSON.parse(spawn(CLI, ["export"], { env }).stdout).length, head + 1);
  // migrate --status on a history created in format 2.
  const migrated = ok(it(["migrate", "--status"]));
  assert.equal(migrated.json.kind, "NATIVE_FORMAT_2");
});

test("G4: one hook dry-run on a format-2 history the hook created (no opt-in in its config)", (t) => {
  const dir = scratch(t), project = join(dir, "project"), home = join(dir, "home");
  spawnSync("mkdir", ["-p", project]);
  const env = { IRONTRELLIS_HOME: home };
  ok(spawn(HOOK, ["init", "--allow", "run-shell", "--expires", "+1d", "--i-understand-same-user-risk"], { cwd: project, env }));
  const config = JSON.parse(readFileSync(join(project, "irontrellis-hook.json"), "utf8"));
  assert.equal(config.enforceFromReadOnlyHistory, undefined);
  assert.equal(core.openHistoryStore(config.history).format, "irontrellis-event/2");
  const allowed = spawn(HOOK, ["check", "claude-code", "Bash", "--input", JSON.stringify({ command: "npm test" })], { cwd: project, env });
  ok(allowed);
  assert.match(allowed.stdout + allowed.stderr, /ALLOW/);
  const denied = spawn(HOOK, ["check", "claude-code", "Write", "--input", JSON.stringify({ file_path: join(project, "a.txt"), content: "x" })], { cwd: project, env });
  assert.match(denied.stdout + denied.stderr, /DENY/);
});

test("G4: one duty describe → activate → dispose → inspect on the gateway's investigation demo case (and a contest, and an exact repeat)", (t) => {
  const dir = scratch(t), caseDir = join(dir, "case");
  const setup = spawn(GATEWAY, ["setup", caseDir, "--investigation"]);
  ok(setup);
  assert.match(setup.stdout, /Investigation: duty:incident-42/);
  const history = join(caseDir, "history.jsonl"), env = { IRONTRELLIS_HISTORY: history };
  const it = (args) => spawn(CLI, [...args, "--json"], { env });
  const session = ["--session", "worker:1", "--session-key", join(caseDir, "worker.key")];
  const selection = ["--incident", join(caseDir, "incident.txt"), "--attester-role", "analyst"];
  const described = ok(it(["duty", "describe", "duty:incident-42", ...selection, ...session]));
  assert.equal(described.json.grantsAuthority, false);
  assert.match(described.json.activationResource, /^duty-policy:0x[0-9a-f]{64}$/);
  assert.equal(described.json.next.length, 3);
  assert.equal(it(["duty", "inspect", "duty:incident-42"]).json.policy, null);
  ok(it(["grant", "duty:activate", "--to", "worker", "--actions", "ACTIVATE_DUTY_POLICY", "--resources", described.json.activationResource, "--expires", "+1h"]));
  const activated = ok(it(["duty", "activate", "investigation", "--duty", "duty:incident-42", ...selection, "--authority", "duty:activate", ...session]));
  assert.deepEqual([activated.json.alreadyRecorded, activated.json.view.dutyDisposition], [false, "OPEN"]);
  for (const [grant, action] of [["duty:attest", "ATTEST_DUTY_FINDING"], ["duty:dispose", "RECORD_DUTY_DISPOSITION"]]) {
    ok(it(["grant", grant, "--to", "worker", "--actions", action, "--resources", described.json.findingResource, "--expires", "+1d"]));
  }
  const report = join(caseDir, "report.json");
  writeFileSync(report, `${JSON.stringify({ purpose: "Local investigation report", externalOutcome: "NOT_PROVEN" })}\n`);
  chmodSync(report, 0o600);
  const finding = ["--duty", "duty:incident-42", "--disposition", "COMPLETED_UNDER_POLICY", "--report", report, "--all-satisfied", "Reviewed the incident and the case; the outside result is still not proven.",
    "--attestation-authority", "duty:attest", "--disposition-authority", "duty:dispose", ...session];
  const disposed = ok(it(["duty", "dispose", "first", ...finding]));
  assert.deepEqual([disposed.json.alreadyRecorded, disposed.json.view.dutyDisposition, disposed.json.view.externalOutcome], [false, "COMPLETED_UNDER_POLICY", "NOT_PROVEN"]);
  const inspected = ok(it(["duty", "inspect", "duty:incident-42"]));
  assert.deepEqual([inspected.json.policy.dutyDisposition, inspected.json.policy.outstanding, inspected.json.executionCapability], ["COMPLETED_UNDER_POLICY", false, false]);
  // An exact repeat signs and writes nothing.
  const events = core.openHistoryStore(history).state().events.length;
  assert.equal(ok(it(["duty", "dispose", "first", ...finding])).json.alreadyRecorded, true);
  assert.equal(core.openHistoryStore(history).state().events.length, events);
  // A contest of the finding.
  const contested = ok(it(["duty", "contest", "challenge", "--duty", "duty:incident-42", "--target", "duty-disposition:first", "--reason", "The service log may be incomplete.",
    "--report-digest", `0x${"c".repeat(64)}`, "--attestation-authority", "duty:attest", "--disposition-authority", "duty:dispose", ...session]));
  assert.equal(contested.json.view.dutyDisposition, "CONTESTED");
  // A key file that is not the session's own is refused before anything is signed.
  const wrong = join(caseDir, "wrong.key");
  writeFileSync(wrong, `${core.generateKeyPair("ed25519", "x").privateKey}\n`, { mode: 0o600 });
  assert.equal(it(["duty", "describe", "duty:incident-42", ...selection, "--session", "worker:1", "--session-key", wrong]).json.error.code, "KEY_MISMATCH");
});

test("budget update / close / show / headroom; counterparty register / rotate / receipts / retire; a tampered export view fails export verify", (t) => {
  const dir = scratch(t), history = join(dir, "history.jsonl"), env = { IRONTRELLIS_HISTORY: history };
  const it = (args) => spawn(CLI, [...args, "--json"], { env });
  ok(it(["init"]));
  ok(it(["agent", "create", "bea"]));
  ok(it(["role", "create", "buyer"]));
  ok(it(["budget", "declare", "monthly", "--roles", "buyer", "--amount-cap", "1000", "--period-ms", "86400000", "--carry-unused", "--carry-cap", "500"]));
  assert.equal(it(["budget", "declare", "monthly", "--amount-cap", "5"]).json.error.code, "TRANSITION_REJECTED");
  assert.equal(it(["budget", "declare", "nocap"]).json.error.code, "USAGE");
  ok(it(["budget", "update", "monthly", "--amount-cap", "800", "--count-cap", "10"]));
  const shown = ok(it(["budget", "show", "monthly"]));
  assert.deepEqual([shown.json.budgets[0].budget.amountCap, shown.json.budgets[0].budget.countCap, shown.json.budgets[0].budget.subjects.roleIds], ["800", 10, ["buyer"]]);
  const headroom = ok(it(["budget", "headroom", "monthly"]));
  assert.deepEqual([headroom.json.remainingAmount, headroom.json.remainingCount], ["800", 10]);
  ok(it(["budget", "update", "monthly", "--clear", "count-cap"]));
  assert.equal(ok(it(["budget", "show", "monthly"])).json.budgets[0].budget.countCap, null);
  ok(it(["budget", "close", "monthly"]));
  assert.equal(ok(it(["budget", "show"])).json.budgets[0].budget.status, "CLOSED");
  assert.equal(it(["budget", "headroom", "absent"]).json.error.code, "INVALID_INPUT");
  // Counterparties.
  const k1 = core.generateKeyPair("ed25519", "acme:1"), k2 = core.generateKeyPair("ed25519", "acme:2");
  ok(it(["counterparty", "register", "acme", "--key", `acme:1=${k1.credential}`]));
  assert.equal(it(["counterparty", "register", "acme", "--key", `acme:1=${k1.credential}`]).json.error.code, "TRANSITION_REJECTED");
  const rotated = ok(it(["counterparty", "rotate", "acme", "--key", `acme:2=${k2.credential}`]));
  assert.equal(typeof rotated.json.retiredEventId, "string");
  const receipts = ok(it(["counterparty", "receipts", "acme"]));
  assert.deepEqual([receipts.json.status, receipts.json.keyIds, receipts.json.receiptCount, receipts.json.receipts], ["ACTIVE", ["acme:2"], 0, []]);
  ok(it(["counterparty", "retire", "acme"]));
  assert.equal(ok(it(["counterparty", "receipts", "acme"])).json.status, "RETIRED");
  // A view whose stated end root is altered fails on its own.
  const view = JSON.parse(spawn(CLI, ["export", "--view"], { env }).stdout);
  const file = join(dir, "view.json");
  writeFileSync(file, JSON.stringify({ ...view, to: { ...view.to, stateRoot: `0x${"0".repeat(64)}` } }));
  const failed = it(["export", "verify", file]);
  assert.equal(failed.code, 1);
  assert.equal(failed.json.ok, false);
  assert.equal(it(["export", "--records"]).json.error.code, "USAGE");
});

test("an older history: format-2 reads say what they need, writes are FORMAT_READ_ONLY with the reason, plain export and status still work", async (t) => {
  const { olderHistory, FORMAT_1 } = await import("./older-formats.mjs");
  const dir = scratch(t), history = await olderHistory(join(dir, "f1.jsonl"), FORMAT_1);
  const env = { IRONTRELLIS_HISTORY: history };
  const it = (args) => spawn(CLI, [...args, "--json"], { env });
  const status = ok(it(["status"]));
  assert.deepEqual([status.json.format, status.json.readOnly], [FORMAT_1, "FORMAT_1"]);
  assert.match(spawn(CLI, ["status"], { env }).stdout, /read only\s+yes: a format-1 history/);
  assert.equal(it(["budget", "show"]).json.error.code, "UNSUPPORTED_FORMAT");
  const write = it(["agent", "create", "bea"]);
  assert.deepEqual([write.json.error.code, write.json.error.context.reason], ["FORMAT_READ_ONLY", "FORMAT_1"]);
  assert.equal(it(["checkpoint", "create"]).json.error.code, "FORMAT_READ_ONLY");
  assert.equal(it(["migrate", "--status"]).json.kind, "NEEDS_MIGRATION");
  assert.ok(Array.isArray(JSON.parse(spawn(CLI, ["export"], { env }).stdout)));
});
