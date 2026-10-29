// End-to-end tests: the built CLI (`node bin/irontrellis.mjs …`) is spawned
// against a temporary history through the full scenario, then compared with
// the core API on the demo history. Build first (`pnpm build`).
import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync, realpathSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const BIN = resolve(here, "../bin/irontrellis.mjs");
assert.ok(existsSync(resolve(here, "../dist/cli.js")), "build the package first: pnpm build");
const { COMMANDS, demo } = await import("../dist/cli.js");
const core = await import("@ramex-labs/irontrellis");
const { LEGACY, olderHistory } = await import("./older-formats.mjs");

const VENDORED_FIXTURE = resolve(here, "../../reference-0.2/tests/fixtures/handover-history.jsonl");

const run = (args, options = {}) => {
  const result = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1", ...options.env }, cwd: options.cwd });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
};
const json = (args, options) => {
  const r = run([...args, "--json"], options);
  let value;
  try { value = JSON.parse(r.stdout); } catch (error) { assert.fail(`not one JSON document (${error.message}):\n${r.stdout}\n${r.stderr}`); }
  return { ...r, value };
};
/** The CLI as a child process that does not block the test (for lock tests). */
const runAsync = (args, options = {}) => new Promise((resolveRun) => {
  const child = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: "1", ...options.env } });
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("close", (code) => resolveRun({ code, stdout, stderr }));
});
const ok = (r, message) => assert.equal(r.code, 0, `${message ?? "expected exit 0"}\n${r.stdout}\n${r.stderr}`);

const tempDir = (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-cli-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  return dir;
};

// ------------------------------------------------------------------ the scenario, command by command

test("the scenario through the CLI: init → structure → grants → decisions → succession → handover → verify", async (t) => {
  const dir = tempDir(t), history = join(dir, "history.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };

  const init = json(["init", "--owner", "operations", "--controller", "operator", "--max-events", "200"], { env });
  ok(init);
  assert.equal(init.value.format, "irontrellis-event/2");
  assert.equal(init.value.owner, "operations");
  assert.match(init.value.historyId, /^0x[0-9a-f]{64}$/, "A-41.3: init prints the historyId readers pin");
  // Genesis (committed to a next key: pre-rotation, on by default) and principal.
  assert.equal(init.value.head.position, 1);
  assert.ok(existsSync(`${history}.owner-key.json`));
  assert.equal(init.value.nextKeyFile, `${history}.owner-next-key.json`);
  assert.equal(init.value.nextKeyCommitted, true);
  assert.deepEqual(init.value.warnings.map((w) => w.code), ["NEXT_KEY_ON_HOST"]);
  assert.equal(json(["init"], { env }).value.error.code, "HISTORY_EXISTS");

  for (const id of ["bea", "alex"]) {
    const r = json(["agent", "create", id], { env });
    ok(r);
    assert.equal(r.value.recorded, `agent ${id}`);
    assert.match(r.value.eventId, /^event:/);
  }
  ok(json(["role", "create", "reviewer"], { env }));
  ok(json(["succession", "declare", "handover", "--from", "bea", "--to", "alex", "--role", "reviewer"], { env }));
  ok(json(["appoint", "bea", "--role", "reviewer", "--tenure", "shift:1", "--number", "1", "--succession", "handover"], { env }));

  const keyFile = join(dir, "bea.key.json");
  const admitted = json(["session", "admit", "session:bea", "--agent", "bea", "--epoch", "1", "--key", "key:bea", "--expires", "+1d", "--new-key", keyFile], { env });
  ok(admitted);
  assert.equal(admitted.value.keyFile, keyFile);
  const key = JSON.parse(readFileSync(keyFile, "utf8"));
  assert.equal(key.scheme, "ed25519");
  assert.match(key.credential, /^0x[0-9a-f]{64}$/);
  const bare = json(["session", "admit", "session:x", "--agent", "bea", "--epoch", "1", "--key", "key:x", "--expires", "+1d"], { env });
  assert.equal(bare.value.error.code, "USAGE");

  ok(json(["grant", "collect", "--to", "bea", "--actions", "read,collect", "--resources", "incident:42", "--expires", "+12h", "--delegable", "1"], { env }));
  const dup = json(["grant", "collect", "--to", "bea", "--actions", "read", "--resources", "incident:42", "--expires", "+12h"], { env });
  assert.equal(dup.code, 1);
  assert.equal(dup.value.error.code, "TRANSITION_REJECTED");
  assert.match(dup.value.error.message, /refuse/);

  // Decisions: ALLOW exits 0, DENY exits 2.
  const allow = json(["authorize", "--actor", "bea", "--action", "read", "--resource", "incident:42"], { env });
  assert.equal(allow.code, 0);
  assert.equal(allow.value.decision, "ALLOW");
  assert.equal(allow.value.scope, "CAPTURED_HISTORY_ONLY");
  const deny = json(["authorize", "--actor", "alex", "--action", "read", "--resource", "incident:42"], { env });
  assert.equal(deny.code, 2);
  assert.equal(deny.value.decision, "DENY");
  assert.equal(deny.value.evidence.code, "NO_AUTHORITY");

  // Delegation and prohibition.
  ok(json(["delegate", "sub", "--parent", "collect", "--from", "bea", "--to", "alex", "--actions", "read", "--resources", "incident:42", "--expires", "+1h"], { env }));
  assert.equal(json(["authorize", "--actor", "alex", "--action", "read", "--resource", "incident:42"], { env }).value.decision, "ALLOW");
  ok(json(["prohibit", "no-alex", "--actions", "read", "--resources", "incident:42", "--subject", "alex", "--root", "collect", "--expires", "+2h"], { env }));
  const prohibited = json(["why", "--actor", "alex", "--action", "read", "--resource", "incident:42"], { env });
  assert.equal(prohibited.value.epistemicStatus, "ESTABLISHED");
  assert.equal(prohibited.value.answer.authorization.decision, "DENY");
  assert.equal(prohibited.value.answer.authorization.code, "PROHIBITED");
  ok(json(["revoke", "no-alex"], { env }));
  const why = json(["why", "--actor", "alex", "--action", "read", "--resource", "incident:42"], { env });
  assert.equal(why.value.answer.authorization.decision, "ALLOW");
  assert.deepEqual(why.value.answer.authorization.proof.permissionPath.map((g) => g.authorityId), ["collect", "sub"]);
  const human = run(["why", "--actor", "alex", "--action", "read", "--resource", "incident:42"], { env });
  ok(human);
  assert.match(human.stdout, /^◆ irontrellis \d+\.\d+\.\d+.* — agents change\. the structure holds\.\n/);
  assert.match(human.stdout, /\nALLOW  alex: read on incident:42/);
  assert.match(human.stdout, /collect \(operations → bea\) › sub \(bea → alex\)/);

  const responsible = json(["responsible", "--actor", "alex", "--action", "read", "--resource", "incident:42"], { env });
  assert.equal(responsible.value.answer.authorizationDecision, "ALLOW");
  assert.ok(responsible.value.answer.attributions.some((a) => a.kind === "ACTOR" && a.subjectId === "alex"));
  assert.ok(responsible.value.answer.attributions.some((a) => a.kind === "AUTHORITY_SOURCE" && a.subjectId === "collect"));

  // Status and capacity before the handover.
  const status = json(["status"], { env });
  ok(status);
  assert.equal(status.value.capacity.maxEvents, 200);
  assert.equal(status.value.capacity.mode, "OPEN");
  assert.equal(status.value.pinnedHead.status, "MATCHES");
  assert.equal(status.value.pinnedHeadStatus, "MATCHES");
  assert.equal(status.value.pinnedAttestation, "VERIFIED");
  assert.equal(status.value.anchorLogStatus, "NONE");
  assert.equal(status.value.ok, true);
  assert.equal(status.value.counts["grants live"], 2);
  assert.equal(status.value.counts["grants revoked"], 1);
  assert.equal(json(["capacity"], { env }).value.profile, "irontrellis-capacity/1");

  // Succession: bea → alex.
  const before = json(["handover", "bea"], { env });
  assert.equal(before.value.terminated, false);
  assert.deepEqual(before.value.liveGrants.map((g) => [g.authorityId, g.followsSuccession]), [["collect", false]]);
  assert.deepEqual(before.value.sessions.map((s) => [s.sessionId, s.current]), [["session:bea", true]]);
  const succeeded = json(["succeed", "h1", "--rule", "handover", "--from", "bea", "--from-tenure", "shift:1", "--to", "alex", "--to-tenure", "shift:2", "--role", "reviewer", "--number", "2"], { env });
  ok(succeeded);
  assert.equal(succeeded.value.status, "HANDOVER_RECORDED");
  // Format 2 seals the handover with a STATE_CHECKPOINT (SPEC §7.3).
  assert.deepEqual(succeeded.value.eventIds, ["handover:h1:retire", "handover:h1:transfer", "handover:h1:checkpoint"]);
  const after = json(["handover", "bea"], { env });
  assert.equal(after.value.terminated, true);
  assert.deepEqual(after.value.tenures, []);
  assert.equal(after.value.sessions[0].current, false);
  assert.equal(after.value.survives.epistemicStatus, "ESTABLISHED");
  assert.equal(after.value.survives.answer.lifecycleStatus, "TERMINATED");
  const report = run(["handover", "bea"], { env });
  ok(report);
  assert.match(report.stdout, /Handover report for bea/);
  assert.match(report.stdout, /bea is terminated\. bea leaves 0 open duties, 1 live grant that will not follow a successor, and 1 session \(1 no longer current\)\./);
  assert.match(report.stdout, /collect — read, collect on incident:42/);
  assert.match(report.stdout, /session:bea .* not current/);
  const survives = json(["survives", "bea"], { env });
  assert.equal(survives.value.answer.transferredRoleTenures.length, 1);
  assert.equal(json(["authorize", "--actor", "bea", "--action", "read", "--resource", "incident:42"], { env }).value.evidence.code, "AGENT_INACTIVE");
  // The delegation bea issued is evaluated against bea's own status: alex no longer reads.
  assert.equal(json(["authorize", "--actor", "alex", "--action", "read", "--resource", "incident:42"], { env }).value.decision, "DENY");

  // Epoch advance, unappoint and terminate on alex.
  ok(json(["epoch", "advance", "alex", "--from", "1", "--to", "2"], { env }));
  ok(json(["succession", "declare", "sr2", "--from", "alex", "--to", "bea", "--role", "reviewer"], { env }));
  ok(json(["unappoint", "alex", "--role", "reviewer", "--tenure", "shift:2"], { env }));
  ok(json(["appoint", "alex", "--role", "reviewer", "--tenure", "shift:3", "--number", "3", "--succession", "sr2"], { env }));
  ok(json(["agent", "terminate", "alex", "--succession", "sr2", "--role", "reviewer", "--tenure", "shift:3"], { env }));
  assert.equal(json(["status"], { env }).value.counts["agents terminated"], 2);

  // Anchor (the local anchor log), then verify. The anchor kind is --kind; --witness names only remote witnesses (init).
  for (const args of [["anchor", "--witness", "local"], ["anchor", "--kind", "http"]]) {
    const refused = json(args, { env });
    assert.equal(refused.code, 1, args.join(" "));
    assert.equal(refused.value.error.code, "USAGE", args.join(" "));
  }
  const anchored = json(["anchor"], { env });
  ok(anchored);
  assert.equal(anchored.value.anchor, "local-head-file");
  assert.ok(existsSync(`${history}.anchors`));
  const verify = json(["verify"], { env });
  ok(verify);
  assert.equal(verify.value.ok, true);
  assert.equal(verify.value.report.chain, "OK");
  assert.equal(verify.value.report.controlSignatures, "VERIFIED");
  assert.equal(verify.value.report.pinnedAttestation, "VERIFIED");
  assert.deepEqual(verify.value.report.anchors.map((a) => a.status), ["PREFIX_OK"]);
  assert.equal(verify.value.report.anchorLogStatus, "OK");
  assert.deepEqual(verify.value.failures, []);
  const verifyHuman = run(["verify"], { env });
  ok(verifyHuman);
  assert.match(verifyHuman.stdout, /VERIFIED/);
  assert.match(verifyHuman.stdout, /anchor log\s+OK/);
  assert.equal(json(["status"], { env }).value.anchorLogStatus, "OK");

  // Export: markers for bigints, one array.
  const exported = run(["export", "--json"], { env });
  ok(exported);
  const events = core.jsonParseWithBigints(exported.stdout);
  assert.equal(events.length, verify.value.report.eventCount);
  assert.equal(events[0].type, "DEPLOYMENT_INITIALIZED");
  const pretty = run(["export"], { env });
  assert.equal(JSON.parse(pretty.stdout).length, events.length);

  // --history on the command line beats the environment; --at is honoured.
  const other = json(["--history", history, "status"], { env: { IRONTRELLIS_HISTORY: "/nowhere" } });
  ok(other);
  const early = json(["survives", "bea", "--at", "1000"], { env });
  assert.equal(early.value.epistemicStatus, "INDETERMINATE");
  assert.equal(early.value.code, "CAUSAL_TIME_INVALID");

  // Rollback: truncate the file after it was pinned (and anchored).
  const lines = readFileSync(history, "utf8").split("\n").filter((l) => l.length > 0);
  writeFileSync(history, `${lines.slice(0, 6).join("\n")}\n`);
  const rolled = json(["verify"], { env });
  assert.equal(rolled.code, 1);
  assert.equal(rolled.value.ok, false);
  assert.equal(rolled.value.error.code, "ROLLBACK_DETECTED");
  assert.equal(rolled.value.report.pinnedHeadStatus, "ROLLBACK");
  assert.ok(rolled.value.failures.some((f) => f.startsWith("PIN_ROLLBACK:")));
  assert.ok(rolled.value.failures.some((f) => f.startsWith("ANCHOR_LOG_ROLLBACK:")), "the anchor log still holds the later head");
  const rolledHuman = run(["verify"], { env });
  assert.equal(rolledHuman.code, 1);
  assert.match(rolledHuman.stdout, /FAILED/);
  assert.match(rolledHuman.stdout, /ROLLBACK_DETECTED/);
  assert.match(rolledHuman.stdout, /Failures \(2\)\n  PIN_ROLLBACK: /);
  const blocked = json(["status"], { env });
  assert.equal(blocked.code, 1);
  assert.equal(blocked.value.error.code, "ROLLBACK_DETECTED");
  assert.equal(blocked.value.error.context.reason, "BEHIND_PIN");
  const blockedHuman = run(["status"], { env });
  assert.equal(blockedHuman.code, 1);
  assert.match(blockedHuman.stderr, /^error: ROLLBACK_DETECTED — The history file does not contain its pinned head/);

  // --accept-rollback re-pins the file as it is, attested with the owner key; the witness keeps failing until its log is archived.
  const accepted = json(["verify", "--accept-rollback"], { env });
  assert.equal(accepted.code, 1);
  assert.equal(accepted.value.report.eventCount, 6);
  assert.equal(accepted.value.report.pinnedHeadStatus, "MATCHES");
  assert.equal(accepted.value.report.pinnedAttestation, "VERIFIED");
  assert.equal(typeof accepted.value.report.rollbackAcceptedAt, "number");
  assert.ok(accepted.value.report.previousPin.position > 5);
  assert.deepEqual(accepted.value.failures.map((f) => f.split(":")[0]), ["ANCHOR_LOG_ROLLBACK"]);
  assert.ok(accepted.value.notes.some((n) => n.startsWith("ANCHOR_LOG_AFTER_ACCEPTED_ROLLBACK:")));
  const archived = `${history}.anchors.archived`;
  renameSync(`${history}.anchors`, archived);
  const clean = json(["verify"], { env });
  ok(clean);
  assert.equal(clean.value.report.rollbackAcceptedAt, accepted.value.report.rollbackAcceptedAt);
  assert.ok(clean.value.notes.some((n) => n.startsWith("ROLLBACK_ACCEPTED:")));
  const cleanHuman = run(["verify"], { env });
  ok(cleanHuman);
  assert.match(cleanHuman.stdout, /rollback\s+accepted at .* · the previous pin was at position \d+/);
  const afterStatus = json(["status"], { env });
  ok(afterStatus);
  assert.equal(afterStatus.value.rollbackAcceptedAt, accepted.value.report.rollbackAcceptedAt);
  // --anchors-file consults another anchor log: the archived one still holds the removed head.
  const witnessed = json(["verify", "--anchors-file", archived], { env });
  assert.equal(witnessed.code, 1);
  assert.equal(witnessed.value.report.anchorLogStatus, "ROLLBACK");
  assert.equal(json(["verify", "--anchors-file", join(dir, "nowhere.anchors")], { env }).value.error.code, "ANCHORS_NOT_FOUND");
});

// ------------------------------------------------------------------ pins: missing, unattested, malformed

test("verify fails on a missing pin; --allow-unpinned accepts it; --accept-rollback re-pins attested; plain repin refuses an unattested pin, repin --accept-rollback attests it", async (t) => {
  const dir = tempDir(t), history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(json(["init"], { env }));
  ok(json(["agent", "create", "bea"], { env }));
  ok(json(["grant", "g1", "--to", "bea", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], { env }));
  ok(json(["verify"], { env }));

  // B1: deleting the pin no longer passes.
  unlinkSync(`${history}.head`);
  const missing = json(["verify"], { env });
  assert.equal(missing.code, 1);
  assert.equal(missing.value.ok, false);
  assert.equal(missing.value.report.pinnedHeadStatus, "MISSING");
  assert.deepEqual(missing.value.failures.map((f) => f.split(":")[0]), ["PIN_MISSING"]);
  assert.equal(missing.value.error.code, "VERIFICATION_FAILED");
  const missingHuman = run(["verify"], { env });
  assert.equal(missingHuman.code, 1);
  assert.match(missingHuman.stdout, /pinned head\s+MISSING \(no pin file beside/);
  assert.match(missingHuman.stdout, /PIN_MISSING: /);
  // Readers and writers refuse the file, and say how to recover.
  const reader = json(["authorize", "--actor", "bea", "--action", "read", "--resource", "r:1"], { env });
  assert.equal(reader.code, 1);
  assert.equal(reader.value.error.code, "ROLLBACK_DETECTED");
  assert.equal(reader.value.error.context.reason, "PIN_MISSING");
  assert.match(reader.value.error.message, /pinned head file .* is missing; .*verify --accept-rollback/);
  assert.equal(json(["revoke", "g1"], { env }).value.error.code, "ROLLBACK_DETECTED");

  const allowed = json(["verify", "--allow-unpinned"], { env });
  ok(allowed);
  assert.equal(allowed.value.ok, true);
  assert.ok(allowed.value.notes.some((n) => n.startsWith("PIN_MISSING:") && n.includes("allowUnpinned")));
  assert.ok(!existsSync(`${history}.head`), "--allow-unpinned is read-only");

  const repinned = json(["verify", "--accept-rollback"], { env });
  ok(repinned);
  assert.equal(repinned.value.report.pinnedHeadStatus, "MATCHES");
  assert.equal(repinned.value.report.pinnedAttestation, "VERIFIED", "the re-pin is attested with the owner key");
  assert.equal(typeof repinned.value.report.rollbackAcceptedAt, "number");
  assert.equal(JSON.parse(readFileSync(`${history}.head`, "utf8")).attestation.keyId, "owner:1");
  ok(json(["verify"], { env }));
  ok(json(["authorize", "--actor", "bea", "--action", "read", "--resource", "r:1"], { env }));

  // A pin without an owner attestation (as older releases wrote it) fails verify, and readers refuse it (R1): its
  // fields are all public. Plain repin refuses to attest it; repin --accept-rollback does, recording the acceptance.
  const pin = JSON.parse(readFileSync(`${history}.head`, "utf8"));
  delete pin.attestation;
  writeFileSync(`${history}.head`, `${JSON.stringify(pin)}\n`);
  const unattested = json(["verify"], { env });
  assert.equal(unattested.code, 1);
  assert.equal(unattested.value.report.pinnedAttestation, "MISSING");
  assert.deepEqual(unattested.value.failures.map((f) => f.split(":")[0]), ["PIN_ATTESTATION_MISSING"]);
  ok(json(["verify", "--allow-unpinned"], { env }));
  const status = json(["status"], { env });
  assert.equal(status.code, 1);
  assert.equal(status.value.error.code, "ROLLBACK_DETECTED");
  assert.equal(status.value.error.context.reason, "PIN_UNATTESTED");
  const plainRepin = json(["repin"], { env });
  assert.equal(plainRepin.code, 1);
  assert.equal(plainRepin.value.error.code, "REPIN_REFUSED");
  assert.equal(plainRepin.value.error.context.reason, "PIN_UNATTESTED");
  const repin = json(["repin", "--accept-rollback"], { env });
  ok(repin);
  assert.equal(repin.value.pinnedAttestation, "VERIFIED");
  assert.equal(repin.value.acceptedRollback, true);
  assert.equal(repin.value.previousPin.attestation, undefined);
  ok(json(["verify"], { env }));
  ok(json(["status"], { env }));

  // A malformed pin is reported as malformed, not as removed events (L10).
  writeFileSync(`${history}.head`, "{ not json");
  const malformed = json(["verify"], { env });
  assert.equal(malformed.code, 1);
  assert.equal(malformed.value.report.pinnedHeadStatus, "MALFORMED");
  assert.match(run(["verify"], { env }).stdout, /pinned head\s+MALFORMED \(the pin file cannot be parsed/);
  const refused = run(["status"], { env });
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /^error: ROLLBACK_DETECTED — The pinned head file .* is malformed/);
  ok(json(["verify", "--accept-rollback"], { env }));
  ok(json(["verify"], { env }));

  // repin needs the owner key and a format-2 history (older formats are read only, SPEC §16.1).
  renameSync(`${history}.owner-key.json`, `${history}.key.aside`);
  assert.equal(json(["repin"], { env }).value.error.code, "KEY_UNAVAILABLE");
  const legacy = await olderHistory(join(dir, "legacy.jsonl"), LEGACY);
  const legacyRepin = json(["--history", legacy, "repin"]);
  assert.equal(legacyRepin.value.error.code, "FORMAT_READ_ONLY");
  assert.equal(legacyRepin.value.error.context.reason, "LEGACY");
});

// ------------------------------------------------------------------ R1 / R2: forged pins and witnesses on open

/** Grants g1 and g2 to a2, revokes both, anchors the head; returns the lines before the two revocations. */
const revokedHistory = (env) => {
  ok(json(["init"], { env }));
  ok(json(["agent", "create", "a2"], { env }));
  ok(json(["grant", "g1", "--to", "a2", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], { env }));
  ok(json(["grant", "g2", "--to", "a2", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], { env }));
  ok(json(["revoke", "g1"], { env }));
  ok(json(["revoke", "g2"], { env }));
  const denied = json(["authorize", "--actor", "a2", "--action", "read", "--resource", "r:1"], { env });
  assert.equal(denied.code, 2);
  assert.equal(denied.value.decision, "DENY");
  assert.equal(denied.value.evidence.code, "REVOKED");
};
const readerCommands = [
  ["authorize", "--actor", "a2", "--action", "read", "--resource", "r:1"],
  ["why", "--actor", "a2", "--action", "read", "--resource", "r:1"],
  ["responsible", "--actor", "a2", "--action", "read", "--resource", "r:1"],
  ["status"], ["export"], ["handover", "a2"], ["survives", "a2"], ["capacity"],
];
/** Cuts the file back to `keep` lines and writes a pin WITHOUT attestation at that head: every field is public. */
const forgeUnattestedPin = (history, keep) => {
  const kept = readFileSync(history, "utf8").split("\n").filter(Boolean).slice(0, keep);
  writeFileSync(history, `${kept.join("\n")}\n`);
  const head = core.openHistoryStore(history, { inspect: true }).head();
  writeFileSync(`${history}.head`, `${JSON.stringify({ version: "irontrellis-pinned-head/1", ...head, recordHash: JSON.parse(kept.at(-1)).recordHash, pinnedAt: Date.now() })}\n`);
};

test("R1: every reader refuses a truncated history with an unattested pin; writers and repin refuse; --accept-rollback re-pins", async (t) => {
  const dir = tempDir(t), history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  revokedHistory(env);
  // The attack: cut both revocations (the last two lines) and forge the pin. No key is used.
  const lines = readFileSync(history, "utf8").split("\n").filter(Boolean).length;
  forgeUnattestedPin(history, lines - 2);
  for (const args of readerCommands) {
    const r = json(args, { env });
    assert.equal(r.code, 1, `${args[0]} must refuse:\n${r.stdout}`);
    assert.equal(r.value.error.code, "ROLLBACK_DETECTED", args[0]);
    assert.equal(r.value.error.context.reason, "PIN_UNATTESTED", args[0]);
  }
  const human = run(readerCommands[0], { env });
  assert.equal(human.code, 1);
  assert.doesNotMatch(human.stdout, /ALLOW/);
  assert.match(human.stderr, /^error: ROLLBACK_DETECTED — The pinned head file .* carries no owner attestation, so it cannot rule out a truncation/);
  // The next owner-keyed write does not launder it, and neither does repin; nothing is written.
  const pinText = readFileSync(`${history}.head`, "utf8"), fileText = readFileSync(history, "utf8");
  const grant = json(["grant", "g3", "--to", "a2", "--actions", "read", "--resources", "r:9", "--expires", "+1h"], { env });
  assert.equal(grant.code, 1);
  assert.equal(grant.value.error.context.reason, "PIN_UNATTESTED");
  const refused = run(["repin"], { env });
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /^error: REPIN_REFUSED — The pinned head file .* carries no owner attestation.* repin did not attest this head.*repin --accept-rollback/s);
  assert.equal(readFileSync(`${history}.head`, "utf8"), pinText);
  assert.equal(readFileSync(history, "utf8"), fileText);
  const verify = json(["verify"], { env });
  assert.equal(verify.code, 1);
  assert.ok(verify.value.failures.some((f) => f.startsWith("PIN_ATTESTATION_MISSING")));
  // The operator accepts the file deliberately: the pin is attested and records the acceptance; readers answer again.
  const accepted = json(["repin", "--accept-rollback"], { env });
  ok(accepted);
  assert.equal(accepted.value.acceptedRollback, true);
  assert.equal(accepted.value.pin.previousPin.attestation, undefined);
  assert.match(run(["repin", "--accept-rollback"], { env }).stdout, /REPINNED/);
  ok(json(["authorize", "--actor", "a2", "--action", "read", "--resource", "r:1"], { env }), "the operator accepted the cut file");
  // A pin carrying the owner's genuine attestation of the removed revocation is PIN_ATTESTED_NOT_PREFIX; an altered one is
  // PIN_ATTESTATION_INVALID.
  ok(json(["revoke", "g1"], { env }));
  const genuine = JSON.parse(readFileSync(`${history}.head`, "utf8"));
  forgeUnattestedPin(history, readFileSync(history, "utf8").split("\n").filter(Boolean).length - 1);
  const forged = JSON.parse(readFileSync(`${history}.head`, "utf8"));
  const authorize = () => json(["authorize", "--actor", "a2", "--action", "read", "--resource", "r:1"], { env });
  writeFileSync(`${history}.head`, JSON.stringify({ ...forged, attestation: genuine.attestation }));
  const notPrefix = authorize();
  assert.equal(notPrefix.value.error.context.reason, "PIN_ATTESTED_NOT_PREFIX");
  assert.match(notPrefix.value.error.message, /The owner attested a head at position \d+ that this history file does not contain/);
  writeFileSync(`${history}.head`, JSON.stringify({ ...forged, attestation: { ...genuine.attestation, head: { ...genuine.attestation.head, position: 1 } } }));
  assert.equal(authorize().value.error.context.reason, "PIN_ATTESTATION_INVALID");
});

test("R2: readers refuse an older copy restored with its own attested pin when <history>.anchors holds a later head", async (t) => {
  const dir = tempDir(t), history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(json(["init"], { env }));
  ok(json(["agent", "create", "a2"], { env }));
  ok(json(["grant", "g1", "--to", "a2", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], { env }));
  copyFileSync(history, join(dir, "old.jsonl"));
  copyFileSync(`${history}.head`, join(dir, "old.jsonl.head"));
  ok(json(["revoke", "g1"], { env }));
  ok(json(["anchor", "--kind", "local"], { env }));
  copyFileSync(join(dir, "old.jsonl"), history);
  copyFileSync(join(dir, "old.jsonl.head"), `${history}.head`);
  for (const args of readerCommands) {
    const r = json(args, { env });
    assert.equal(r.code, 1, `${args[0]} must refuse:\n${r.stdout}`);
    assert.equal(r.value.error.context.reason, "ANCHOR_LOG_ROLLBACK", args[0]);
  }
  assert.match(run(readerCommands[0], { env }).stderr, /^error: ROLLBACK_DETECTED — The anchor log .*h\.jsonl\.anchors holds an owner-attested head at position \d+ that this history file does not contain/);
  const refused = json(["repin"], { env });
  assert.equal(refused.value.error.code, "REPIN_REFUSED");
  assert.equal(refused.value.error.context.reason, "ANCHOR_LOG_ROLLBACK");
  // Accepted deliberately: the pin records it; verify and readers keep failing until the log is archived.
  const accepted = json(["repin", "--accept-rollback"], { env });
  assert.equal(accepted.code, 1, "verify still fails on the witness");
  assert.equal(accepted.value.acceptedRollback, true);
  assert.equal(accepted.value.anchorLogStatus, "ROLLBACK");
  assert.equal(json(readerCommands[0], { env }).value.error.context.reason, "ANCHOR_LOG_ROLLBACK");
  renameSync(`${history}.anchors`, join(dir, "archived.anchors"));
  ok(json(readerCommands[0], { env }));
  // An unreadable log fails every reader with its own code.
  writeFileSync(`${history}.anchors`, "{torn");
  const unreadable = run(readerCommands[0], { env });
  assert.equal(unreadable.code, 1);
  assert.match(unreadable.stderr, /^error: ANCHOR_LOG_UNREADABLE — The anchor log .* cannot be read/);
});

// ------------------------------------------------------------------ damaged and empty files (M6)

test("a damaged file is INVALID_HISTORY with the store's reason; HISTORY_EMPTY only for an empty file", (t) => {
  const dir = tempDir(t), history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(json(["init"], { env }));
  ok(json(["agent", "create", "bea"], { env }));
  writeFileSync(history, `${readFileSync(history, "utf8")}{"version":"irontrellis-portable`, { flag: "w" });
  for (const args of [["status"], ["authorize", "--actor", "bea", "--action", "read", "--resource", "r"], ["why", "--actor", "bea", "--action", "read", "--resource", "r"], ["handover", "bea"], ["export"], ["agent", "create", "alex"]]) {
    const r = json(args, { env });
    assert.equal(r.code, 1, args.join(" "));
    assert.equal(r.value.error.code, "INVALID_HISTORY", args.join(" "));
    assert.match(r.value.error.message, /incomplete record/, args.join(" "));
  }
  const human = run(["status"], { env });
  assert.match(human.stderr, /^error: INVALID_HISTORY — The history file is damaged, out of order or fails a signature or hash check: history file has an incomplete record\./);
  const verify = json(["verify"], { env });
  assert.equal(verify.code, 1);
  assert.equal(verify.value.error.code, "INVALID_HISTORY");
  // Bad UTF-8 is a damaged file too.
  writeFileSync(history, Buffer.from([0xff, 0xfe, 0x0a]));
  assert.equal(json(["status"], { env }).value.error.code, "INVALID_HISTORY");

  const empty = join(dir, "empty.jsonl");
  writeFileSync(empty, "");
  const r = json(["--history", empty, "status"]);
  assert.equal(r.code, 1);
  assert.equal(r.value.error.code, "HISTORY_EMPTY");
});

// ------------------------------------------------------------------ writers under a held lock (M10)

test("writes retry under a held lock, parallel writers take turns, and an unreleased lock is named", async (t) => {
  const dir = tempDir(t), history = join(dir, "h.jsonl"), lock = `${history}.writer-lock`;
  const env = { IRONTRELLIS_HISTORY: history };
  ok(json(["init"], { env }));
  // A lock held by a live process (this test) that lets go after 300 ms: the write waits and succeeds.
  writeFileSync(lock, JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: Date.now() }));
  const pending = runAsync(["agent", "create", "bea", "--json"], { env });
  await new Promise((resolveWait) => setTimeout(resolveWait, 300));
  unlinkSync(lock);
  const waited = await pending;
  ok(waited);
  assert.equal(JSON.parse(waited.stdout).recorded, "agent bea");

  // A lock that is never released: the command gives up after its retries and names the lock.
  writeFileSync(lock, JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: Date.now() }));
  const busy = json(["agent", "create", "alex"], { env });
  assert.equal(busy.code, 1);
  assert.equal(busy.value.error.code, "HISTORY_CONFLICT");
  // A-184.1: a lock path is compared after canonicalising both sides (on macOS a tmpdir path may run through a symlink).
  assert.equal(realpathSync(busy.value.error.context.lockPath), realpathSync(lock));
  assert.ok(busy.value.error.message.includes(busy.value.error.context.lockPath), busy.value.error.message);
  assert.match(busy.value.error.message, /retried 5 times, and nothing was written/);
  const busyHuman = run(["agent", "create", "alex"], { env });
  assert.match(busyHuman.stderr, new RegExp(`^error: HISTORY_CONFLICT — Another process holds the writer lock ${realpathSync(lock).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} \\(pid ${process.pid}`));
  // anchor waits on the store's own lock timeout and names the lock too.
  const anchorBusy = json(["anchor"], { env });
  assert.equal(anchorBusy.value.error.code, "STORE_BUSY");
  assert.equal(realpathSync(anchorBusy.value.error.context.lockPath), realpathSync(lock));
  unlinkSync(lock);

  // Four parallel writers, three writes each: every write lands.
  const loops = [0, 1, 2, 3].map(async (n) => {
    for (let i = 0; i < 3; i += 1) {
      const r = await runAsync(["agent", "create", `w${n}-${i}`], { env });
      assert.equal(r.code, 0, r.stderr);
    }
  });
  await Promise.all(loops);
  assert.equal(json(["status"], { env }).value.counts.agents, 13);
  ok(json(["verify"], { env }));
});

// ------------------------------------------------------------------ input errors name the argument (L8)

test("input errors name the argument and the limit; engine refusals carry the engine's reason", (t) => {
  const dir = tempDir(t), history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(json(["init"], { env }));
  ok(json(["agent", "create", "bea"], { env }));
  const actions = Array.from({ length: 33 }, (_, i) => `a${i}`).join(",");
  const tooMany = json(["grant", "g", "--to", "bea", "--actions", actions, "--resources", "r", "--expires", "+1h"], { env });
  assert.equal(tooMany.value.error.code, "INVALID_INPUT");
  assert.equal(tooMany.value.error.message, "An argument is not valid: --actions has 33 values; a list is limited to 32.");
  const long = json(["agent", "create", "x".repeat(129)], { env });
  assert.equal(long.value.error.code, "INVALID_INPUT");
  assert.match(long.value.error.message, /<id> is 129 characters long; identifiers are limited to 128/);
  assert.match(json(["agent", "create", "x".repeat(100_000)], { env }).value.error.message, /100000 characters long/);
  assert.match(json(["grant", "g", "--to", "b".repeat(200), "--actions", "read", "--resources", "r", "--expires", "+1h"], { env }).value.error.message, /--to is 200 characters long/);
  assert.match(json(["grant", "g", "--to", "bea", "--actions", "read,read", "--resources", "r", "--expires", "+1h"], { env }).value.error.message, /--actions lists "read" more than once/);
  assert.match(json(["grant", "g", "--to", "bea", "--actions", "read", "--resources", "r", "--expires", "+1h", "--max-amount", "9".repeat(80)], { env }).value.error.message, /--max-amount .* limited to 2\^256 - 1/);
  const human = run(["grant", "g", "--to", "bea", "--actions", actions, "--resources", "r", "--expires", "+1h"], { env });
  assert.equal(human.stderr, "error: INVALID_INPUT — An argument is not valid: --actions has 33 values; a list is limited to 32.\n");
  // 32 values are accepted.
  ok(json(["grant", "g32", "--to", "bea", "--actions", Array.from({ length: 32 }, (_, i) => `a${i}`).join(","), "--resources", "r", "--expires", "+1h"], { env }));
  // An engine refusal names what the engine found.
  const unknown = json(["grant", "g2", "--to", "nobody", "--actions", "read", "--resources", "r", "--expires", "+1h"], { env });
  assert.equal(unknown.value.error.code, "TRANSITION_REJECTED");
  assert.match(unknown.value.error.message, /^The history's rules refuse this event in the current state \(event at position \d+ rejected: .+\); nothing was written\.$/);
  // A session key file is never overwritten, and says so with a code.
  const keyFile = join(dir, "k.json");
  writeFileSync(keyFile, "{}");
  const exists = json(["session", "admit", "s1", "--agent", "bea", "--epoch", "1", "--key", "k1", "--expires", "+1h", "--new-key", keyFile], { env });
  assert.equal(exists.value.error.code, "FILE_EXISTS");
});

test("init refuses an existing owner key unless --reuse-existing-key", (t) => {
  const dir = tempDir(t), history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(json(["--history", join(dir, "first.jsonl"), "init"]));
  copyFileSync(join(dir, "first.jsonl.owner-key.json"), `${history}.owner-key.json`);
  const refused = json(["init"], { env });
  assert.equal(refused.code, 1);
  assert.equal(refused.value.error.code, "KEY_EXISTS");
  assert.match(refused.value.error.message, /not adopted silently.*--reuse-existing-key/);
  assert.equal(refused.value.error.context.keyPath, `${history}.owner-key.json`);
  assert.ok(!existsSync(history));
  const reused = json(["init", "--reuse-existing-key"], { env });
  ok(reused);
  assert.deepEqual(reused.value.ownerKeys, [JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8")).keyId]);
});

// ------------------------------------------------------------------ demo

test("demo runs with no arguments, leaves a verifiable history and answers WHY / WHO / WHAT", async (t) => {
  const dir = tempDir(t);
  const r = json(["demo", "--dir", dir]);
  ok(r);
  const d = r.value;
  assert.equal(d.history, join(dir, "history.jsonl"));
  assert.equal(d.verify.ok, true);
  assert.deepEqual(d.verify.failures, []);
  assert.equal(d.verify.pinnedAttestation, "VERIFIED");
  assert.equal(d.verify.anchorLogStatus, "OK", "the demo anchors its head in the local anchor log");
  assert.ok(existsSync(`${d.history}.anchors`));
  assert.equal(d.why.answer.authorization.decision, "ALLOW");
  assert.equal(d.why.answer.authorization.proof.runtimeSessionId, "session:bea");
  assert.equal(d.whyNow.answer.authorization.decision, "DENY");
  assert.equal(d.whyNow.answer.authorization.code, "AGENT_INACTIVE");
  const assignees = d.responsible.answer.attributions.filter((a) => a.kind === "PERFORMANCE_ASSIGNEE").map((a) => a.subjectId).sort();
  assert.deepEqual(assignees, ["alex", "bea"]);
  assert.equal(d.survives.answer.lifecycleStatus, "TERMINATED");
  assert.deepEqual(d.survives.answer.currentPerformanceAssignments.map((p) => [p.obligationId, p.assigneeId]), [["duty:42", "alex"]]);
  assert.deepEqual(d.handover.openDuties.map((x) => [x.id, x.assignee, x.status]), [["duty:42", "bea", "OPEN"]]);
  assert.deepEqual(d.handover.liveGrants.map((g) => g.authorityId), ["collect"]);
  assert.deepEqual(d.handoverAfter.openDuties.map((x) => [x.id, x.assignee]), [["duty:42", "alex"]]);
  assert.ok(!d.handoverAfter.liveGrants.some((g) => g.authorityId === "collect"));

  // The printed commands work on the history it left behind.
  const env = { IRONTRELLIS_HISTORY: d.history };
  const verified = json(["verify"], { env });
  ok(verified);
  assert.equal(verified.value.report.anchorLogStatus, "OK");
  const who = json(["responsible", "--intent", "operation:42"], { env });
  ok(who);
  assert.deepEqual(who.value.answer.attributions.filter((a) => a.temporalBasis === "LATER_CAUSAL_STATE" && a.kind === "PERFORMANCE_ASSIGNEE").map((a) => a.subjectId).sort(), ["alex", "bea"]);
  const clash = json(["responsible", "--intent", "operation:42", "--actor", "bea"], { env });
  assert.equal(clash.value.error.code, "USAGE");
  const unknown = json(["why", "--intent", "nope"], { env });
  assert.equal(unknown.value.error.code, "INVALID_INPUT");
  const positional = json(["why", "--actor", "bea", "--action", "read", "--resource", "incident:42", "--position", "12"], { env });
  assert.equal(positional.value.answer.authorization.decision, "ALLOW");
  assert.equal(positional.value.scope.headRelationship, "STRICT_EXTENSION");

  // The CLI's handover report is the core's.
  const state = core.openHistoryStore(d.history).state();
  const owner = core.openLocalOwner({ historyFile: d.history, domain: state.genesis.domain, owner: "operations", controller: "operator", now: () => Date.now() });
  const at = 1_800_000_000_000;
  const mine = json(["handover", "alex", "--at", String(at)], { env }).value;
  const theirs = JSON.parse(core.jsonStringifyWithBigints(owner.handover("alex", { at })));
  assert.deepEqual(mine, theirs);

  const human = run(["demo", "--dir", join(dir, "again")]);
  ok(human);
  assert.match(human.stdout, /^◆ irontrellis/);
  assert.match(human.stdout, /WHY was bea allowed to read incident:42\?/);
  assert.match(human.stdout, /WHO is responsible for that action now\?/);
  assert.match(human.stdout, /performance assignee\s+alex/);
  assert.match(human.stdout, /WHAT survives bea\?/);
  assert.match(human.stdout, /Leaving now would leave 1 open duty, 1 live grant that will not follow a successor, and 1 session\./);
  assert.match(human.stdout, /OPEN  duty:42 — Review the collected material for incident 42\./);
  assert.match(human.stdout, /The history is at /);
  assert.equal(json(["demo", "--history", "/x"]).value.error.code, "USAGE");
});

// ------------------------------------------------------------------ migration of a legacy fixture

test("migrate re-records the legacy handover fixture; the archive keeps answering intent questions", async (t) => {
  // No host fallback path (publication hygiene, as S5-27): without the vendored fixture the test skips and says why.
  if (!existsSync(VENDORED_FIXTURE)) { t.skip(`the vendored legacy fixture ${VENDORED_FIXTURE} is absent`); return; }
  const dir = tempDir(t);
  const source = join(dir, "handover-history.jsonl");
  copyFileSync(VENDORED_FIXTURE, source);
  const original = readFileSync(source);
  const target = join(dir, "migrated.jsonl");
  // A Continuity-written history has no pinned head: migration needs the explicit flag, and a refusal leaves nothing behind.
  const unpinned = json(["migrate", source, target]);
  assert.equal(unpinned.code, 1);
  assert.equal(unpinned.value.error.code, "MIGRATION_UNSUPPORTED");
  assert.equal(unpinned.value.error.context.reason, "SOURCE_UNPINNED");
  assert.match(unpinned.value.error.message, /no pinned head.*Continuity-written histories never have a pin.*--accept-unpinned-source/);
  assert.ok(!existsSync(target) && !existsSync(`${target}.owner-key.json`));
  const migrated = json(["migrate", source, target, "--accept-unpinned-source"]);
  ok(migrated);
  assert.equal(migrated.value.eventCount, 26);
  assert.equal(migrated.value.sourceHead.position, 25);
  assert.equal(migrated.value.targetHead.position, 25);
  // A-41.3: the target's historyId (recordHash(0)) for hook and gateway configs.
  assert.equal(migrated.value.historyId, JSON.parse(readFileSync(target, "utf8").split("\n")[0]).recordHash);
  // The target genesis commits the new owner key to a next key (default), written beside the target.
  assert.equal(migrated.value.nextKeyCommitted, true);
  assert.equal(migrated.value.nextKeyFile, `${realpathSync(target)}.owner-next-key.json`); // A-184.1: the target is reported canonical
  assert.deepEqual(core.openHistoryStore(target).state().events[0].data.nextKeyDigests, migrated.value.nextKeyDigests);
  // `owner status` still gates on format 1 (G3 moves the CLI to format 2); the commitment is asserted on the genesis above.
  assert.deepEqual(readFileSync(source), original, "the source is untouched");
  assert.equal(migrated.value.phase, "FENCED");
  assert.match(migrated.value.stateRoot, /^0x[0-9a-f]{64}$/);
  // The fence (SPEC §16.2 step 6): the source is read only and names the target; a re-run with the same plan resumes and reports the same head.
  assert.equal(existsSync(`${source}.migrated`), true);
  assert.equal(json(["migrate", source, join(dir, "elsewhere.jsonl"), "--accept-unpinned-source"]).value.error.context.reason, "SOURCE_FENCED");
  const rerun = json(["migrate", source, target, "--accept-unpinned-source"]);
  ok(rerun);
  assert.deepEqual(rerun.value.targetHead, migrated.value.targetHead);
  const planStatus = json(["migrate", "--status", `${target}.migration-plan.json`]);
  ok(planStatus);
  assert.equal(planStatus.value.phase, "FENCED");
  assert.equal(planStatus.value.verified, true);
  assert.match(run(["migrate", "--status", `${target}.migration-plan.json`]).stdout, /FENCED  /);
  // Each further migration case needs its own (unfenced) copy of the source.
  let copies = 0;
  const fresh = () => { const copy = join(dir, `source-${(copies += 1)}.jsonl`); copyFileSync(source, copy); return copy; };
  // An owner key file already at the target's key path is not adopted silently.
  const second = join(dir, "second.jsonl");
  copyFileSync(`${target}.owner-key.json`, `${second}.owner-key.json`);
  const keyExists = json(["migrate", fresh(), second, "--accept-unpinned-source"]);
  assert.equal(keyExists.value.error.code, "KEY_EXISTS");
  assert.match(keyExists.value.error.message, /--reuse-existing-key/);
  const reused = json(["migrate", fresh(), second, "--accept-unpinned-source", "--reuse-existing-key"]);
  ok(reused);
  assert.equal(reused.value.ownerKeyId, migrated.value.ownerKeyId);
  // --no-next-key migrates without a commitment (owner commit-next-key adds one later); the flags exclude each other.
  const bare = join(dir, "bare-migrated.jsonl");
  const uncommitted = json(["migrate", fresh(), bare, "--accept-unpinned-source", "--no-next-key"]);
  ok(uncommitted);
  assert.equal(uncommitted.value.nextKeyCommitted, false);
  assert.equal(existsSync(`${bare}.owner-next-key.json`), false);
  assert.equal(Object.hasOwn(core.openHistoryStore(bare).state().events[0].data, "nextKeyDigests"), false);
  assert.equal(json(["migrate", fresh(), join(dir, "x.jsonl"), "--accept-unpinned-source", "--no-next-key", "--next-public-key", `0x${"11".repeat(32)}`]).value.error.code, "USAGE");

  const status = json(["--history", target, "status"]);
  ok(status);
  assert.equal(status.value.format, "irontrellis-event/2");
  assert.equal(status.value.migratedFrom.position, 25);
  assert.equal(status.value.owner, "principal:first-look");
  const verify = json(["--history", target, "verify"]);
  ok(verify);
  assert.equal(verify.value.report.controlSignatures, "VERIFIED");
  assert.equal(verify.value.report.pinnedAttestation, "VERIFIED");

  // Decisions are unchanged by migration.
  const q = ["authorize", "--actor", "b:first-look", "--action", "record-review-progress", "--resource", "obligation:first-look", "--at", "30"];
  const before = json(["--history", source, ...q]), afterwards = json(["--history", target, ...q]);
  assert.equal(before.value.decision, afterwards.value.decision);
  assert.equal(before.value.decision, "ALLOW");
  const legacyStatus = json(["--history", source, "status"]);
  assert.equal(legacyStatus.value.format, "continuity-event/0.2");
  assert.equal(legacyStatus.value.capacity.profile, "continuity-managed-capacity/1");
  const handover = json(["--history", source, "handover", "a:first-look", "--at", "30"]);
  ok(handover);
  assert.equal(handover.value.terminated, true);

  // The recorded admission is re-evaluated on the archive; the migrated copy says so.
  const who = json(["--history", source, "responsible", "--intent", "intent:first-look"]);
  ok(who);
  assert.equal(who.value.answer.authorizationDecision, "ALLOW");
  assert.ok(who.value.answer.attributions.some((a) => a.kind === "PERFORMANCE_ASSIGNEE" && a.subjectId === "b:first-look"));
  const refused = json(["--history", target, "responsible", "--intent", "intent:first-look"]);
  assert.equal(refused.value.error.code, "MIGRATED_INTENT");
  const anchored = json(["--history", source, "anchor"]);
  assert.equal(anchored.value.error.code, "FORMAT_READ_ONLY");
  assert.equal(anchored.value.error.context.reason, "MIGRATED");
});

// ------------------------------------------------------------------ help, errors, environment

test("--help works for every command and the command list is complete", () => {
  const all = [...COMMANDS, demo];
  const expected = [
    "init", "status", "verify", "export", "migrate", "agent create", "agent terminate", "role create", "appoint", "unappoint", "succession declare", "succeed",
    "session admit", "epoch advance", "grant", "delegate", "prohibit", "revoke", "authorize", "why", "responsible", "survives", "handover", "anchor", "capacity", "demo", "repin",
    "owner status", "owner commit-next-key", "owner rotate-key", "owner export-key-events", "witness add", "witness status", "witness sync", "witness remove",
    "signer test", "signer ref", "signer list", "signer to-ssh", "doctor",
    "budget declare", "budget update", "budget close", "budget show", "budget headroom", "checkpoint create", "checkpoint list", "checkpoint verify",
    "counterparty register", "counterparty rotate", "counterparty retire", "counterparty receipts",
    "duty describe", "duty activate", "duty dispose", "duty contest", "duty inspect", "export verify",
  ];
  assert.deepEqual(all.map((c) => c.name).sort(), expected.sort());
  const main = run(["--help"]);
  ok(main);
  for (const c of all) {
    assert.ok(main.stdout.includes(`  ${c.name}`), `main help lists ${c.name}`);
    const r = run([...c.name.split(" "), "--help"]);
    ok(r, `${c.name} --help`);
    assert.match(r.stdout, new RegExp(`usage: irontrellis ${c.name.replace(/ /g, " ")}`), `${c.name} usage line`);
    assert.ok(r.stdout.includes("--history <file>"), `${c.name} help shows global options`);
    for (const option of c.options) assert.ok(r.stdout.includes(`--${option.name}`), `${c.name} help shows --${option.name}`);
  }
  assert.equal(run([]).code, 0);
  assert.match(run(["--version"]).stdout, /^irontrellis \d+\.\d+\.\d+/);
});

test("errors: exit 1, `error: CODE — sentence` on stderr, one JSON document with --json", () => {
  const unknown = run(["bogus"]);
  assert.equal(unknown.code, 1);
  assert.equal(unknown.stdout, "");
  assert.match(unknown.stderr, /^error: UNKNOWN_COMMAND — unknown command "bogus"/);
  assert.deepEqual(json(["bogus"]).value, { error: { code: "UNKNOWN_COMMAND", message: 'unknown command "bogus"' } });

  const noHistory = run(["status"], { env: { IRONTRELLIS_HISTORY: "" } });
  assert.equal(noHistory.code, 1);
  assert.match(noHistory.stderr, /^error: HISTORY_REQUIRED — Name the history file with --history <file> or the IRONTRELLIS_HISTORY environment variable\./);
  const missing = json(["--history", "/nowhere/h.jsonl", "status"]);
  assert.equal(missing.code, 1);
  assert.equal(missing.value.error.code, "HISTORY_NOT_FOUND");

  const usage = json(["grant", "x", "--to", "bea"]);
  assert.equal(usage.value.error.code, "USAGE");
  assert.match(usage.value.error.message, /--actions is required/);
  assert.equal(json(["grant", "x", "--bogus"]).value.error.message, "unknown option --bogus");
  // Roles are exclusive in both history formats: there is no shared-role option.
  assert.equal(json(["role", "create", "x", "--shared"]).value.error.message, "unknown option --shared");
  assert.equal(json(["appoint", "bea", "--role", "r", "--tenure", "t", "--number", "one"]).value.error.code, "USAGE");
  assert.equal(json(["why", "--actor", "a", "--action", "b", "--resource", "c", "--at", "yesterday"]).value.error.code, "USAGE");
});

test("brand output: header glyph follows the locale, colour only on a TTY without NO_COLOR", () => {
  const utf8 = run(["--help"], { env: { LANG: "en_US.UTF-8", LC_ALL: "" } });
  assert.match(utf8.stdout, /^◆ irontrellis/);
  const plain = run(["--help"], { env: { LC_ALL: "C", LANG: "C" } });
  assert.match(plain.stdout, /^\* irontrellis/);
  assert.ok(!utf8.stdout.includes("\u001b["), "no ANSI colour when stdout is not a TTY");
});

test("colour follows the open-source custom (founder 4bz): --no-color, NO_COLOR (any value), FORCE_COLOR (not 0 or false), else a TTY; the brand's ANSI-256 values", async () => {
  const { colourEnabled, PALETTE, style, stateWord } = await import("../dist/output.js");
  assert.deepEqual({ ...PALETTE }, { forge: 208, allow: 35, deny: 203, indeterminate: 178, open: 74, secondary: 245 });
  const on = (isTTY, env, flag) => colourEnabled({ isTTY, env }, flag);
  assert.equal(on(true, {}), true);
  assert.equal(on(false, {}), false, "no TTY, no colour");
  assert.equal(on(true, { TERM: "dumb" }), false);
  for (const value of ["1", "", "0", "false"]) assert.equal(on(true, { NO_COLOR: value }), false, `NO_COLOR=${JSON.stringify(value)}`);
  for (const value of ["1", "true", "2", "3", ""]) assert.equal(on(false, { FORCE_COLOR: value }), true, `FORCE_COLOR=${JSON.stringify(value)} without a TTY`);
  for (const value of ["0", "false", "FALSE"]) assert.equal(on(true, { FORCE_COLOR: value }), false, `FORCE_COLOR=${value}`);
  assert.equal(on(false, { FORCE_COLOR: "1", NO_COLOR: "1" }), false, "NO_COLOR wins over FORCE_COLOR");
  assert.equal(on(true, { FORCE_COLOR: "1" }, false), false, "--no-color wins over everything");
  const s = style({ isTTY: true, env: {} });
  assert.equal(stateWord(s, "DENY"), "\u001b[38;5;203mDENY\u001b[0m");
  assert.equal(stateWord(s, "OPEN"), "\u001b[38;5;74mOPEN\u001b[0m");
  // Through the command: FORCE_COLOR gives the Forge header without a TTY; --no-color and NO_COLOR take it away; --no-color is accepted by every command.
  const forced = run(["--help"], { env: { NO_COLOR: undefined, FORCE_COLOR: "1", LANG: "en_US.UTF-8", LC_ALL: "" } });
  assert.match(forced.stdout, /^\u001b\[38;5;208m◆ irontrellis\u001b\[0m/);
  const flagged = run(["why", "--no-color", "--help"], { env: { NO_COLOR: undefined, FORCE_COLOR: "1" } });
  assert.equal(flagged.code, 0, flagged.stderr);
  assert.ok(!flagged.stdout.includes("\u001b["), "--no-color");
  assert.ok(!run(["--help"], { env: { NO_COLOR: "", FORCE_COLOR: "1" } }).stdout.includes("\u001b["), "NO_COLOR empty");
  const unknown = run(["why", "--no-color", "--history", "/nonexistent/h.jsonl"], { env: { NO_COLOR: undefined, FORCE_COLOR: "1" } });
  assert.notEqual(unknown.code, 0);
  assert.ok(!unknown.stderr.includes("\u001b["), "errors honour --no-color too");
  assert.doesNotMatch(unknown.stderr, /unknown option/);
});

test("BRAND-001 p. 6 and p. 9: a state colour paints only the four state words, and Forge only the header's product marker (one highlight per view)", async (t) => {
  const { STATE_WORDS, style, stateWord, PALETTE } = await import("../dist/output.js");
  assert.deepEqual([...STATE_WORDS], ["ALLOW", "DENY", "INDETERMINATE", "OPEN"]);
  const s = style({ isTTY: true, env: {} });
  for (const word of ["FAILED", "WARNING", "OK", "QUEUED", "SIGNED", "NOT_A_STATE"]) assert.equal(stateWord(s, word), word, `${word} is not painted`);
  assert.equal(s.strong("FAILED"), "\u001b[1mFAILED\u001b[22m");
  // The source: paint() takes only forge and secondary (the compiler checks the type; this pins it against a cast).
  const src = resolve(here, "../src");
  for (const name of readdirSync(src).filter((n) => n.endsWith(".ts"))) {
    assert.doesNotMatch(readFileSync(join(src, name), "utf8"), /\.paint\([^;]*?"(?:allow|deny|indeterminate|open)"\)/, `${name}: a state tone outside stateWord`);
  }
  // Through the command, with colour forced: every state colour wraps exactly its own state word, and Forge appears once.
  const dir = tempDir(t);
  const forced = { NO_COLOR: undefined, FORCE_COLOR: "1", LANG: "en_US.UTF-8", LC_ALL: "" };
  const codeOf = { [PALETTE.allow]: "ALLOW", [PALETTE.deny]: "DENY", [PALETTE.indeterminate]: "INDETERMINATE", [PALETTE.open]: "OPEN" };
  for (const args of [["demo", "--dir", join(dir, "demo")], ["--help"]]) {
    const r = run(args, { env: forced });
    assert.equal(r.code, 0, r.stderr);
    const painted = [...r.stdout.matchAll(/\u001b\[38;5;(\d+)m([^\u001b]*)\u001b\[0m/g)].map((m) => [Number(m[1]), m[2]]);
    for (const [code, text] of painted) {
      if (code === PALETTE.secondary) continue;
      if (code === PALETTE.forge) { assert.match(text, /^◆ irontrellis$/, `${args[0]}: Forge on ${JSON.stringify(text)}`); continue; }
      assert.equal(codeOf[code], text, `${args[0]}: colour ${code} on ${JSON.stringify(text)}`);
    }
    assert.equal(painted.filter(([code]) => code === PALETTE.forge).length, 1, `${args[0]}: one Forge highlight`);
    if (args[0] === "demo") assert.ok(painted.some(([, text]) => STATE_WORDS.includes(text)), "the demo prints state words in colour");
  }
});

test("messages: every core error code has a plain sentence", async () => {
  const { CORE_MESSAGES, describe } = await import("../dist/messages.js");
  const source = readFileSync(resolve(here, "../../core/src/input.ts"), "utf8");
  const codes = [...source.matchAll(/^\s*\| "([A-Z_]+)"/gm)].map((m) => m[1]);
  assert.ok(codes.length >= 26);
  for (const code of codes) assert.equal(typeof CORE_MESSAGES[code], "string", `sentence for ${code}`);
  for (const code of Object.keys(CORE_MESSAGES)) assert.ok(codes.includes(code), `${code} is still a core code`);
  assert.equal(describe("NOT_A_CODE", "engine said so"), "engine said so");
});

// ------------------------------------------------------------------ owner key rotation and pre-rotation

test("pre-rotation: init commits a next key (or not, --no-next-key); owner status warns while it is on this host; rotate-key needs it (--next-key); commit-next-key", async (t) => {
  const dir = tempDir(t), history = join(dir, "history.jsonl"), next = `${history}.owner-next-key.json`;
  const WARNING = "move it offline; pre-rotation only protects you if the next key is not on this host";
  const init = run(["init", "--history", history]);
  ok(init);
  assert.match(init.stdout, /next key {3}.*owner-next-key\.json \(mode 0600/);
  assert.ok(init.stdout.includes(`WARNING  The next key ${next} sits beside the current owner key: ${WARNING}.`), init.stdout);
  const status = json(["owner", "status", "--history", history]);
  ok(status);
  assert.deepEqual([status.value.commitment.position, status.value.commitment.source], [0, "GENESIS"]);
  assert.equal(status.value.nextKeyFile.state, "COMMITTED");
  assert.equal(status.value.nextKeyOnHost, true);
  assert.deepEqual(status.value.warnings.map((w) => w.code), ["NEXT_KEY_ON_HOST"]);
  assert.ok(status.value.warnings[0].message.endsWith(WARNING));
  const human = run(["owner", "status", "--history", history]);
  ok(human);
  assert.match(human.stdout, /OWNER KEYS {2}next key on this host/);
  assert.match(human.stdout, /next key +COMMITTED · 1 key · in the genesis .* at position 0/);
  assert.ok(human.stdout.includes(WARNING));
  // Moved offline: no warning; the rotation refuses without it and names the remedy.
  const usb = join(dir, "usb-next-key.json");
  renameSync(next, usb);
  const offline = json(["owner", "status", "--history", history]);
  assert.deepEqual(offline.value.warnings, []);
  assert.equal(offline.value.nextKeyFile, null);
  assert.match(run(["owner", "status", "--history", history]).stdout, /next-key file +not on this host/);
  const refused = json(["owner", "rotate-key", "--history", history]);
  assert.equal(refused.code, 1);
  assert.equal(refused.value.error.code, "KEY_UNAVAILABLE");
  assert.match(refused.value.error.message, /only that key can replace them.*owner rotate-key --next-key <file>/);
  assert.equal(json(["owner", "rotate-key", "--history", history, "--next-key", join(dir, "nowhere.json")]).value.error.code, "NEXT_KEY_NOT_FOUND");
  const wrong = json(["owner", "rotate-key", "--history", history, "--next-key", `${history}.owner-key.json`]);
  assert.equal(wrong.value.error.code, "KEY_UNAVAILABLE");
  const rotated = json(["owner", "rotate-key", "--history", history, "--next-key", usb, "--reason", "drill"]);
  ok(rotated);
  assert.equal(rotated.value.preRotated, true);
  assert.equal(rotated.value.keyId, "owner:2");
  assert.equal(rotated.value.nextKeySource, usb);
  assert.equal(rotated.value.nextKeyFile, next);
  assert.equal(rotated.value.nextKeyCommitted, true);
  assert.deepEqual(rotated.value.warnings.map((w) => w.code), ["NEXT_KEY_ON_HOST"]);
  const event = core.openHistoryStore(history).state().events.at(-1);
  assert.deepEqual(event.data.nextKeyAuthorizations.map((p) => p.keyId), ["owner:2"]);
  ok(run(["verify", "--history", history]));
  // The default path: the next key beside the history is taken; the output says the used copy now holds the owner key when it was elsewhere.
  const again = run(["owner", "rotate-key", "--history", history]);
  ok(again);
  assert.match(again.stdout, /ROTATED {2}owner key owner:2 → owner:3 \(pre-rotated: the committed next key\)/);
  assert.ok(again.stdout.includes(WARNING));
  // --no-next-key, then owner commit-next-key; a second commitment is refused.
  const bare = join(dir, "bare.jsonl");
  const created = json(["init", "--history", bare, "--no-next-key"]);
  ok(created);
  assert.equal(created.value.head.position, 1);
  assert.equal(created.value.nextKeyCommitted, false);
  assert.equal(existsSync(`${bare}.owner-next-key.json`), false);
  assert.deepEqual(created.value.warnings.map((w) => w.code), ["NO_NEXT_KEY_COMMITMENT"]);
  assert.match(run(["owner", "status", "--history", bare]).stdout, /next key +NONE/);
  const committed = json(["owner", "commit-next-key", "--history", bare]);
  ok(committed);
  assert.equal(committed.value.committed, true);
  assert.equal(committed.value.keyId, "owner:2");
  assert.equal(committed.value.nextKeyFile, `${bare}.owner-next-key.json`);
  assert.equal(committed.value.head.position, 2);
  assert.equal(committed.value.ownerKeysUnchanged, true);
  const commitEvent = core.openHistoryStore(bare).state().events[2];
  assert.equal(commitEvent.type, "OWNER_KEYS_ROTATED", "a commitment-only rotation: the owner keys are kept");
  assert.deepEqual(commitEvent.data.ownerKeys.map((k) => k.keyId), ["owner:1"]);
  assert.match(run(["owner", "status", "--history", bare]).stdout, /next key +COMMITTED · 1 key · by the commitment-only rotation \(keys unchanged\)/);
  const twice = json(["owner", "commit-next-key", "--history", bare]);
  assert.equal(twice.code, 1);
  assert.equal(twice.value.error.code, "TRANSITION_REJECTED");
  // A leftover next-key file is not adopted by init.
  const planted = join(dir, "planted.jsonl");
  copyFileSync(`${bare}.owner-next-key.json`, `${planted}.owner-next-key.json`);
  const exists = json(["init", "--history", planted]);
  assert.equal(exists.value.error.code, "KEY_EXISTS");
  assert.match(exists.value.error.message, /--reuse-existing-key/);
  // Legacy histories have no owner keys.
  const legacy = await olderHistory(join(dir, "legacy.jsonl"), LEGACY);
  assert.equal(existsSync(`${legacy}.owner-next-key.json`), false);
  assert.equal(json(["owner", "commit-next-key", "--history", legacy]).value.error.code, "FORMAT_READ_ONLY");
  assert.match(run(["owner", "status", "--history", legacy]).stdout, /legacy .* has no owner keys/);
});

test("owner rotate-key: records the rotation, swaps the key file, later writes and pins use the new key; refusals", async (t) => {
  const dir = tempDir(t), history = join(dir, "history.jsonl");
  ok(run(["init", "--history", history]));
  ok(run(["agent", "create", "bea", "--history", history]));
  const before = readFileSync(`${history}.owner-key.json`, "utf8");
  const rotated = json(["owner", "rotate-key", "--reason", "scheduled rotation", "--history", history]);
  ok(rotated);
  assert.equal(rotated.value.rotated, true);
  assert.equal(rotated.value.keyId, "owner:2");
  assert.equal(rotated.value.signedBy, "owner:1");
  assert.deepEqual(rotated.value.retired, ["owner:1"]);
  assert.deepEqual(rotated.value.ownerKeys, ["owner:2"]);
  assert.equal(rotated.value.fromPosition, rotated.value.head.position + 1);
  assert.equal(rotated.value.reason, "scheduled rotation");
  assert.equal(rotated.value.keyFile, `${history}.owner-key.json`);
  assert.equal(readFileSync(rotated.value.retiredKeyFile, "utf8"), before);
  ok(run(["agent", "create", "alex", "--history", history]));
  const status = json(["status", "--history", history]);
  assert.deepEqual(status.value.ownerKeys, ["owner:2"]);
  assert.equal(status.value.pinnedHead.attestation.keyId, "owner:2");
  ok(run(["verify", "--history", history]));
  const human = run(["owner", "rotate-key", "--key-id", "owner:ops", "--history", history]);
  ok(human);
  assert.match(human.stdout, /ROTATED {2}owner key owner:2 → owner:ops/);
  assert.match(human.stdout, /key file .*owner-key\.json \(mode 0600/);
  const reused = json(["owner", "rotate-key", "--key-id", "owner:1", "--history", history]);
  assert.equal(reused.code, 1);
  assert.equal(reused.value.error.code, "INVALID_INPUT");
  const legacy = await olderHistory(join(dir, "legacy.jsonl"), LEGACY);
  const refused = json(["owner", "rotate-key", "--history", legacy]);
  assert.equal(refused.code, 1);
  assert.equal(refused.value.error.code, "FORMAT_READ_ONLY");
  // init has no option that writes an older format (A-9).
  assert.equal(json(["init", "--legacy", "--history", join(dir, "never.jsonl")]).value.error.code, "USAGE");
});
