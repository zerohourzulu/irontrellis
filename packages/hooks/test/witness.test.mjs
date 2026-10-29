/**
 * The hook and remote witnesses (docs/WITNESS.md §5): the hook opens the history through the owner API, which picks
 * up the witness policy from <history>.witness.json and the history's bindings, so no hook configuration changes.
 * A SessionStart that writes submits the head statement before the hook exits; a history rolled back behind the
 * witness makes tool calls fail closed. The witness is the core's in-test fake; the hook runs as an asynchronous child
 * process so the fake in this process can answer it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { openHistoryStore, openLocalOwner } from "@ramex-labs/irontrellis";
import { startFakeWitness } from "../../core/test/helpers/fake-witness.mjs";

const BIN = resolve(fileURLToPath(new URL("../bin/irontrellis-hook.mjs", import.meta.url)));
const STATE_HOME = mkdtempSync(join(tmpdir(), "irontrellis-home-"));

const run = (args, { cwd, stdin = "" }) => new Promise((done) => {
  const child = spawn(process.execPath, [BIN, ...args], { cwd, env: { ...process.env, NO_COLOR: "1", IRONTRELLIS_HOME: STATE_HOME } });
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("close", (code) => {
    let json;
    try { json = stdout.trim() === "" ? undefined : JSON.parse(stdout); } catch { json = undefined; }
    done({ code, stdout, stderr, json });
  });
  child.stdin.end(stdin);
});
const hook = (event, payload, cwd) => run(["claude-code", event], { cwd, stdin: JSON.stringify(payload) });
const sessionStart = (dir, session) => ({ session_id: session, transcript_path: `${dir}/t.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "SessionStart", source: "startup" });
const preToolUse = (dir, tool_name, tool_input, session) => ({ session_id: session, transcript_path: `${dir}/t.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "toolu_1" });
const configOf = (dir) => JSON.parse(readFileSync(join(dir, "irontrellis-hook.json"), "utf8"));
const historyOf = (dir) => resolve(dir, configOf(dir).history);
const ownerOf = (dir) => {
  const config = configOf(dir);
  // The hook creates format-2 histories (A-85): the default writer.
  return openLocalOwner({ historyFile: historyOf(dir), domain: config.domain, owner: config.owner, controller: config.controller, now: () => Date.now() });
};
const SUFFIXES = ["", ".head", ".anchors", ".witness.json"];
const snapshot = (h) => Object.fromEntries(SUFFIXES.map((x) => [x, existsSync(h + x) ? readFileSync(h + x) : undefined]));
const restore = (h, snap) => { for (const [x, bytes] of Object.entries(snap)) { if (bytes === undefined) rmSync(h + x, { force: true }); else writeFileSync(h + x, bytes, { mode: 0o600 }); } };

test("a hook-triggered write submits its head statement to the remote witness before the hook exits", async (t) => {
  const w = await startFakeWitness({ name: "hook-witness" });
  t.after(() => w.close());
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-hook-witness-")));
  assert.equal((await run(["init"], { cwd: dir })).code, 0);
  const owner = ownerOf(dir);
  const added = await owner.addWitness({ url: w.url, verifierKey: w.verifierKey }); // async mode: the hook must flush itself
  assert.equal(added.submitted, true);
  const history = historyOf(dir);
  const historyId = openHistoryStore(history).state().eventHistoryHashes[0];
  const before = w.heads(historyId).length;
  const start = await hook("SessionStart", sessionStart(dir, "s-1"), dir);
  assert.equal(start.code, 0, start.stderr);
  const head = openHistoryStore(history).state().head;
  assert.ok(head.position > added.status.head.position, "the session start wrote to the history");
  assert.deepEqual(w.latest(historyId), head, "the witness holds the head the hook left behind");
  assert.ok(w.heads(historyId).length > before);
  // A tool decision reads; it writes nothing and submits nothing.
  const statements = w.state.statements.length;
  const decision = await hook("PreToolUse", preToolUse(dir, "Read", { file_path: join(dir, "README.md") }, "s-1"), dir);
  assert.equal(decision.code, 0, decision.stderr);
  assert.equal(w.state.statements.length, statements);
});

test("a history rolled back behind the witness makes the hook fail closed", async (t) => {
  const w = await startFakeWitness({ name: "hook-witness-2" });
  t.after(() => w.close());
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-hook-witness-")));
  assert.equal((await run(["init"], { cwd: dir })).code, 0);
  const owner = ownerOf(dir);
  await owner.addWitness({ url: w.url, verifierKey: w.verifierKey }, { mode: "sync" });
  const history = historyOf(dir);
  assert.equal((await hook("SessionStart", sessionStart(dir, "s-1"), dir)).code, 0);
  const old = snapshot(history);
  await owner.grant({ id: "grant:read", to: configOf(dir).agentId, actions: ["read-file"], resources: ["*"], expiresAt: Date.now() + 86_400_000 });
  await owner.revoke("grant:read");
  const call = () => hook("PreToolUse", preToolUse(dir, "Bash", { command: "ls" }, "s-1"), dir);
  // The history and its pin are put back to the older copy; the side file remembers what the witness holds.
  restore(history, { "": old[""], ".head": old[".head"] });
  let refused = await call();
  assert.equal(refused.code, 2, refused.stderr);
  assert.match(refused.stderr, /ROLLBACK_DETECTED \(WITNESS_AHEAD\)/);
  // Everything restored, side file included: with requireOnOpen the hook asks the witness before deciding.
  restore(history, old);
  const policy = JSON.parse(readFileSync(`${history}.witness.json`, "utf8"));
  writeFileSync(`${history}.witness.json`, JSON.stringify({ ...policy, policy: { ...policy.policy, requireOnOpen: true, cacheMs: 0 } }), { mode: 0o600 });
  refused = await call();
  assert.equal(refused.code, 2, refused.stderr);
  assert.match(refused.stderr, /ROLLBACK_DETECTED \(WITNESS_AHEAD\)/);
  // A session start on the old copy writes nothing and admits nothing.
  const events = openHistoryStore(history, { inspect: true }).state().events.length;
  const start = await hook("SessionStart", sessionStart(dir, "s-2"), dir);
  assert.match(start.stdout + start.stderr, /ROLLBACK_DETECTED/);
  assert.equal(openHistoryStore(history, { inspect: true }).state().events.length, events);
});

// runtime events (here, recorded refusals signed by the agent's session) count
// toward maxUnwitnessedEvents but queue no head statement. At the limit, the next owner write (the next session's fence
// and admission) flushes first, as `irontrellis witness sync` does; with the witness down it is refused, without a
// false "queued", naming the remedy, and the power-reducing fence still goes through.
const sessionEnd = (dir, session) => ({ session_id: session, transcript_path: `${dir}/t.jsonl`, cwd: dir, hook_event_name: "SessionEnd", reason: "exit" });
const eventsOf = (history) => openHistoryStore(history, { inspect: true, witness: false }).state().events;
async function atTheLimit(t, name) {
  const w = await startFakeWitness({ name });
  t.after(() => w.close());
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-hook-witness-limit-")));
  assert.equal((await run(["init"], { cwd: dir })).code, 0);
  // A limit of 1: the hook coalesces a repeated refusal by the same actor within a minute (session-writes), so this
  // test, whose hook processes run on the wall clock, records one runtime event; one is enough to reach the limit.
  await ownerOf(dir).addWitness({ url: w.url, verifierKey: w.verifierKey }, { maxUnwitnessedEvents: 1 });
  assert.equal((await hook("SessionStart", sessionStart(dir, "s-1"), dir)).code, 0);
  // A denied call, recorded as a refusal signed by the agent's session: a runtime event, which queues no head statement.
  const denied = await hook("PreToolUse", preToolUse(dir, "mcp__a__run", { x: 1 }, "s-1"), dir);
  assert.match(denied.stdout + denied.stderr, /DENY/);
  assert.equal(eventsOf(historyOf(dir)).at(-1).type, "REQUEST_REFUSED");
  assert.ok(ownerOf(dir).witnessStatus().unwitnessedEvents >= 1, "the runtime event reached the limit");
  assert.equal((await hook("SessionEnd", sessionEnd(dir, "s-1"), dir)).code, 0);
  return { w, dir, history: historyOf(dir) };
}
const admitted = (events, host) => events.some((e) => e.type === "RUNTIME_SESSION_ADMITTED" && JSON.stringify(e.data).includes(`session:${host}`));

test("at maxUnwitnessedEvents after runtime events, the next session start flushes, then fences and admits", async (t) => {
  const { w, dir, history } = await atTheLimit(t, "hook-witness-limit-1");
  const start = await hook("SessionStart", sessionStart(dir, "s-2"), dir);
  assert.equal(start.code, 0, start.stderr);
  const events = eventsOf(history);
  assert.ok(admitted(events, "s-2"), "s-2 admitted");
  assert.ok(events.some((e) => e.type === "CONTROL_EPOCH_ADVANCED"), "s-1 fenced");
  const historyId = openHistoryStore(history).state().eventHistoryHashes[0];
  assert.deepEqual(w.latest(historyId), openHistoryStore(history).state().head, "the witness holds the new head");
});

test("the same with the witness down: the fence is written, the admission refused (MAX_UNWITNESSED) naming the remedy; \"queued\" only for the fence's real statement", async (t) => {
  const { w, dir, history } = await atTheLimit(t, "hook-witness-limit-2");
  w.down = true;
  const start = await hook("SessionStart", sessionStart(dir, "s-2"), dir);
  const said = start.stdout + start.stderr;
  assert.match(said, /not yet witnessed/);
  assert.match(said, /irontrellis witness sync/);
  // The fence is an owner write: it queued its own head statement, so "queued" is true here (a runtime event queues none).
  const pending = JSON.parse(readFileSync(`${history}.witness.json`, "utf8")).pending.filter((item) => item.kind === "statement");
  assert.ok(pending.length > 0 && /queued head statements/.test(said));
  const events = eventsOf(history);
  assert.ok(events.some((e) => e.type === "CONTROL_EPOCH_ADVANCED"), "the power-reducing fence went through");
  assert.ok(admitted(events, "s-1") && !admitted(events, "s-2"), "s-2 not admitted");
});

// the recorder writes with the witnesses off, so it must not append while a prepared owner key rotation is
// outstanding (a bound witness may already hold its head; an append on its previous head would fork that witness). The
// hook's own owner handle resolves a pending rotation when it opens, if it can; one it cannot resolve (witnesses
// unreachable) is still there when the recorder runs, which is the case tested here, by calling the recorder directly.
test("while a prepared rotation is pending, the recorder spools a session refusal and records no CONNECTOR refusal; nothing is appended", async () => {
  const { loadConfigFile } = await import("../dist/config.js");
  const { recordToolRefusal } = await import("../dist/refusals.js");
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-hook-rotation-pending-")));
  assert.equal((await run(["init"], { cwd: dir })).code, 0);
  assert.equal((await hook("SessionStart", sessionStart(dir, "s-1"), dir)).code, 0);
  const config = loadConfigFile(join(dir, "irontrellis-hook.json"));
  const history = historyOf(dir), pendingFile = `${history}.rotation.pending.json`, spool = `${history}.refusals.spool`;
  writeFileSync(pendingFile, "{}\n", { mode: 0o600 }); // only its presence matters to the recorder
  const head = () => openHistoryStore(history, { inspect: true, witness: false }).state().head;
  const before = head();
  const session = await recordToolRefusal(config, "s-1", { action: "call-mcp", resource: "mcp:a", code: "NO_AUTHORITY" }, () => Date.now());
  assert.deepEqual(session, { recorded: false, reason: "SPOOLED" });
  const connector = await recordToolRefusal(config, "s-1", { action: "call-mcp", resource: "mcp:b", code: "NO_AUTHORITY", withoutSession: true }, () => Date.now());
  assert.deepEqual(connector, { recorded: false, reason: "ROTATION_PENDING" });
  assert.deepEqual(head(), before, "nothing appended");
  assert.equal(readFileSync(spool, "utf8").trim().split("\n").length, 1, "the session refusal is spooled");
  rmSync(pendingFile);
  const next = await recordToolRefusal(config, "s-1", { action: "call-mcp", resource: "mcp:c", code: "NO_AUTHORITY" }, () => Date.now());
  assert.ok(next.eventId !== undefined || next.reason === "COALESCED", JSON.stringify(next));
  const refused = openHistoryStore(history, { inspect: true, witness: false }).state().events.filter((e) => e.type === "REQUEST_REFUSED");
  assert.ok(refused.some((e) => JSON.stringify(e.data).includes("mcp:a")), "the spooled refusal is recorded by the next drain");
});

// Astra's review of the fix above: the recorder's own check runs before the append lock, so a rotation prepared between that
// check and the append was not seen. The store now refuses a witness-off append under the writer lock while the marker
// exists; these interleave the marker's creation with a held lock, as Astra's reproducer does.
async function raceSetup(name) {
  const { loadConfigFile } = await import("../dist/config.js");
  const { recordToolRefusal } = await import("../dist/refusals.js");
  const dir = realpathSync(mkdtempSync(join(tmpdir(), name)));
  assert.equal((await run(["init"], { cwd: dir })).code, 0);
  assert.equal((await hook("SessionStart", sessionStart(dir, "race-session"), dir)).code, 0);
  const config = loadConfigFile(join(dir, "irontrellis-hook.json")), history = historyOf(dir);
  const read = () => openHistoryStore(history, { inspect: true, witness: false }).state();
  const refuse = (resource) => recordToolRefusal(config, "race-session", { action: "call-mcp", resource, code: "NO_AUTHORITY" }, () => Date.now(), 2000);
  /** Starts `refuse(resource)` while another handle holds the writer lock, and creates the marker before releasing it. */
  const raced = async (resource) => {
    const holder = openHistoryStore(history, { witness: false });
    let attempt;
    await holder.withExclusiveWriter(async () => { attempt = refuse(resource); writeFileSync(`${history}.rotation.pending.json`, "{}\n", { mode: 0o600 }); });
    holder.close();
    return attempt;
  };
  return { history, read, refuse, raced, spool: `${history}.refusals.spool`, pending: `${history}.rotation.pending.json` };
}
const spooled = (file) => existsSync(file) ? readFileSync(file, "utf8").trim().split("\n").filter(Boolean).length : 0;

test("a rotation prepared between the recorder's check and its locked append: the refusal is spooled, nothing appended (Astra's reproducer)", async () => {
  const r = await raceSetup("irontrellis-rotation-race-");
  const before = r.read().head;
  const outcome = await r.raced("mcp:rotation-race");
  assert.deepEqual(outcome, { recorded: false, reason: "SPOOLED" });
  assert.equal(existsSync(r.pending), true);
  assert.deepEqual(r.read().head, before, "nothing appended while the marker exists");
  assert.equal(spooled(r.spool), 1);
});

test("the spool drain under the same race: a rotation prepared during the drain keeps the spooled entries, nothing appended", async () => {
  const r = await raceSetup("irontrellis-rotation-race-drain-");
  writeFileSync(r.pending, "{}\n", { mode: 0o600 });
  assert.deepEqual(await r.refuse("mcp:first"), { recorded: false, reason: "SPOOLED" });
  rmSync(r.pending);
  const before = r.read().head;
  await r.raced("mcp:second"); // drains mcp:first under the lock it waits for, after the marker appeared
  assert.deepEqual(r.read().head, before, "neither the drained entry nor the new refusal was appended");
  assert.equal(r.read().events.some((e) => e.type === "REQUEST_REFUSED" && JSON.stringify(e.data).includes("mcp:first")), false);
  assert.ok(spooled(r.spool) >= 2, "both refusals wait in the spool");
});
