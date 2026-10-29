// End to end against the REAL witness server process (WITNESS-DESIGN §1, §6 e2e (1), (2); scenario 10): the rc.1
// residual attack (an older copy of the history + pin + anchors + side file restored), truncation, and registration
// authorisation — driven through the real `irontrellis` CLI and `irontrellis-hook` binaries and the core library.
// Every scenario asserts the client outcome AND the witness log (HTTP API and the offline `check-log`).
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  checkLog, checkpointOf, cliFor, core, diskHead, freshProcess, historyIdOf, historyLog, hookRunner, http, ownerOn, restoreFiles, rollbackWith,
  scratch, snapshotFiles, startProxy, startWitnessServer, witnessHistory, witnessLatest,
} from "./e2e-harness.mjs";
const { FORMAT1_TEST_TOOLING } = await import("@ramex-labs/irontrellis/internal-format1"); // A-185.3 / A-194: older formats are test tooling

test("(1) the rc.1 residual attack against a real witness: verify, requireOnOpen readers, library and CLI writers all refuse; the witness receives nothing", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync", "--require-on-open", "--cache-ms", "0"]);
    const id = historyIdOf(history);
    // The owner writes N events, each witnessed before the CLI returns (sync), and anchors in the local anchor log.
    for (let n = 0; n < 4; n += 1) await cli.ok(["agent", "create", `agent:${n}`]);
    // A write whose data is built from the current state (a grant) from a fresh process under requireOnOpen: the
    // witness check comes first (it used to fail NOT_CHECKED before asking).
    await cli.ok(["grant", "grant:read", "--to", "agent:0", "--actions", "read", "--resources", "doc:*", "--expires", String(Date.now() + 86_400_000)]);
    await cli.ok(["anchor"]);
    await cli.ok(["agent", "create", "agent:after-anchor"]);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history), "sync: the witness holds the head the CLI left");
    // The attacker keeps this copy: history, owner-attested pin, anchors log, witness side file.
    const old = snapshotFiles(history);
    const oldHead = diskHead(history);
    for (let n = 0; n < 5; n += 1) await cli.ok(["agent", "create", `agent:later:${n}`]);
    const witnessed = await witnessLatest(server, id);
    assert.deepEqual(witnessed, diskHead(history));
    assert.ok(witnessed.position > oldHead.position);
    const good = snapshotFiles(history);
    restoreFiles(history, old);
    const before = await checkpointOf(server);
    const logBefore = await historyLog(server, id);

    // Locally the copy is flawless.
    await cli.ok(["verify", "--no-remote"]);
    // verify asks the witness: REMOTE_WITNESS_ROLLBACK, non-zero exit.
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 1, verdict.stdout);
    assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")), verdict.stdout);
    const human = await cli(["verify"]);
    assert.equal(human.code, 1);
    assert.match(human.stdout + human.stderr, /REMOTE_WITNESS_ROLLBACK/);
    // A reader under requireOnOpen (the restored side file's own policy): gated, then the check fails, then every read fails.
    freshProcess();
    const reader = core.openHistoryStore(history);
    assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
    await assert.rejects(reader.checkWitnesses(), rollbackWith("WITNESS_AHEAD"));
    assert.throws(() => reader.state(), rollbackWith("WITNESS_AHEAD"));
    const status = await cli(["status"], { json: true });
    assert.equal(status.code, 1);
    assert.equal(status.json.error.code, "ROLLBACK_DETECTED");
    // The next owner write refuses before appending: through the library (a fresh owner process) …
    freshProcess();
    const owner = ownerOn(history);
    await assert.rejects(owner.createAgent({ id: "agent:on-the-old-branch" }), rollbackWith("WITNESS_AHEAD"));
    await assert.rejects(owner.createAgent({ id: "agent:again" }), rollbackWith("WITNESS_AHEAD"), "sticky");
    owner.close?.();
    // … and through the CLI.
    const write = await cli(["agent", "create", "agent:cli-on-the-old-branch"]);
    assert.equal(write.code, 1, write.stdout);
    assert.match(write.stderr, /ROLLBACK_DETECTED/);
    // repin cannot re-attest the old head.
    const repin = await cli(["repin"]);
    assert.notEqual(repin.code, 0);
    assert.deepEqual(diskHead(history), oldHead, "nothing was appended to the rolled-back copy");
    // The witness received NO new statement: log size, root and this history's leaves unchanged.
    assert.deepEqual(await checkpointOf(server), before);
    assert.deepEqual(await historyLog(server, id), logBefore);
    assert.deepEqual(await witnessLatest(server, id), witnessed);
    const audit = checkLog(server.dataDir);
    assert.equal(audit.status, "VALID", JSON.stringify(audit.problems));
    assert.equal(audit.entries, before.size);
    assert.equal(audit.equivocatingHistories, 0);

    // Recovery: the good copy (on the witness chain) is put back, and the owner writes on.
    restoreFiles(history, good);
    await cli.ok(["agent", "create", "agent:after-recovery"]);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    assert.equal(diskHead(history).position, witnessed.position + 1);
    await cli.ok(["verify"]);
  } finally {
    await space.cleanup();
  }
});

/** The side file as an attacker on the host rewrites it (policy changed, everything remembered dropped). */
const rewriteSideFile = (history, policy) => {
  const path = `${history}.witness.json`;
  const doc = JSON.parse(readFileSync(path, "utf8"));
  writeFileSync(path, JSON.stringify({ ...doc, policy: policy(doc.policy), witnesses: {}, pending: [] }), { mode: 0o600 });
};

/** The rc.1 residual attack set up against a real witness: returns the old (restored) head, the witnessed latest and the log before. */
async function rolledBack(space, server, cli, history, writes = 3) {
  for (let n = 0; n < 2; n += 1) await cli.ok(["agent", "create", `agent:${n}`]);
  const old = snapshotFiles(history);
  const oldHead = diskHead(history);
  for (let n = 0; n < writes; n += 1) await cli.ok(["agent", "create", `agent:later:${n}`]);
  const id = historyIdOf(history);
  const witnessed = await witnessLatest(server, id);
  assert.ok(witnessed.position > oldHead.position);
  restoreFiles(history, old);
  return { id, oldHead, witnessed, before: await checkpointOf(server), logBefore: await historyLog(server, id) };
}

test("B1 (review), real server: the attacker-writable side file points the BOUND witness's verifier key at a loopback relay that replays the older genuine answer — ignored: the bound URL is pinned, the relay is never asked, the rollback is found by verify, readers and writers", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "pinned.witness" });
    const relay = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync", "--require-on-open", "--cache-ms", "0"]);
    const { id, oldHead, witnessed, before, logBefore } = await rolledBack(space, server, cli, history);
    // The review's PoC: the relay answers `latest` with the genuine receipt of the restored (older) head and drops writes.
    const older = (await http(server.url, "GET", `/v1/histories/${id}/heads/${oldHead.position}`)).json;
    relay.transform = (request, response) => {
      if (request.method !== "GET" || request.path !== `/v1/histories/${id}`) return undefined;
      return { body: JSON.stringify({ ...JSON.parse(response.body), latest: { head: older.head, receipt: older.receipt } }) };
    };
    relay.before = (request) => (request.method === "POST" ? { status: 503, body: { error: { code: "INTERNAL", message: "down" } } } : undefined);
    rewriteSideFile(history, (policy) => ({ ...policy, witnesses: policy.witnesses.map((w) => ({ ...w, url: relay.url })) }));
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 1, verdict.stdout);
    assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && f.includes(server.url)), verdict.stdout);
    freshProcess();
    const reader = core.openHistoryStore(history);
    assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
    await assert.rejects(reader.checkWitnesses(), rollbackWith("WITNESS_AHEAD"));
    reader.close();
    freshProcess();
    const owner = ownerOn(history);
    assert.deepEqual(owner.witnessStatus().witnesses.map((w) => w.url), [server.url], "the binding's URL");
    await assert.rejects(owner.createAgent({ id: "agent:on-old-copy" }), rollbackWith("WITNESS_AHEAD"));
    owner.close?.();
    const write = await cli(["agent", "create", "agent:cli-on-old-copy"], { json: true });
    assert.equal(write.code, 1, write.stdout);
    assert.equal(write.json.error.code, "ROLLBACK_DETECTED");
    assert.deepEqual(diskHead(history), oldHead);
    assert.deepEqual(relay.log, [], "the relay was never asked");
    assert.deepEqual(await checkpointOf(server), before);
    assert.deepEqual(await historyLog(server, id), logBefore);
    assert.deepEqual(await witnessLatest(server, id), witnessed);
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("H1 (review), real server: the side file raises the quorum and adds an attacker's witness (registration open) while pointing the bound one at a dead port — the bound witness is still asked (its binding pins it and its quorum), the rollback is found even with --allow-unreachable-witness, writers refuse", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const honest = await startWitnessServer(space, { name: "honest.witness" });
    const attacker = await startWitnessServer(space, { name: "attacker.witness", config: { registration: "open" } });
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", honest.url, "--verifier-key", honest.verifierKey, "--token", honest.token, "--mode", "sync", "--require-on-open", "--cache-ms", "0"]);
    const { id, oldHead, witnessed, before, logBefore } = await rolledBack(space, honest, cli, history);
    rewriteSideFile(history, () => ({
      witnesses: [{ url: "http://127.0.0.1:1", verifierKey: honest.verifierKey, timeoutMs: 1 }, { url: attacker.url, verifierKey: attacker.verifierKey }],
      quorum: 2, mode: "async", maxUnwitnessedEvents: Number.MAX_SAFE_INTEGER, requireOnOpen: false, cacheMs: 60_000,
    }));
    for (const args of [["verify"], ["verify", "--allow-unreachable-witness"]]) {
      const verdict = await cli(args, { json: true });
      assert.equal(verdict.code, 1, `${args.join(" ")}: ${verdict.stdout}`);
      assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && f.includes(honest.url)), verdict.stdout);
    }
    freshProcess();
    const reader = core.openHistoryStore(history);
    assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED", "the binding's requireOnOpen holds");
    reader.close();
    freshProcess();
    const owner = ownerOn(history);
    await assert.rejects(owner.createAgent({ id: "agent:on-old-copy" }), rollbackWith("WITNESS_AHEAD"));
    owner.close?.();
    const write = await cli(["agent", "create", "agent:cli-on-old-copy"], { json: true });
    assert.equal(write.code, 1, write.stdout);
    assert.equal(write.json.error.code, "ROLLBACK_DETECTED");
    assert.deepEqual(diskHead(history), oldHead);
    assert.deepEqual(await checkpointOf(honest), before);
    assert.deepEqual(await historyLog(honest, id), logBefore);
    assert.deepEqual(await witnessLatest(honest, id), witnessed);
    assert.ok(!(await historyLog(attacker, id)).some((line) => line.startsWith("HEAD")), "no head statement for the old copy reached the attacker's witness either");
  } finally {
    await space.cleanup();
  }
});

test("(1, hook) a Claude Code tool call on a history rolled back behind the real witness fails closed (exit 2); a SessionStart writes nothing", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "hook.witness" });
    const project = space.path("project");
    const hook = hookRunner(space.path("state-home"));
    mkdirSync(project, { mode: 0o700 });
    const init = await hook(["init"], { cwd: project });
    assert.equal(init.code, 0, init.stdout + init.stderr);
    const config = JSON.parse(readFileSync(join(project, "irontrellis-hook.json"), "utf8"));
    const history = resolve(project, config.history);
    const cli = cliFor(history);
    await cli.ok(["witness", "add", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync", "--require-on-open", "--cache-ms", "0"]);
    const id = historyIdOf(history);
    const payload = (event, extra) => JSON.stringify({ session_id: "s-1", transcript_path: `${project}/t.jsonl`, cwd: project, permission_mode: "default", hook_event_name: event, ...extra });
    const start = await hook(["claude-code", "SessionStart"], { cwd: project, stdin: payload("SessionStart", { source: "startup" }) });
    assert.equal(start.code, 0, start.stderr);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history), "the hook's write was witnessed before it exited");
    const toolCall = () => hook(["claude-code", "PreToolUse"], { cwd: project, stdin: payload("PreToolUse", { tool_name: "Read", tool_input: { file_path: join(project, "README.md") }, tool_use_id: "toolu_1" }) });
    const allowedBefore = await toolCall();
    assert.equal(allowedBefore.code, 0, allowedBefore.stderr);

    const old = snapshotFiles(history);
    const owner = ownerOn(history, { owner: config.owner, controller: config.controller, extra: { domain: config.domain } });
    await owner.grant({ id: "grant:later", to: config.agentId, actions: ["read-file"], resources: ["*"], expiresAt: Date.now() + 86_400_000 });
    await owner.revoke("grant:later");
    owner.close?.();
    const witnessed = await witnessLatest(server, id);
    assert.deepEqual(witnessed, diskHead(history));
    restoreFiles(history, old);
    const size = (await checkpointOf(server)).size;

    const refused = await toolCall();
    assert.equal(refused.code, 2, `the hook fails closed: ${refused.stdout}\n${refused.stderr}`);
    assert.match(refused.stderr, /ROLLBACK_DETECTED \(WITNESS_AHEAD\)/);
    const eventsBefore = diskHead(history).position;
    const again = await hook(["claude-code", "SessionStart"], { cwd: project, stdin: payload("SessionStart", { session_id: "s-2", source: "startup" }) });
    assert.match(again.stdout + again.stderr, /ROLLBACK_DETECTED/);
    assert.equal(diskHead(history).position, eventsBefore, "nothing appended");
    assert.equal((await checkpointOf(server)).size, size, "no statement reached the witness");
    assert.deepEqual(await witnessLatest(server, id), witnessed);
  } finally {
    await space.cleanup();
  }
});

test("(2) truncation: the honest write attempt is refused and the witness latest is unchanged — with the side file kept, and with it deleted", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "trunc.witness" });
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    const id = historyIdOf(history);
    for (let n = 0; n < 3; n += 1) await cli.ok(["agent", "create", `agent:${n}`]);
    const cut = snapshotFiles(history);
    for (let n = 0; n < 3; n += 1) await cli.ok(["agent", "create", `agent:later:${n}`]);
    const witnessed = await witnessLatest(server, id);
    const sizeBefore = (await checkpointOf(server)).size;

    // (a) The history and its pin are cut back; the side file (which remembers the witness head) stays.
    restoreFiles(history, { "": cut[""], ".head": cut[".head"] });
    const kept = await cli(["agent", "create", "agent:after-truncation"]);
    assert.equal(kept.code, 1);
    assert.match(kept.stderr, /ROLLBACK_DETECTED/);
    freshProcess();
    await assert.rejects(async () => ownerOn(history).createAgent({ id: "agent:lib" }), rollbackWith("WITNESS_AHEAD"));
    assert.equal((await cli(["verify"], { json: true })).code, 1);
    assert.deepEqual(await witnessLatest(server, id), witnessed);
    assert.equal((await checkpointOf(server)).size, sizeBefore);

    // (b) The side file is deleted too: the history's own owner-signed binding still names the witness, which is asked.
    rmSync(`${history}.witness.json`);
    const deleted = await cli(["agent", "create", "agent:after-truncation-2"], { json: true });
    assert.equal(deleted.code, 1, deleted.stdout);
    assert.equal(deleted.json.error.code, "ROLLBACK_DETECTED");
    assert.equal(deleted.json.error.context.reason, "WITNESS_AHEAD");
    freshProcess();
    const owner = ownerOn(history);
    assert.equal(owner.witnessStatus().witnesses[0].bound, true);
    await assert.rejects(owner.createAgent({ id: "agent:lib-2" }), rollbackWith("WITNESS_AHEAD"));
    owner.close?.();
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 1);
    assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && /past the end/.test(f)), verdict.stdout);
    assert.deepEqual(await witnessLatest(server, id), witnessed, "witness latest unchanged");
    assert.equal((await checkpointOf(server)).size, sizeBefore, "no statement for the truncated branch");
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("(10) registration needs the admin token: without it UNAUTHORIZED (nothing registered); `irontrellis witness add --token` registers", { timeout: 60_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "auth.witness" });
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    const id = historyIdOf(history);
    const genesis = core.openHistoryStore(history, { witness: false }).state().events[0];
    // Raw HTTP: no token, a wrong token.
    for (const headers of [{}, { authorization: "Bearer itw_not-the-token" }, { authorization: `Basic ${server.token}` }]) {
      const reply = await http(server.url, "POST", "/v1/histories", { genesis }, headers);
      assert.equal(reply.status, 401, reply.text);
      assert.equal(reply.json.error.code, "UNAUTHORIZED");
    }
    assert.equal(await witnessHistory(server, id), undefined);
    assert.equal((await checkpointOf(server)).size, 0, "nothing was appended");
    // The CLI without a token: refused, the history binds nothing.
    const refused = await cli(["witness", "add", server.url, "--verifier-key", server.verifierKey], { json: true });
    assert.notEqual(refused.code, 0, refused.stdout);
    assert.match(JSON.stringify(refused.json), /UNAUTHORIZED/);
    assert.equal(await witnessHistory(server, id), undefined);
    assert.equal(core.openHistoryStore(history, { witness: false }).state().anchors.length, 0, "no binding was recorded");
    // Reads never need a token; a head statement for an unregistered history is NOT_REGISTERED (and registers nothing).
    assert.equal((await http(server.url, "GET", "/v1/witness")).status, 200);
    // With the token: registered (REGISTERED leaf), bound, and the head witnessed.
    const added = await cli(["witness", "add", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"], { json: true });
    assert.equal(added.code, 0, added.stdout + added.stderr);
    assert.equal(added.json.submitted, true);
    const info = await witnessHistory(server, id);
    assert.deepEqual(info.latest.head, diskHead(history));
    assert.deepEqual((await historyLog(server, id))[0], "REGISTERED");
    // The token is kept in the side file (0600) for later registrations; a second history registers through the library with it.
    const side = JSON.parse(readFileSync(`${history}.witness.json`, "utf8"));
    assert.equal(side.policy.witnesses[0].token, server.token);
    const other = space.path("other.jsonl");
    const owner = await core.createLocalOwner({ historyFile: other, domain: core.createLocalDomain({ format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, owner: "o", controller: "o", now: () => Date.now(),
      witness: { witnesses: [{ url: server.url, verifierKey: server.verifierKey, token: server.token }], mode: "sync" } });
    await owner.createAgent({ id: "agent:x" });
    assert.deepEqual(await witnessLatest(server, historyIdOf(other)), diskHead(other));
    // A library policy without the token: the registration is refused BEFORE the history file exists (the genesis is
    // registered in memory first), so the creation fails with WITNESS_REJECTED and leaves nothing behind.
    const tokenless = space.path("tokenless.jsonl");
    const size = (await checkpointOf(server)).size;
    await assert.rejects(core.createLocalOwner({ historyFile: tokenless, domain: core.createLocalDomain({ format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, owner: "o", controller: "o", now: () => Date.now(),
      witness: { witnesses: [{ url: server.url, verifierKey: server.verifierKey }], mode: "sync" } }), (e) => e.code === "WITNESS_REJECTED" && /UNAUTHORIZED/.test(e.message) && /was not created/.test(e.message));
    assert.equal(existsSync(tokenless), false, "no history file");
    assert.equal(existsSync(`${tokenless}.owner-key.json`), false, "no key file left behind");
    assert.equal(existsSync(`${tokenless}.owner-next-key.json`), false, "no next-key file left behind either");
    assert.equal((await checkpointOf(server)).size, size, "nothing reached the witness");
    // The CLI's init --witness does the same.
    const cliTokenless = space.path("cli-tokenless.jsonl");
    const refusedInit = await cliFor(cliTokenless)(["init", "--owner", "ops", "--witness", server.url, "--verifier-key", server.verifierKey], { json: true });
    assert.equal(refusedInit.code, 1, refusedInit.stdout);
    assert.equal(refusedInit.json.error.code, "WITNESS_REJECTED");
    assert.equal(existsSync(cliTokenless), false);
    // init --witness with the token: the binding is the event right after the principal, written with the first events and
    // carrying the witness's signed REGISTERED receipt; no copy of the history ever exists without it.
    const bound = space.path("bound-at-init.jsonl");
    await cliFor(bound).ok(["init", "--owner", "ops", "--witness", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    const boundState = core.openHistoryStore(bound, { inspect: true, witness: false }).state();
    // Genesis (carrying the next-key commitment), principal and binding (position 2), all in the first write.
    assert.equal(boundState.events.length, 3);
    assert.equal(boundState.events[0].data.nextKeyDigests.length, 1);
    assert.equal(boundState.events[2].type, "WITNESSES_BOUND");
    assert.ok(core.boundRegistrationOf(boundState, server.verifierKey) !== undefined);
    assert.deepEqual(await witnessLatest(server, historyIdOf(bound)), diskHead(bound), "the head was submitted before init exited");
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("(10) a witness that refuses the registration later (bound while unreachable, now wants a token) is a sticky WITNESS_REJECTED state in writes and witness status, not unavailability; the policy change clears it", { timeout: 90_000 }, async () => {
  const space = scratch();
  try {
    const first = await startWitnessServer(space, { name: "first.witness" });
    const second = await startWitnessServer(space, { name: "second.witness" });
    const proxy = await startProxy(space, second);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    // A-39.3 made requireOnOpen the init default; this scenario reads with a witness down, so it turns it off.
    await cli.ok(["init", "--owner", "ops", "--witness", first.url, "--verifier-key", first.verifierKey, "--token", first.token, "--mode", "sync", "--no-require-on-open"]);
    await cli.ok(["agent", "create", "agent:1"]);
    // witness add fails WITHOUT binding anything when the witness answers but refuses (no token) ...
    const size = (await checkpointOf(second)).size;
    const eventsBefore = diskHead(history).position;
    const refused = await cli(["witness", "add", proxy.url, "--verifier-key", second.verifierKey], { json: true });
    assert.equal(refused.code, 1, refused.stdout);
    assert.equal(refused.json.error.code, "WITNESS_REJECTED");
    assert.equal(diskHead(history).position, eventsBefore, "no binding was written");
    // ... or serves another key ...
    const wrongKey = await cli(["witness", "add", proxy.url, "--verifier-key", first.verifierKey, "--token", second.token], { json: true });
    assert.equal(wrongKey.code, 1, wrongKey.stdout);
    assert.equal(wrongKey.json.error.code, "WITNESS_REJECTED");
    assert.match(wrongKey.stdout, /serves verifier key/);
    // ... or cannot be reached (unless --allow-offline).
    proxy.down = true;
    const offline = await cli(["witness", "add", proxy.url, "--verifier-key", second.verifierKey], { json: true });
    assert.equal(offline.code, 1, offline.stdout);
    assert.equal(offline.json.error.code, "WITNESS_UNAVAILABLE");
    assert.equal(diskHead(history).position, eventsBefore, "nothing written");
    const added = await cli(["witness", "add", proxy.url, "--verifier-key", second.verifierKey, "--allow-offline"], { json: true });
    assert.equal(added.code, 0, added.stdout + added.stderr);
    assert.equal(added.json.registered, false);
    assert.equal(diskHead(history).position, eventsBefore + 1, "bound (without a registration receipt)");
    // The witness comes back and refuses the registration: every owner write is refused with WITNESS_REJECTED (sticky),
    // nothing is appended, and witness status shows the state.
    proxy.down = false;
    const write = await cli(["agent", "create", "agent:2"], { json: true });
    assert.equal(write.code, 1, write.stdout);
    assert.equal(write.json.error.code, "WITNESS_REJECTED");
    assert.equal(write.json.error.context.reason, "REGISTRATION_REFUSED");
    assert.equal(diskHead(history).position, eventsBefore + 1);
    const again = await cli(["agent", "create", "agent:3"], { json: true });
    assert.equal(again.json.error.code, "WITNESS_REJECTED", "sticky");
    const status = await cli(["witness", "status"], { json: true });
    assert.equal(status.code, 1, status.stdout);
    assert.equal(status.json.rejected.url, proxy.url);
    assert.match(status.stdout, /UNAUTHORIZED/);
    const human = await cli(["witness", "status"]);
    assert.match(human.stdout, /WITNESS_REJECTED/);
    assert.equal((await checkpointOf(second)).size, size, "nothing was registered or submitted at the refusing witness");
    // Changing the policy for that witness (its token) clears the state: registered, re-bound with the receipt, writes go on.
    const fixed = await cli(["witness", "add", proxy.url, "--verifier-key", second.verifierKey, "--token", second.token], { json: true });
    assert.equal(fixed.code, 0, fixed.stdout + fixed.stderr);
    assert.equal(fixed.json.registered, true);
    assert.ok(core.boundRegistrationOf(core.openHistoryStore(history, { inspect: true, witness: false }).state(), second.verifierKey) !== undefined);
    await cli.ok(["agent", "create", "agent:4"]);
    const clean = await cli(["witness", "status"], { json: true });
    assert.equal(clean.code, 0, clean.stdout);
    assert.equal(clean.json.rejected, undefined);
    for (const server of [first, second]) {
      assert.deepEqual(await witnessLatest(server, historyIdOf(history)), diskHead(history));
      assert.equal(checkLog(server.dataDir).status, "VALID");
    }
  } finally {
    await space.cleanup();
  }
});

test("a copy restored from BEFORE `irontrellis witness add` (side file deleted) carries no binding: an out-of-band IRONTRELLIS_WITNESS_POLICY (CLI and hook) catches it; without one it is the documented residual, which binding at init avoids", { timeout: 90_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "prebinding.witness" });
    const project = space.path("project");
    mkdirSync(project, { mode: 0o700 });
    const hook = hookRunner(space.path("state-home"));
    const init = await hook(["init"], { cwd: project });
    assert.equal(init.code, 0, init.stdout + init.stderr);
    const config = JSON.parse(readFileSync(join(project, "irontrellis-hook.json"), "utf8"));
    const history = resolve(project, config.history);
    const cli = cliFor(history);
    await cli.ok(["agent", "create", "agent:before-the-witness"]);
    const beforeWitness = snapshotFiles(history); // owner-attested pin, no binding, no side file
    await cli.ok(["witness", "add", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync", "--require-on-open"]);
    for (const agent of ["agent:1", "agent:2"]) await cli.ok(["agent", "create", agent]);
    const id = historyIdOf(history);
    const witnessed = await witnessLatest(server, id);
    restoreFiles(history, beforeWitness);
    const size = (await checkpointOf(server)).size;
    // The operator's out-of-band minimum policy, outside anything the agent can write (here: a directory of the test).
    const policyDir = space.path("operator");
    mkdirSync(policyDir, { mode: 0o700 });
    const policyFile = join(policyDir, "irontrellis-witness-policy.json");
    writeFileSync(policyFile, JSON.stringify({ witnesses: [{ url: server.url, verifierKey: server.verifierKey, token: server.token }], requireOnOpen: true }), { mode: 0o600 });
    const env = { IRONTRELLIS_WITNESS_POLICY: policyFile };
    const guarded = cliFor(history, env);
    const verdict = await guarded(["verify"], { json: true });
    assert.equal(verdict.code, 1, verdict.stdout);
    assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")), verdict.stdout);
    const write = await guarded(["agent", "create", "agent:on-the-fork"], { json: true });
    assert.equal(write.code, 1, write.stdout);
    assert.equal(write.json.error.code, "ROLLBACK_DETECTED");
    const status = await guarded(["witness", "status"], { json: true });
    assert.equal(status.json.minimumPolicyFile, policyFile);
    // The hook reads the same variable: a tool call on the restored copy fails closed.
    const payload = JSON.stringify({ session_id: "s-1", transcript_path: `${project}/t.jsonl`, cwd: project, permission_mode: "default", hook_event_name: "PreToolUse",
      tool_name: "Read", tool_input: { file_path: join(project, "README.md") }, tool_use_id: "toolu_1" });
    const refused = await hookRunner(space.path("state-home"), env)(["claude-code", "PreToolUse"], { cwd: project, stdin: payload });
    assert.equal(refused.code, 2, `the hook fails closed: ${refused.stdout}\n${refused.stderr}`);
    assert.match(refused.stderr, /ROLLBACK_DETECTED/);
    // A policy file the agent could have rewritten (group/world-writable) is refused, never ignored (POSIX; on Windows
    // the ACL protects it and the synthetic mode is not checked: docs/PLATFORMS.md §3).
    if (process.platform !== "win32") {
      writeFileSync(policyFile, JSON.stringify({ witnesses: [] }), { mode: 0o666 });
      const { chmodSync } = await import("node:fs");
      chmodSync(policyFile, 0o666);
      const weak = await guarded(["verify"], { json: true });
      assert.equal(weak.code, 1);
      assert.equal(weak.json.error.code, "WITNESS_UNREADABLE", weak.stdout);
    }
    assert.equal((await checkpointOf(server)).size, size, "nothing reached the witness from the restored copy");
    // RESIDUAL (documented): without the out-of-band policy, the history's own files know no witness.
    const unguarded = await cli(["verify"], { json: true });
    assert.equal(unguarded.code, 0, "only an out-of-band witness configuration catches this");
    assert.ok(unguarded.json.notes.some((n) => n.startsWith("ANCHOR_LOG_NONE")));
    assert.deepEqual(await witnessLatest(server, id), witnessed, "the witness chain is untouched");
    // A history created with init --witness has no such copy: its first pinned state already holds the binding.
    const bound = space.path("bound.jsonl");
    await cliFor(bound).ok(["init", "--owner", "ops", "--witness", server.url, "--verifier-key", server.verifierKey, "--token", server.token]);
    const first = core.openHistoryStore(bound, { inspect: true, witness: false });
    assert.equal(first.pinnedHead().position, 2, "the first pin already covers the binding");
    assert.equal(first.state().events[2].type, "WITNESSES_BOUND");
  } finally {
    await space.cleanup();
  }
});

test("a real loss (the witness holds a head no surviving copy contains): `irontrellis witness remove --accept-loss --reason` records the owner's decision and the history continues; nothing else can lift it", { timeout: 90_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "loss.witness" });
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops", "--witness", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    await cli.ok(["agent", "create", "agent:1"]);
    const backup = snapshotFiles(history);
    for (const agent of ["agent:lost-1", "agent:lost-2"]) await cli.ok(["agent", "create", agent]);
    const id = historyIdOf(history);
    const lost = await witnessLatest(server, id);
    // The disk dies; the newest backup is older than what the witness holds.
    restoreFiles(history, backup);
    const refused = await cli(["agent", "create", "agent:x"], { json: true });
    assert.equal(refused.json.error.code, "ROLLBACK_DETECTED");
    const repinned = await cli(["verify", "--accept-rollback"], { json: true });
    const stillRefused = await cli(["agent", "create", "agent:x"], { json: true });
    assert.equal(stillRefused.json.error.code, "ROLLBACK_DETECTED", `--accept-rollback does not accept a remote finding (${repinned.code})`);
    const plainRemove = await cli(["witness", "remove", server.url], { json: true });
    assert.equal(plainRemove.json.error.code, "ROLLBACK_DETECTED", "a plain removal is a refused owner write");
    const noReason = await cli(["witness", "remove", server.url, "--accept-loss"], { json: true });
    assert.equal(noReason.code, 1);
    assert.equal(noReason.json.error.code, "USAGE", "--accept-loss needs --reason");
    // Without the owner key nobody can accept it.
    const keyPath = `${history}.owner-key.json`;
    const key = readFileSync(keyPath);
    rmSync(keyPath);
    const keyless = await cli(["witness", "remove", server.url, "--accept-loss", "--reason", "disk lost"], { json: true });
    assert.equal(keyless.json.error.code, "KEY_UNAVAILABLE", keyless.stdout);
    writeFileSync(keyPath, key, { mode: 0o600 });
    const size = (await checkpointOf(server)).size;
    const accepted = await cli(["witness", "remove", server.url, "--accept-loss", "--reason", "disk lost; restored the backup of 09:00"], { json: true });
    assert.equal(accepted.code, 0, accepted.stdout + accepted.stderr);
    assert.equal(accepted.json.acceptedLoss.reason, "disk lost; restored the backup of 09:00");
    assert.deepEqual(accepted.json.acceptedLoss.heads[0].head, lost);
    const human = await cli(["witness", "status"], { json: true });
    assert.equal(human.code, 1, "no witness left: witness status says so (NO_WITNESS)");
    await cli.ok(["agent", "create", "agent:continues"]);
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 0, verdict.stdout);
    assert.equal((await checkpointOf(server)).size, size, "the removed witness received nothing of the new branch");
    assert.deepEqual(await witnessLatest(server, id), lost, "it keeps what it received");
    // It cannot be bound again (it holds the lost head); a new witness can.
    const readd = await cli(["witness", "add", server.url, "--verifier-key", server.verifierKey, "--token", server.token], { json: true });
    assert.equal(readd.json.error.code, "ROLLBACK_DETECTED");
    const fresh = await startWitnessServer(space, { name: "fresh.witness" });
    await cli.ok(["witness", "add", fresh.url, "--verifier-key", fresh.verifierKey, "--token", fresh.token, "--mode", "sync"]);
    assert.deepEqual(await witnessLatest(fresh, id), diskHead(history));
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});
