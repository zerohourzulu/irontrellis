// End to end against the REAL witness server process (WITNESS-DESIGN §6 e2e (5), (6); quorum): the witness restarted
// between writes (SIGTERM and SIGKILL, one held mid-POST) with clients continuing and no split view raised; the witness
// down in async mode (queue, maxUnwitnessedEvents, reads continue, `irontrellis witness sync` recovers); and 2-of-3
// quorum with three real servers. Each server sits behind a proxy so its URL survives restarts.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  checkLog, checkpointOf, cliFor, core, diskHead, freshProcess, gate, historyIdOf, ownerOn, restoreFiles, rollbackWith, scratch, snapshotFiles, startProxy,
  startWitnessServer, witnessLatest,
} from "./e2e-harness.mjs";

test("(5) witness restarts between writes (SIGTERM, SIGKILL, and a SIGKILL while a statement is in flight): clients continue, checkpoints stay consistent, no split view", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "restart.witness" });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    const id = historyIdOf(history);
    // A long-lived owner process (library) keeps its checkpoint knowledge in memory across the restarts.
    freshProcess();
    const owner = ownerOn(history);
    let n = 0;
    const libraryWrite = async () => {
      const result = await owner.createAgent({ id: `agent:lib:${(n += 1)}` });
      assert.deepEqual(await witnessLatest(server, id), result.head, "sync: witnessed when the write returns");
      return result;
    };
    await libraryWrite();
    await cli.ok(["agent", "create", "agent:cli:0"]);
    for (const signal of ["SIGTERM", "SIGKILL"]) {
      const exit = await server.stop(signal);
      // Windows: every kill is TerminateProcess (no graceful SIGTERM); the restart reclaims the stale lock either way.
      if (signal === "SIGTERM" && process.platform !== "win32") assert.equal(exit.code, 0, "graceful shutdown");
      else assert.equal(exit.signal, signal);
      await server.start();
      await libraryWrite();
      await cli.ok(["agent", "create", `agent:cli:${signal}`]);
      assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    }
    assert.ok(server.logs.some((line) => /stale/.test(line.msg ?? "")), "the SIGKILLed server's lock was reclaimed");

    // SIGKILL while a head statement is on the wire: the write is recorded locally and its statement stays queued.
    const hold = gate();
    proxy.before = hold.hold((request) => request.method === "POST" && request.path.endsWith("/heads"));
    const inFlight = owner.createAgent({ id: "agent:in-flight" });
    await hold.reached;
    await server.stop("SIGKILL");
    hold.release();
    const written = await inFlight;
    proxy.before = undefined;
    assert.equal(owner.witnessStatus().unwitnessedEvents, 1, "not counted as witnessed");
    await server.start();
    await owner.flush();
    assert.deepEqual(await witnessLatest(server, id), written.head);
    await libraryWrite();
    const status = owner.witnessStatus();
    assert.equal(status.alarm, undefined);
    assert.equal(status.witnesses[0].splitView, undefined);
    assert.equal(status.unwitnessedEvents, 0);
    owner.close?.();
    // The checkpoint remembered in the side file is the witness's current one (or proven a prefix of it), and every
    // checkpoint the witness ever issued verifies against its replayed log.
    const side = core.readWitnessState(`${history}.witness.json`);
    const remembered = Object.values(side.witnesses)[0].checkpoint;
    const current = await checkpointOf(server);
    assert.ok(remembered.size <= current.size);
    if (remembered.size === current.size) assert.equal(remembered.rootB64, current.rootB64);
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 0, verdict.stdout);
    assert.equal(verdict.json.report.remoteWitnessStatus, "OK");
    assert.equal(server.starts, 4);
    const audit = checkLog(server.dataDir);
    assert.equal(audit.status, "VALID", JSON.stringify(audit.problems));
    assert.equal(audit.entries, current.size);
  } finally {
    await space.cleanup();
  }
});

test("(6) witness down, async mode: writes queue up to maxUnwitnessedEvents then refuse WITNESS_UNAVAILABLE; reads continue; `irontrellis witness sync` recovers", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "down.witness" });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "async", "--max-unwitnessed", "3"]);
    await cli.ok(["agent", "create", "agent:0"]);
    await cli.ok(["witness", "sync"]);
    const id = historyIdOf(history);
    const witnessed = await witnessLatest(server, id);
    assert.deepEqual(witnessed, diskHead(history));

    await server.stop("SIGTERM");
    for (let k = 1; k <= 3; k += 1) {
      const queued = await cli(["agent", "create", `agent:queued:${k}`]);
      assert.equal(queued.code, 0, `write ${k} is recorded and queued: ${queued.stdout}\n${queued.stderr}`);
    }
    const refused = await cli(["agent", "create", "agent:refused"], { json: true });
    assert.equal(refused.code, 1, refused.stdout);
    assert.equal(refused.json.error.code, "WITNESS_UNAVAILABLE");
    assert.equal(refused.json.error.context.reason, "MAX_UNWITNESSED");
    assert.equal(diskHead(history).position, witnessed.position + 3, "the refused write appended nothing");
    // The library owner is refused the same way; reads continue.
    freshProcess();
    const owner = ownerOn(history);
    await assert.rejects(owner.createAgent({ id: "agent:lib-refused" }), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "MAX_UNWITNESSED");
    assert.equal(owner.capacity().eventCount, diskHead(history).position + 1);
    owner.close?.();
    await cli.ok(["status"]);
    assert.equal(core.openHistoryStore(history).state().head.position, diskHead(history).position);
    // verify fails closed while the witness is unreachable, unless allowed.
    const down = await cli(["verify"], { json: true });
    assert.equal(down.code, 1);
    assert.ok(down.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_UNREACHABLE")), down.stdout);
    await cli.ok(["verify", "--allow-unreachable-witness"]);
    const stillDown = await cli(["witness", "sync"], { json: true });
    assert.equal(stillDown.code, 1);
    assert.equal(stillDown.json.synced, false);
    assert.deepEqual(await (async () => { await server.start(); return witnessLatest(server, id); })(), witnessed, "nothing arrived while down");

    // Back: sync submits the queued head (coalesced), writes resume.
    const synced = await cli(["witness", "sync"], { json: true });
    assert.equal(synced.code, 0, synced.stdout + synced.stderr);
    assert.equal(synced.json.status.unwitnessedEvents, 0);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    await cli.ok(["agent", "create", "agent:resumed"]);
    await cli.ok(["witness", "sync"]);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    await cli.ok(["verify"]);
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("(8) quorum 2 of 3 real witnesses: one down is tolerated, two down refuse; a rollback shown by any single witness is fatal", { timeout: 180_000 }, async () => {
  const space = scratch();
  try {
    const servers = await Promise.all([1, 2, 3].map((k) => startWitnessServer(space, { name: `quorum-${k}.witness` })));
    const proxies = await Promise.all(servers.map((server) => startProxy(space, server)));
    const [w1, w2, w3] = servers;
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    for (const [k, server] of servers.entries()) {
      await cli.ok(["witness", "add", proxies[k].url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync", "--max-unwitnessed", "2", ...(k === 1 ? ["--quorum", "2"] : [])]);
    }
    const id = historyIdOf(history);
    const status = await cli(["witness", "status"], { json: true });
    assert.equal(status.json.policy.quorum, 2);
    assert.equal(status.json.witnesses.length, 3);
    await cli.ok(["agent", "create", "agent:all"]);
    for (const server of servers) assert.deepEqual(await witnessLatest(server, id), diskHead(history));

    // One down: tolerated.
    await w3.stop("SIGTERM");
    await cli.ok(["agent", "create", "agent:two-of-three"]);
    assert.deepEqual(await witnessLatest(w1, id), diskHead(history));
    assert.deepEqual(await witnessLatest(w2, id), diskHead(history));
    const tolerated = await cli(["verify"], { json: true });
    assert.equal(tolerated.code, 0, tolerated.stdout);
    assert.ok(tolerated.json.notes.some((note) => note.startsWith("REMOTE_WITNESS_UNREACHABLE")));
    await cli.ok(["witness", "sync"]);

    // Two down: the head is not witnessed by a quorum; sync and verify refuse, writes stop at maxUnwitnessedEvents.
    await w2.stop("SIGTERM");
    await cli.ok(["agent", "create", "agent:one-of-three"]);
    const sync = await cli(["witness", "sync"], { json: true });
    assert.equal(sync.code, 1, sync.stdout);
    const unreachable = await cli(["verify"], { json: true });
    assert.equal(unreachable.code, 1);
    assert.ok(unreachable.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_UNREACHABLE")), unreachable.stdout);
    await cli.ok(["agent", "create", "agent:second-unwitnessed"]);
    const refused = await cli(["agent", "create", "agent:refused"], { json: true });
    assert.equal(refused.code, 1, refused.stdout);
    assert.equal(refused.json.error.code, "WITNESS_UNAVAILABLE");
    await w2.start();
    await w3.start();
    const recovered = await cli(["witness", "sync"], { json: true });
    assert.equal(recovered.code, 0, recovered.stdout + recovered.stderr);
    for (const server of servers) assert.deepEqual(await witnessLatest(server, id), diskHead(history));

    // Only w3 hears the newest head (the statements to w1 and w2 are lost on the way; quorum 2 is not reached);
    // the attacker then restores the older copy. w1 and w2 still see a prefix — w3's word alone fails it.
    const old = snapshotFiles(history);
    for (const proxy of [proxies[0], proxies[1]]) proxy.before = (request) => (request.method === "POST" && request.path.endsWith("/heads") ? { status: 503, body: { error: { code: "INTERNAL", message: "dropped" } } } : undefined);
    const lossy = await cli(["agent", "create", "agent:only-w3"]);
    assert.equal(lossy.code, 0, lossy.stdout + lossy.stderr);
    for (const proxy of proxies) proxy.before = undefined;
    const newest = diskHead(history);
    assert.deepEqual(await witnessLatest(w3, id), newest);
    assert.notDeepEqual(await witnessLatest(w1, id), newest);
    restoreFiles(history, old);
    const sizes = await Promise.all(servers.map(async (server) => (await checkpointOf(server)).size));
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 1, verdict.stdout);
    assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && f.includes(proxies[2].url)), verdict.stdout);
    freshProcess();
    const owner = ownerOn(history);
    await assert.rejects(owner.createAgent({ id: "agent:on-old-copy" }), rollbackWith("WITNESS_AHEAD"));
    owner.close?.();
    const write = await cli(["agent", "create", "agent:cli-on-old-copy"]);
    assert.equal(write.code, 1);
    assert.match(write.stderr, /ROLLBACK_DETECTED/);
    assert.deepEqual(await Promise.all(servers.map(async (server) => (await checkpointOf(server)).size)), sizes, "no witness received anything for the old copy");
    for (const server of servers) assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});
