// End to end against the REAL witness server process (WITNESS-DESIGN §6 e2e (3), §9.1): two divergent copies written
// with the same owner key (the witness records EQUIVOCATION as evidence; the divergent writer refuses with WITNESS_FORK;
// the on-chain writer continues), and the C5 race (the file is rolled back between the client's GET and its POST) —
// timing is controlled by a proxy that holds the racing POST. Real `irontrellis` CLI processes on both copies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import {
  checkLog, checkpointOf, cliFor, core, diskHead, freshProcess, gate, historyIdOf, historyLog, ownerOn, restoreFiles, rollbackWith, scratch,
  snapshotFiles, startProxy, startWitnessServer, witnessHistory, witnessLatest, SIDE_FILES,
} from "./e2e-harness.mjs";

const isHeadPost = (request) => request.method === "POST" && /\/v1\/histories\/0x[0-9a-f]{64}\/heads$/.test(request.path);

test("(3) two divergent copies with the same owner key: EQUIVOCATION evidence, the divergent writer refuses (WITNESS_FORK), the on-chain writer goes on and verifies with the warning", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "equivocation.witness" });
    const proxy = await startProxy(space, server);
    const a = space.path("a", "history.jsonl");
    const b = space.path("b", "history.jsonl");
    mkdirSync(space.path("a"), { mode: 0o700 });
    mkdirSync(space.path("b"), { mode: 0o700 });
    const cliA = cliFor(a), cliB = cliFor(b);
    await cliA.ok(["init", "--owner", "ops"]);
    await cliA.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    for (const id of ["agent:1", "agent:2"]) await cliA.ok(["agent", "create", id]);
    const id = historyIdOf(a);
    // The copy: every file, the owner key included (the same owner key writes both).
    for (const suffix of [...SIDE_FILES, ".owner-key.json"]) if (existsSync(a + suffix)) copyFileSync(a + suffix, b + suffix);
    const base = diskHead(a);

    // B's head statement is held on the network after B checked the witness and appended; A's write lands meanwhile.
    const hold = gate();
    proxy.before = hold.hold(isHeadPost);
    const writeB = cliB(["agent", "create", "agent:branch-b"], { json: true });
    await hold.reached;
    await cliA.ok(["agent", "create", "agent:branch-a"]);
    const aHead = diskHead(a);
    assert.equal(aHead.position, base.position + 1);
    assert.deepEqual(await witnessLatest(server, id), aHead, "A's head is the witness latest");
    hold.release();
    const refusedB = await writeB;
    proxy.before = undefined;
    assert.equal(refusedB.code, 1, refusedB.stdout + refusedB.stderr);
    assert.equal(refusedB.json.error.code, "ROLLBACK_DETECTED");
    assert.equal(refusedB.json.error.context.reason, "WITNESS_FORK");
    const bHead = diskHead(b);
    assert.equal(bHead.position, aHead.position, "B appended locally before its statement was refused");
    assert.notEqual(bHead.hash, aHead.hash);

    // The witness recorded the conflicting statement as evidence (§9.1) and kept its latest.
    const info = await witnessHistory(server, id);
    assert.equal(info.equivocations, 1);
    assert.equal(info.lastEquivocation.entry.kind, "EQUIVOCATION");
    assert.equal(info.lastEquivocation.entry.first.statement.head.hash, aHead.hash);
    assert.equal(info.lastEquivocation.entry.second.statement.head.hash, bHead.hash);
    assert.deepEqual(info.latest.head, aHead);
    assert.equal((await historyLog(server, id)).at(-1), `EQUIVOCATION ${aHead.position}`);
    const size = (await checkpointOf(server)).size;

    // The divergent writer refuses further writes (a new CLI process, and a library handle), signing nothing.
    const again = await cliB(["agent", "create", "agent:b2"], { json: true });
    assert.equal(again.code, 1);
    assert.equal(again.json.error.code, "ROLLBACK_DETECTED");
    assert.equal(again.json.error.context.reason, "WITNESS_FORK");
    freshProcess();
    const ownerB = ownerOn(b);
    await assert.rejects(ownerB.createAgent({ id: "agent:b3" }), rollbackWith("WITNESS_FORK"));
    await assert.rejects(ownerB.createAgent({ id: "agent:b4" }), rollbackWith("WITNESS_FORK"), "sticky");
    ownerB.close?.();
    assert.equal((await checkpointOf(server)).size, size, "nothing more reached the witness from B");
    const verifyB = await cliB(["verify"], { json: true });
    assert.equal(verifyB.code, 1);
    assert.ok(verifyB.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK") && /not a prefix/.test(f)), verifyB.stdout);

    // The on-chain writer continues; its statements keep being accepted.
    for (const agent of ["agent:a2", "agent:a3"]) await cliA.ok(["agent", "create", agent]);
    assert.deepEqual(await witnessLatest(server, id), diskHead(a));
    const verifyA = await cliA(["verify"], { json: true });
    assert.equal(verifyA.code, 0, verifyA.stdout);
    assert.equal(verifyA.json.report.remoteWitnessStatus, "OK");
    assert.ok(verifyA.json.notes.some((n) => n.startsWith("REMOTE_WITNESS_EQUIVOCATION_RECORDED 1")), verifyA.stdout);
    assert.equal(verifyA.json.warnings[0].code, "REMOTE_WITNESS_EQUIVOCATION_RECORDED");
    assert.equal(verifyA.json.warnings[0].lastEquivocation.position, aHead.position);
    const text = await cliA(["verify"]);
    assert.equal(text.code, 0);
    assert.match(text.stdout, /^WARNING {2}/m);
    assert.match(text.stdout, /treat the owner key as compromised and rotate it/);
    const status = await cliA(["witness", "status"], { json: true });
    assert.equal(status.code, 0, status.stdout);
    assert.equal(status.json.remote[0].equivocations, 1);
    const library = await core.verifyHistoryWithWitnesses(a);
    assert.equal(library.ok, true, library.failures.join("\n"));
    assert.ok(library.notes.some((n) => n.startsWith("REMOTE_WITNESS_EQUIVOCATION_RECORDED 1:")));

    const audit = checkLog(server.dataDir);
    assert.equal(audit.status, "VALID", JSON.stringify(audit.problems));
    assert.equal(audit.equivocatingHistories, 1);
    assert.equal(audit.kinds.EQUIVOCATION, 1);
  } finally {
    await space.cleanup();
  }
});

test("(3, C5 race) the file is rolled back between the client's GET and its POST: recorded as evidence, that process refuses, no permanent damage — the restored good copy writes on", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "c5.witness" });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    for (const agent of ["agent:1", "agent:2"]) await cli.ok(["agent", "create", agent]);
    const id = historyIdOf(history);
    const old = snapshotFiles(history);

    // The true branch appends while the witness is unreachable: its statement stays queued in the side file.
    proxy.down = true;
    const queued = await cli(["agent", "create", "agent:true"]);
    assert.equal(queued.code, 0, `an unreachable witness queues (sync mode): ${queued.stdout}\n${queued.stderr}`);
    proxy.down = false;
    const good = snapshotFiles(history);
    const trueHead = diskHead(history);
    assert.equal((await witnessLatest(server, id)).position, trueHead.position - 1);

    // The attacker restores the older copy; a fresh owner process checks the witness (a prefix: fine), appends, and
    // while its statement is on the wire the attacker puts the true branch back, lets it be submitted, and rolls back again.
    restoreFiles(history, old);
    const hold = gate();
    proxy.before = hold.hold(isHeadPost);
    const racing = cli(["agent", "create", "agent:rolled-back"], { json: true });
    await hold.reached;
    const racingFiles = snapshotFiles(history);
    restoreFiles(history, good);
    await cli.ok(["witness", "sync"]);
    assert.deepEqual(await witnessLatest(server, id), trueHead);
    restoreFiles(history, racingFiles);
    hold.release();
    const refused = await racing;
    proxy.before = undefined;
    assert.equal(refused.code, 1, refused.stdout + refused.stderr);
    assert.equal(refused.json.error.code, "ROLLBACK_DETECTED");
    assert.equal(refused.json.error.context.reason, "WITNESS_FORK");
    const info = await witnessHistory(server, id);
    assert.equal(info.equivocations, 1, "the conflicting statement is recorded as evidence");
    assert.deepEqual(info.latest.head, trueHead, "the witness latest is untouched");

    // No permanent damage: the good copy is restored and the owner writes on (CLI and library).
    restoreFiles(history, good);
    await cli.ok(["agent", "create", "agent:after-restore"]);
    const next = diskHead(history);
    assert.equal(next.position, trueHead.position + 1);
    assert.deepEqual(await witnessLatest(server, id), next, "the witness accepts the statement extending its latest head");
    freshProcess();
    const owner = ownerOn(history);
    const written = await owner.createAgent({ id: "agent:library" });
    await owner.flush();
    assert.deepEqual(await witnessLatest(server, id), written.head);
    assert.equal(owner.witnessStatus().alarm, undefined);
    owner.close?.();
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 0, verdict.stdout);
    assert.ok(verdict.json.notes.some((n) => n.startsWith("REMOTE_WITNESS_EQUIVOCATION_RECORDED 1")));
    const log = await historyLog(server, id);
    const at = log.indexOf(`EQUIVOCATION ${trueHead.position}`);
    assert.ok(at >= 0, log.join("\n"));
    assert.deepEqual(log.slice(at + 1).map((line) => line.split(" ").slice(0, 2).join(" ")), [`HEAD ${next.position}`, `HEAD ${written.head.position}`]);
    const audit = checkLog(server.dataDir);
    assert.equal(audit.status, "VALID", JSON.stringify(audit.problems));
    assert.equal(audit.equivocatingHistories, 1);
  } finally {
    await space.cleanup();
  }
});

test("M1 (review), real server: the history file is swapped for an owner-signed fork while an honest owner process's sync submission is on the network (the unlocked window): FILE_CHANGED_UNDER_WRITER, nothing is signed for the fork, the witness log is unchanged", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "m1.witness" });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    await cli.ok(["agent", "create", "agent:0"]);
    const id = historyIdOf(history);
    // A long-lived owner process that has checked and submitted once.
    freshProcess();
    const owner = ownerOn(history);
    await owner.createAgent({ id: "agent:warm" });
    const x = await witnessLatest(server, id);
    assert.deepEqual(x, diskHead(history));
    // A genuine second branch F from x, written with the owner key (a second owner process with the witness off).
    const forkFile = space.path("fork", "history.jsonl");
    mkdirSync(space.path("fork"));
    for (const suffix of ["", ".head", ".anchors", ".owner-key.json"]) if (existsSync(history + suffix)) copyFileSync(history + suffix, forkFile + suffix);
    const forkOwner = ownerOn(forkFile, { extra: { witness: false } });
    for (let n = 0; n < 3; n += 1) await forkOwner.createAgent({ id: `agent:fork:${n}` });
    forkOwner.close?.();
    const fork = snapshotFiles(forkFile);
    const forkHead = diskHead(forkFile);
    const before = await checkpointOf(server), logBefore = await historyLog(server, id);
    // The attacker swaps F in when the honest process asks the witness after its next append (before it signs).
    let swapped = false;
    proxy.before = (request) => {
      if (swapped || request.method !== "GET" || request.path !== `/v1/histories/${id}`) return undefined;
      swapped = true;
      restoreFiles(history, { "": fork[""], ".head": fork[".head"], ".anchors": fork[".anchors"] });
      return undefined;
    };
    await assert.rejects(owner.createAgent({ id: "agent:honest" }), rollbackWith("FILE_CHANGED_UNDER_WRITER"));
    assert.equal(swapped, true);
    await assert.rejects(owner.flush(), rollbackWith("FILE_CHANGED_UNDER_WRITER"), "sticky: this handle never signs again");
    owner.close?.();
    proxy.before = undefined;
    assert.deepEqual(await checkpointOf(server), before, "nothing reached the witness");
    assert.deepEqual(await historyLog(server, id), logBefore);
    assert.deepEqual(await witnessLatest(server, id), x);
    assert.notDeepEqual(await witnessLatest(server, id), forkHead, "the fork's head was never attested");
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});
