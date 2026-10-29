// Storage: restart replays the log to the identical tree; a torn final line
// is cut with a warning; any other corruption refuses to start with a precise
// error; check-log audits a data directory offline; the server lock.
import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, readFileSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { buildHistory, buildScenario, collectingLogger, silentLogger, startWitness, t, tempDir, TestClient, witnessLib } from "./helpers.mjs";

const { Witness, loadWitnessKey, loadConfig, checkLog, DataError } = witnessLib;

/** Fills a fresh data dir with a registered scenario history, heads, a rotation and an equivocation in a second history. */
async function populate(dir) {
  const handle = await startWitness({ dir });
  const client = new TestClient(handle.url, handle.witness.verifierKey);
  const s = await buildScenario();
  const heads = `/v1/histories/${s.historyId}/heads`;
  await client.register(s.events[0]);
  for (const statement of [s.statements.s0, s.statements.s3, s.statements.s6]) await client.post(heads, statement);
  await client.post(heads, await t.signHeadStatement(s.owner1, s.statement(s.heads[7], s.heads[6])));
  const rotated = await client.post(`/v1/histories/${s.historyId}/key-events`, { event: s.rotation, previousHead: { hash: s.heads[6].hash, position: 6 }, eventHead: { hash: s.heads[7].hash, position: 7 } });
  assert.equal(rotated.status, 201);
  await client.post(heads, await t.signHeadStatement(s.owner2, s.statement(s.heads[8], s.heads[7])));
  const h = await buildHistory({ name: "persist-fork", agents: 5 });
  await client.register(h.genesis);
  await client.post(`/v1/histories/${h.historyId}/heads`, await h.statement(0, null));
  await client.post(`/v1/histories/${h.historyId}/heads`, await h.statement(3, 0));
  // A different head at 3 (same key): forge by stating a different hash for position 3.
  const forkHead = { hash: h.heads[4].hash, position: 3, canonicalTime: 3 };
  const fork = await t.signHeadStatement(h.signer1, { version: t.HEAD_STATEMENT_VERSION, historyId: h.historyId, domain: h.domain, head: forkHead, previous: h.at(h.heads[0]) });
  const eq = await client.post(`/v1/histories/${h.historyId}/heads`, fork);
  assert.equal(eq.json.error.code, "EQUIVOCATION");
  const state = {
    checkpoint: (await client.get("/v1/checkpoint")).text,
    history: (await client.get(`/v1/histories/${s.historyId}`)).json,
    equivocated: (await client.get(`/v1/histories/${h.historyId}`)).json,
    size: handle.witness.size,
  };
  await handle.close();
  return { s, h, fork, eq, client, state };
}

const openWitness = (dir, logger = silentLogger, extra = {}) => {
  const key = loadWitnessKey(join(dir, "witness-key.json"));
  const config = loadConfig(join(dir, "config.json"));
  return Witness.open({ dataDir: dir, origin: config.origin, signer: key.signer, verifierKey: key.verifierKey, logger, ...extra });
};

const logLines = (dir) => readFileSync(join(dir, "log.jsonl"), "utf8").split("\n").filter((line) => line !== "");

test("restart replays the log to the identical tree, state and checkpoint; appends continue consistently", async () => {
  const { dir, cleanup } = tempDir();
  try {
    const { s, h, fork, eq, client, state } = await populate(dir);
    const before = readFileSync(join(dir, "checkpoints.jsonl"), "utf8");
    const handle = await startWitness({ dir, init: false });
    client.url = handle.url;
    assert.equal(handle.witness.size, state.size);
    const checkpoint = await client.get("/v1/checkpoint");
    assert.equal(checkpoint.text, state.checkpoint, "no new checkpoint: the last one already covers the log");
    assert.equal(readFileSync(join(dir, "checkpoints.jsonl"), "utf8"), before);
    const history = await client.get(`/v1/histories/${s.historyId}`);
    assert.deepEqual(history.json, state.history);
    // The equivocation evidence and its dedupe survive the restart (the state is a function of the log), and the history is open.
    const equivocated = await client.get(`/v1/histories/${h.historyId}`);
    assert.deepEqual(equivocated.json, state.equivocated);
    assert.equal(equivocated.json.equivocations, 1);
    const again = await client.post(`/v1/histories/${h.historyId}/heads`, fork);
    assert.equal(again.json.error.code, "EQUIVOCATION");
    assert.equal(again.json.receipt.index, eq.json.receipt.index);
    assert.equal((await client.post(`/v1/histories/${h.historyId}/heads`, await h.statement(4, 3))).status, 201);
    const after = await client.post(`/v1/histories/${s.historyId}/heads`, await t.signHeadStatement(s.owner2, s.statement(s.heads[8], s.heads[7])));
    assert.equal(after.json.status, "ALREADY_WITNESSED");
    const more = await buildHistory({ name: "after-restart" });
    assert.equal((await client.register(more.genesis)).status, 201);
    assert.ok(client.checkpoints.length > 10, "the client checked every checkpoint against the ones before the restart");
    await handle.close();
    assert.equal(checkLog(dir, { verifierKey: handle.witness.verifierKey, origin: handle.witness.origin }).ok, true);
  } finally {
    cleanup();
  }
});

test("a torn final line is truncated with a warning (text fragment and zero-filled tail)", async () => {
  const { dir, cleanup } = tempDir();
  try {
    const { state } = await populate(dir);
    const logPath = join(dir, "log.jsonl");
    const size = statSync(logPath).size;
    appendFileSync(logPath, `{"entry":{"genesis":{"data":`);
    const { lines, logger } = collectingLogger();
    let witness = await openWitness(dir, logger);
    assert.equal(witness.size, state.size);
    assert.equal(witness.checkpoint.note, state.checkpoint);
    assert.equal(statSync(logPath).size, size, "the fragment was cut off");
    assert.ok(lines.some((line) => line.level === "warn" && /torn/.test(line.msg)));
    await witness.close();

    appendFileSync(logPath, Buffer.alloc(300));
    witness = await openWitness(dir);
    assert.equal(witness.size, state.size);
    await witness.close();
    assert.equal(statSync(logPath).size, size);

    // A torn checkpoints.jsonl tail is cut too.
    appendFileSync(join(dir, "checkpoints.jsonl"), `{"note":"irontrellis`);
    witness = await openWitness(dir);
    await witness.close();
    assert.ok(readFileSync(join(dir, "checkpoints.jsonl"), "utf8").endsWith("}\n"));
  } finally {
    cleanup();
  }
});

test("corruption refuses to start with a precise error: edited, non-canonical, deleted, reordered, lost lines", async () => {
  const { dir, cleanup } = tempDir();
  try {
    await populate(dir);
    const logPath = join(dir, "log.jsonl");
    const original = readFileSync(logPath, "utf8");
    const lines = logLines(dir);
    const refuse = async (text, pattern) => {
      writeFileSync(logPath, text);
      await assert.rejects(openWitness(dir), (error) => {
        assert.ok(error instanceof DataError, String(error));
        assert.match(error.message, pattern);
        return true;
      });
      writeFileSync(logPath, original);
    };
    // A canonical edit of an unsigned field: replay accepts the line, but the checkpoint root no longer matches.
    const edited = [...lines];
    edited[2] = edited[2].replace(/"receivedAt":(\d+)/, (_, n) => `"receivedAt":${Number(n) + 1}`);
    await refuse(`${edited.join("\n")}\n`, /checkpoints\.jsonl line \d+: .*does not match the root/);
    // Non-canonical spacing on line 3.
    const spaced = [...lines];
    spaced[2] = spaced[2].replace('{"entry":', '{ "entry":');
    await refuse(`${spaced.join("\n")}\n`, /log\.jsonl line 3: not in canonical form/);
    // Not JSON in the middle.
    const garbage = [...lines];
    garbage[1] = "garbage";
    await refuse(`${garbage.join("\n")}\n`, /log\.jsonl line 2: not JSON/);
    // A deleted middle line: the next index is out of place.
    await refuse(`${[lines[0], ...lines.slice(2)].join("\n")}\n`, /log\.jsonl line 2: index 2 where 1 was expected/);
    // A forged statement signature in a HEAD line: the rules pass (no re-verification at start), the root does not.
    const forged = [...lines];
    forged[3] = forged[3].replace(/"signature":"0x([0-9a-f]{4})/, '"signature":"0xffff');
    await refuse(`${forged.join("\n")}\n`, /does not match the root/);
    // An entry that breaks the rules: a HEAD line moved before its registration.
    const moved = JSON.parse(lines[1]);
    moved.index = 0;
    const { canonicalEncode } = await import("@ramex-labs/irontrellis");
    await refuse(`${canonicalEncode(moved)}\n`, /log\.jsonl line 1: history .* is not registered/);
    // Lost acknowledged entries: the last complete line removed.
    await refuse(`${lines.slice(0, -1).join("\n")}\n`, /log lost acknowledged entries/);
    // A checkpoint by another key.
    witnessLib.initDataDir(join(dir, "other"), "other.witness");
    const cpPath = join(dir, "checkpoints.jsonl");
    const cps = readFileSync(cpPath, "utf8");
    const otherKey = loadWitnessKey(join(dir, "other", "witness-key.json"));
    const last = JSON.parse(cps.trim().split("\n").at(-1));
    const note = t.signNote(t.openNote(last.note, [loadWitnessKey(join(dir, "witness-key.json")).verifierKey]).body, otherKey.signer);
    writeFileSync(cpPath, `${cps}${canonicalEncode({ note, size: last.size, time: last.time })}\n`);
    await assert.rejects(openWitness(dir), /does not verify with this witness's key/);
    writeFileSync(cpPath, cps);
    // Everything restored: starts again.
    const witness = await openWitness(dir);
    await witness.close();
  } finally {
    cleanup();
  }
});

test("check-log: VALID on a good log (re-verifying every signature); pinpoints a forged signature, a tampered line and a lost tail", async () => {
  const { dir, cleanup } = tempDir();
  try {
    await populate(dir);
    const key = loadWitnessKey(join(dir, "witness-key.json"));
    const trust = { verifierKey: key.verifierKey, origin: loadConfig(join(dir, "config.json")).origin };
    const good = checkLog(dir, trust);
    assert.equal(good.ok, true, JSON.stringify(good.problems));
    assert.equal(good.histories, 2);
    assert.equal(good.equivocatingHistories, 1);
    assert.deepEqual(good.kinds, { REGISTERED: 2, HEAD: 7, ROTATED: 1, EQUIVOCATION: 1, SUPERSEDED: 0 });
    assert.ok(good.checkpoints >= good.entries);
    assert.equal(good.lastCheckpointSize, good.entries);

    const logPath = join(dir, "log.jsonl");
    const original = readFileSync(logPath, "utf8");
    const lines = logLines(dir);
    // A forged signature: the replay itself (with verification) rejects the line.
    const forged = [...lines];
    const headLine = forged.findIndex((line) => line.includes('"kind":"HEAD"') && !line.includes('"position":0,'));
    forged[headLine] = forged[headLine].replace(/"signature":"0x([0-9a-f]{4})/, '"signature":"0xffff');
    writeFileSync(logPath, `${forged.join("\n")}\n`);
    const bad = checkLog(dir, trust);
    assert.equal(bad.ok, false);
    assert.equal(bad.problems[0].file, "log.jsonl");
    assert.equal(bad.problems[0].line, headLine + 1);
    assert.match(bad.problems[0].message, /signature does not verify/);

    // An unsigned field edited: every checkpoint from that size on fails.
    const edited = [...lines];
    edited[4] = edited[4].replace(/"receivedAt":(\d+)/, (_, n) => `"receivedAt":${Number(n) + 1}`);
    writeFileSync(logPath, `${edited.join("\n")}\n`);
    const tampered = checkLog(dir, trust);
    assert.equal(tampered.ok, false);
    assert.ok(tampered.problems.every((problem) => problem.file === "checkpoints.jsonl" && /does not match the root/.test(problem.message)));
    assert.ok(tampered.problems.length >= 1);

    // §9.2: a ROTATED leaf is verified from the leaf alone. One whose previousHead was altered fails its owner signature.
    const rotationLine = lines.findIndex((line) => line.includes('"kind":"ROTATED"'));
    assert.ok(!lines[rotationLine].includes('"aux"'), "no data outside the leaf");
    assert.match(lines[rotationLine], /^\{"entry":\{"historyId":"0x[0-9a-f]{64}","kind":"ROTATED","previousHead":\{/);
    const moved = [...lines];
    moved[rotationLine] = moved[rotationLine].replace(/"previousHead":\{"hash":"0x([0-9a-f])/, (_, c) => `"previousHead":{"hash":"0x${c === "0" ? "1" : "0"}`);
    writeFileSync(logPath, `${moved.join("\n")}\n`);
    const rot = checkLog(dir, trust);
    assert.equal(rot.ok, false);
    assert.equal(rot.problems[0].line, rotationLine + 1);
    assert.match(rot.problems[0].message, /rotation/);

    // Lost tail.
    writeFileSync(logPath, `${lines.slice(0, -2).join("\n")}\n`);
    const lost = checkLog(dir, trust);
    assert.equal(lost.ok, false);
    assert.ok(lost.problems.some((problem) => /acknowledged entries are missing/.test(problem.message)));

    // Torn tail is only a warning.
    writeFileSync(logPath, `${original}{"ind`);
    const torn = checkLog(dir, trust);
    assert.equal(torn.ok, true);
    assert.ok(torn.warnings.some((warning) => /torn/.test(warning)));
    // Wrong trust: another key.
    writeFileSync(logPath, original);
    const other = checkLog(dir, { verifierKey: t.generateNoteKey("someone").verifierKey, origin: trust.origin });
    assert.equal(other.ok, false);
    assert.match(other.problems[0].message, /does not verify with the witness key/);
  } finally {
    cleanup();
  }
});

test("server.lock: one writer; a dead holder's lock is reclaimed; another host's lock needs --force-unlock", async () => {
  const { dir, cleanup } = tempDir();
  try {
    witnessLib.initDataDir(dir, "lock.witness");
    const first = await openWitness(dir);
    await assert.rejects(openWitness(dir), /another witness server holds the lock \(pid \d+ on /);
    await first.close();

    const lockPath = join(dir, "server.lock");
    // A holder that is gone (a pid that cannot exist).
    writeFileSync(lockPath, JSON.stringify({ pid: 2 ** 22 + 12345, hostname: hostname(), createdAt: Date.now() }));
    const { lines, logger } = collectingLogger();
    const reclaimed = await openWitness(dir, logger);
    assert.ok(lines.some((line) => /stale server lock/.test(line.msg)));
    await reclaimed.close();

    // Our own pid from a previous life (a container's pid 1).
    writeFileSync(lockPath, JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: Date.now() }));
    await (await openWitness(dir)).close();

    // Another host: liveness unknowable.
    writeFileSync(lockPath, JSON.stringify({ pid: 1, hostname: "elsewhere.example", createdAt: Date.now() }));
    await assert.rejects(openWitness(dir), /--force-unlock/);
    const forced = await openWitness(dir, silentLogger, { forceUnlock: true });
    await forced.close();

    // An empty lock (a crash between create and write) is stale after a while.
    writeFileSync(lockPath, "");
    await assert.rejects(openWitness(dir), /holds the lock/);
    const old = new Date(Date.now() - 60_000);
    const { utimesSync } = await import("node:fs");
    utimesSync(lockPath, old, old);
    await (await openWitness(dir)).close();
  } finally {
    cleanup();
  }
});

test("a data directory is bound to its key and origin", async () => {
  const { dir, cleanup } = tempDir();
  try {
    await populate(dir);
    const key = loadWitnessKey(join(dir, "witness-key.json"));
    await assert.rejects(Witness.open({ dataDir: dir, origin: "irontrellis-witness/renamed", signer: key.signer, verifierKey: key.verifierKey, logger: silentLogger }), /origin/);
    // Truncating the log to nothing while checkpoints exist: refuse.
    truncateSync(join(dir, "log.jsonl"), 0);
    await assert.rejects(openWitness(dir), /lost acknowledged entries/);
  } finally {
    cleanup();
  }
});

test("start-up takes each leaf's bytes from its canonical log line: byte-identical to encoding the entry", async () => {
  const { pathToFileURL } = await import("node:url");
  const { packageRoot } = await import("./helpers.mjs");
  const logLib = await import(pathToFileURL(join(packageRoot, "dist", "log.js")).href);
  const { dir, cleanup } = tempDir();
  try {
    const populated = await populate(dir);
    const kinds = new Set();
    let lines = 0;
    logLib.scanLines(join(dir, "log.jsonl"), (line) => {
      const record = logLib.parseLogLine(line);
      kinds.add(record.entry.kind);
      assert.deepEqual(Buffer.from(logLib.entryBytesOfLine(line, record)), Buffer.from(t.encodeEntry(record.entry)), `line ${line.lineNumber}`);
      lines += 1;
    });
    assert.equal(lines, populated.state.size);
    assert.ok(["REGISTERED", "HEAD", "ROTATED", "EQUIVOCATION"].every((kind) => kinds.has(kind)), [...kinds].join(","));
    // Escapes and non-ASCII text survive the cut (a REGISTERED genesis carries arbitrary protocol strings).
    const entry = { version: "irontrellis-witness-entry/1", kind: "REGISTERED", historyId: `0x${"ab".repeat(32)}`, receivedAt: 7, genesis: { note: "quote \" backslash \\ tab \t é 𝄞 \u0001", index: ',"index":1}' } };
    for (const index of [0, 9, 1234567]) {
      const text = logLib.encodeLogLine({ index, entry }).slice(0, -1);
      const line = { text, offset: 0, length: text.length + 1, lineNumber: index + 1 };
      assert.deepEqual(Buffer.from(logLib.entryBytesOfLine(line, { index, entry })), Buffer.from(t.encodeEntry(entry)));
    }
  } finally {
    cleanup();
  }
});
