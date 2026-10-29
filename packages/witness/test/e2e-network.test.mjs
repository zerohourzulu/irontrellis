// End to end against the REAL witness server process (WITNESS-DESIGN §6 e2e (7); scenarios 9 and 11): split view by a
// second server instance holding the SAME witness key with another log (a switching proxy), an attacker-controlled
// network that tampers with receipts, strips signatures, replays old answers (B1 of the review: refused, the latest notes
// are signed over the client's nonce) or returns another history's latest, and receipts from the real server checked by
// the Python verifier (`python -m irontrellis verify-receipt`).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import {
  checkLog, checkpointOf, cliFor, core, diskHead, freshProcess, historyIdOf, historyLog, http, ownerOn, PYTHON_SRC, restoreFiles, scratch, snapshotFiles, startProxy,
  startWitnessServer, t as transparency, witnessHistory, witnessLatest,
} from "./e2e-harness.mjs";
const { FORMAT1_TEST_TOOLING } = await import("@ramex-labs/irontrellis/internal-format1"); // A-185.3 / A-194: older formats are test tooling

/** A throwaway history registered (and stated once) at `server` directly, to grow its log. */
async function growLog(space, server, name, writes = 1) {
  const file = space.path(`${name}.jsonl`);
  const owner = await core.createLocalOwner({ historyFile: file, domain: core.createLocalDomain({ format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, owner: "o", controller: "o", now: () => Date.now(),
    witness: { witnesses: [{ url: server.url, verifierKey: server.verifierKey, token: server.token }], mode: "sync" } });
  for (let k = 0; k < writes; k += 1) await owner.createAgent({ id: `agent:${k}` });
  owner.close?.();
  return file;
}

const splitViewRecorded = (history) => Object.values(core.readWitnessState(`${history}.witness.json`).witnesses).find((entry) => entry.splitView !== undefined);

test("(7) split view: a second server with the SAME witness key and another log, behind the same URL: detected (WITNESS_SPLIT_VIEW), sticky, recorded in the side file", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const a = await startWitnessServer(space, { name: "split.witness", sub: "instance-a" });
    const b = await startWitnessServer(space, { name: "split.witness", sub: "instance-b", keyFrom: a.dataDir, config: { registration: "open" } });
    assert.equal(b.verifierKey, a.verifierKey, "one witness key, two logs");
    const proxy = await startProxy(space, a);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", a.verifierKey, "--token", a.token, "--mode", "sync"]);
    const id = historyIdOf(history);
    freshProcess();
    const owner = ownerOn(history);
    await owner.createAgent({ id: "agent:1" });
    // Instance B's log is longer than what the client saw from A (other histories), so its checkpoints are larger.
    const seen = await checkpointOf(a);
    await growLog(space, b, "b-1", 6);
    await growLog(space, b, "b-2", 6);
    assert.ok((await checkpointOf(b)).size > seen.size);

    proxy.target = b;
    const sizeB = (await checkpointOf(b)).size;
    // The live owner process: its next write asks the witness, which cannot prove B's tree extends the one it saw from A.
    await assert.rejects(owner.createAgent({ id: "agent:2" }), (e) => e.code === "WITNESS_SPLIT_VIEW");
    assert.throws(() => owner.capacity(), (e) => e.code === "WITNESS_SPLIT_VIEW", "sticky: reads refuse too");
    await assert.rejects(owner.createAgent({ id: "agent:3" }), (e) => e.code === "WITNESS_SPLIT_VIEW");
    owner.close?.();
    const recorded = splitViewRecorded(history);
    assert.ok(recorded !== undefined, "recorded in the side file");
    assert.match(recorded.splitView.message, /split view/);
    // Later processes refuse on the record, whichever instance answers.
    const cliWrite = await cli(["agent", "create", "agent:cli"], { json: true });
    assert.equal(cliWrite.code, 1);
    assert.equal(cliWrite.json.error.code, "WITNESS_SPLIT_VIEW");
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 1);
    assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_SPLIT_VIEW")), verdict.stdout);
    proxy.target = a;
    const back = await cli(["verify"], { json: true });
    assert.equal(back.code, 1, "still refused on the record");
    assert.ok(back.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_SPLIT_VIEW")));
    // B's first signed answer (its checkpoint, asked before believing its unsigned "not registered") exposed its log:
    // B got neither the registration nor a head statement.
    assert.equal((await checkpointOf(b)).size, sizeB);
    assert.deepEqual((await historyLog(b, id)), []);

    // A fresh verifier (no side file, only the history's binding) that remembers nothing cannot tell: each log is
    // self-consistent. Split view detection needs a remembered checkpoint (the side file, or a process that saw A).
    const clean = space.path("clean.jsonl");
    restoreFiles(clean, { ...snapshotFiles(history), ".witness.json": undefined });
    const fresh = await core.verifyHistoryWithWitnesses(clean);
    assert.equal(fresh.remoteWitnessStatus, "OK", fresh.failures.join("\n"));
    for (const server of [a, b]) assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("(7) split view by a SMALLER log under the same key (a witness rolled back to an older backup, or a fresh instance): detected as WITNESS_SPLIT_VIEW, never as mere unavailability", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const a = await startWitnessServer(space, { name: "split-small.witness", sub: "instance-a" });
    const b = await startWitnessServer(space, { name: "split-small.witness", sub: "instance-b", keyFrom: a.dataDir, config: { registration: "open" } });
    const proxy = await startProxy(space, a);
    await growLog(space, a, "a-1", 6); // A's log is larger than B's will be
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", a.verifierKey, "--token", a.token, "--mode", "sync"]);
    await cli.ok(["agent", "create", "agent:1"]);
    await growLog(space, b, "b-1", 1);
    assert.ok((await checkpointOf(b)).size < (await checkpointOf(a)).size);
    proxy.target = b;
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 1, verdict.stdout);
    assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_SPLIT_VIEW")), verdict.stdout);
    const allowed = await cli(["verify", "--allow-unreachable-witness"], { json: true });
    assert.equal(allowed.code, 1, "a split view is not an unreachable witness: --allow-unreachable-witness does not accept it");
    const write = await cli(["agent", "create", "agent:2"], { json: true });
    assert.equal(write.code, 1, write.stdout);
    assert.equal(write.json.error.code, "WITNESS_SPLIT_VIEW");
    assert.ok(splitViewRecorded(history) !== undefined);
  } finally {
    await space.cleanup();
  }
});

// ---------------------------------------------------------------- (9) the attacker-controlled network

const flip = (b64) => `${b64[0] === "A" ? "B" : "A"}${b64.slice(1)}`;
const rewriteJson = (response, change) => {
  let body;
  try { body = JSON.parse(response.body); } catch { return undefined; }
  const changed = change(body);
  return changed === undefined ? undefined : { body: JSON.stringify(changed) };
};
/** Every receipt in a JSON body, rewritten by `change`. */
const mapReceipts = (value, change) => {
  if (value === null || typeof value !== "object") return value;
  if (value.version === "irontrellis-witness-receipt/1") return change(value);
  if (Array.isArray(value)) return value.map((item) => mapReceipts(item, change));
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, mapReceipts(item, change)]));
};
const stripSignatures = (note) => note.split("\n").filter((line) => !line.startsWith("— ")).join("\n");

test("(9) attacker-controlled network: tampered receipts, stripped signatures, another history's latest, a replayed old answer — never counted as witnessed, never a false OK", { timeout: 180_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "mitm.witness" });
    const proxy = await startProxy(space, server);
    const other = await growLog(space, server, "other", 2);
    const otherId = historyIdOf(other);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"]);
    const id = historyIdOf(history);
    freshProcess();
    const owner = ownerOn(history);
    await owner.createAgent({ id: "agent:0" });
    assert.equal(owner.witnessStatus().unwitnessedEvents, 0);

    const attacks = {
      "tampered inclusion proof": (request, response) => rewriteJson(response, (body) => mapReceipts(body, (receipt) => ({ ...receipt, inclusionProof: receipt.inclusionProof.length === 0 ? ["AAAA"] : [flip(receipt.inclusionProof[0]), ...receipt.inclusionProof.slice(1)] }))),
      "tampered entry": (request, response) => rewriteJson(response, (body) => mapReceipts(body, (receipt) => ({ ...receipt, entry: { ...receipt.entry, receivedAt: receipt.entry.receivedAt + 1 } }))),
      "stripped checkpoint signatures": (request, response) => (request.path === "/v1/checkpoint" ? { body: stripSignatures(response.body) }
        : rewriteJson(response, (body) => mapReceipts({ ...body, ...(typeof body.checkpoint === "string" ? { checkpoint: stripSignatures(body.checkpoint) } : {}) }, (receipt) => ({ ...receipt, checkpoint: stripSignatures(receipt.checkpoint) })))),
      "another history's latest": async (request, response) => {
        if (request.method === "GET" && request.path === `/v1/histories/${id}`) {
          const theirs = await http(server.url, "GET", `/v1/histories/${otherId}`);
          return { body: JSON.stringify({ ...JSON.parse(response.body), latest: theirs.json.latest, checkpoint: theirs.json.checkpoint }) };
        }
        if (request.method === "POST" && request.path.endsWith("/heads")) {
          const theirs = await http(server.url, "GET", `/v1/histories/${otherId}`);
          return rewriteJson(response, (body) => ({ ...body, receipt: theirs.json.latest.receipt, latest: theirs.json.latest, checkpoint: theirs.json.checkpoint }));
        }
        return undefined;
      },
    };
    let k = 0;
    for (const [name, transform] of Object.entries(attacks)) {
      proxy.transform = transform;
      const written = await owner.createAgent({ id: `agent:attack:${(k += 1)}` });
      // The real witness may well hold the head (the statement reached it) — but the client does not count it.
      const status = owner.witnessStatus();
      assert.ok(status.unwitnessedEvents >= 1, `${name}: not counted as witnessed`);
      assert.equal(status.witnesses[0].lastError?.code, "WITNESS_INVALID_RESPONSE", `${name}: ${JSON.stringify(status.witnesses[0].lastError)}`);
      assert.equal(status.alarm, undefined, `${name}: a forged answer is not evidence of anything`);
      await assert.rejects(owner.flush(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.cause === "WITNESS_INVALID_RESPONSE", name);
      const verdict = await cli(["verify"], { json: true });
      assert.equal(verdict.code, 1, `${name}: verify must not pass: ${verdict.stdout}`);
      assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_INVALID")), `${name}: ${verdict.stdout}`);
      const synced = await cli(["witness", "sync"], { json: true });
      assert.equal(synced.code, 1, `${name}: sync reports failure`);
      proxy.transform = undefined;
      await owner.flush();
      assert.equal(owner.witnessStatus().unwitnessedEvents, 0, `${name}: counted once the answer verifies`);
      assert.deepEqual(await witnessLatest(server, id), written.head);
    }

    // A replayed earlier POST answer (a genuine receipt, but for an earlier head) is not the receipt of this statement.
    let lastHeadAnswer;
    proxy.transform = (request, response) => {
      if (request.method !== "POST" || !request.path.endsWith("/heads")) return undefined;
      if (lastHeadAnswer === undefined) { lastHeadAnswer = response; return undefined; }
      return { status: lastHeadAnswer.status, body: lastHeadAnswer.body };
    };
    await owner.createAgent({ id: "agent:record-answer" });
    await owner.createAgent({ id: "agent:replayed-answer" });
    assert.equal(owner.witnessStatus().witnesses[0].lastError?.code, "WITNESS_INVALID_RESPONSE");
    assert.ok(owner.witnessStatus().unwitnessedEvents >= 1);
    proxy.transform = undefined;
    await owner.flush();
    assert.equal(owner.witnessStatus().unwitnessedEvents, 0);
    owner.close?.();
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("B1 (review), real server: a network attacker (plain http over loopback) who also rolls back the host files replays the witness's genuine older answers: the signed latest note answers another nonce, so verify fails REMOTE_WITNESS_INVALID, the requireOnOpen gate stays closed, the owner write is refused and the witness receives nothing; plain http to a non-loopback host is refused unless allowInsecureHttp", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "replay.witness" });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    // Plain http to anything but loopback is refused before anything is asked or written; --allow-insecure-http accepts it.
    const plain = await cli(["witness", "add", "http://witness.example.invalid:8411", "--verifier-key", server.verifierKey], { json: true });
    assert.equal(plain.code, 1, plain.stdout);
    assert.equal(plain.json.error.code, "INVALID_INPUT");
    assert.match(plain.stdout, /plain http is refused/);
    assert.throws(() => core.normalizeWitnessConfig({ url: "http://10.0.0.5:8411", verifierKey: server.verifierKey }), (e) => e.code === "INVALID_INPUT" && e.detail.reason === "INSECURE_HTTP");
    for (const url of ["https://witness.example.org", "http://localhost:8411", "http://127.3.4.5:1", "http://[::1]:8411"]) assert.equal(core.normalizeWitnessConfig({ url, verifierKey: server.verifierKey }).url.startsWith("http"), true, url);
    assert.equal(core.normalizeWitnessConfig({ url: "http://10.0.0.5:8411", verifierKey: server.verifierKey, allowInsecureHttp: true }).allowInsecureHttp, true);
    const insecure = await cli(["witness", "add", "http://witness.example.invalid:8411", "--verifier-key", server.verifierKey, "--allow-insecure-http", "--timeout-ms", "200"], { json: true });
    assert.equal(insecure.json.error.code, "WITNESS_UNAVAILABLE", "accepted as a URL, then simply unreachable");
    // The attack over loopback, where the proxy is the network path to the bound witness.
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync", "--require-on-open", "--cache-ms", "0"]);
    await cli.ok(["agent", "create", "agent:1"]);
    const id = historyIdOf(history);
    // The attacker records the witness's answers about the old state, and keeps the old files.
    const recorded = new Map();
    proxy.transform = (request, response) => { if (request.method === "GET") recorded.set(request.path, response); return undefined; };
    await cli.ok(["verify"]);
    proxy.transform = undefined;
    assert.ok(recorded.has(`/v1/histories/${id}`));
    const old = snapshotFiles(history);
    const oldHead = diskHead(history);
    for (const agent of ["agent:2", "agent:3"]) await cli.ok(["agent", "create", agent]);
    const witnessed = await witnessLatest(server, id);
    restoreFiles(history, old);
    // Without replay, verify catches it.
    const caught = await cli(["verify"], { json: true });
    assert.equal(caught.code, 1);
    assert.ok(caught.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK")), caught.stdout);
    // With the history answers replayed from the recording (signatures and proofs genuine, just old) and writes dropped.
    restoreFiles(history, old);
    proxy.before = (request) => {
      if (request.method === "POST") return { status: 503, body: { error: { code: "INTERNAL", message: "dropped" } } };
      const answer = request.method === "GET" && request.path === `/v1/histories/${id}` ? recorded.get(request.path) : undefined;
      return answer === undefined ? undefined : { status: answer.status, body: answer.body, headers: answer.headers };
    };
    const size = (await checkpointOf(server)).size;
    const fooled = await cli(["verify"], { json: true });
    assert.equal(fooled.code, 1, `a replayed old answer must not pass: ${fooled.stdout}`);
    assert.ok(fooled.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_INVALID") && /latest note/.test(f) && /NONCE_MISMATCH/.test(f)), fooled.stdout);
    assert.equal((await cli(["verify", "--allow-unreachable-witness"], { json: true })).code, 1, "an invalid answer is not unreachability");
    // requireOnOpen readers stay closed.
    freshProcess();
    const reader = core.openHistoryStore(history);
    await assert.rejects(reader.checkWitnesses(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.cause === "WITNESS_INVALID_RESPONSE");
    assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED");
    reader.close();
    // The writers are refused and append nothing: the library owner and the CLI.
    freshProcess();
    const owner = ownerOn(history);
    await assert.rejects(owner.createAgent({ id: "agent:on-old-copy" }), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "INVALID_ANSWER");
    owner.close?.();
    const write = await cli(["agent", "create", "agent:cli-on-old-copy"], { json: true });
    assert.equal(write.code, 1, write.stdout);
    assert.equal(write.json.error.code, "WITNESS_UNAVAILABLE");
    assert.equal(write.json.error.context.reason, "INVALID_ANSWER", write.stdout);
    assert.deepEqual(diskHead(history), oldHead, "nothing was appended to the restored copy");
    proxy.before = undefined;
    assert.deepEqual(await witnessLatest(server, id), witnessed, "the witness chain is untouched");
    assert.equal((await checkpointOf(server)).size, size, "nothing reached the witness");
    const evidence = await witnessHistory(server, id);
    assert.equal(evidence.equivocations, 0, "no false alarm either");
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

// python.org and actions/setup-python install no python3 on Windows (conformance/run.mjs makes the same choice).
const PYTHON = process.env.IRONTRELLIS_PYTHON || (process.platform === "win32" ? "python" : "python3");
test("(11) Python: a receipt from the real server verifies with `python -m irontrellis verify-receipt`; tampered, it is INVALID", { timeout: 60_000 }, async (t) => {
  const probe = spawnSync(PYTHON, ["-c", "import sys; sys.path.insert(0, sys.argv[1]); import irontrellis.transparency", PYTHON_SRC], { encoding: "utf8" });
  if (probe.error !== undefined || probe.status !== 0) {
    t.skip(`${PYTHON} with the irontrellis package is not available (${probe.error?.message ?? probe.stderr.trim().split("\n").at(-1)})`);
    return;
  }
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "python.witness" });
    // The Python package is frozen at format 1 (python/README.md): its receipt verifier reads `irontrellis/1` statement
    // domains only, so this case witnesses a format-1 history, written through the core's test-only format-1 writer.
    const history = space.path("history.jsonl");
    const owner = await core.createLocalOwner({ historyFile: history, domain: core.createLocalDomain({ format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, owner: "ops", controller: "ops", now: () => Date.now(),
      witness: { witnesses: [{ url: server.url, verifierKey: server.verifierKey, token: server.token }], mode: "sync" } });
    await owner.createAgent({ id: "agent:1" });
    await owner.rotateOwnerKey({ reason: "python" });
    await owner.createAgent({ id: "agent:2" });
    await owner.flush();
    owner.close();
    const id = historyIdOf(history);
    const impostor = transparency.generateNoteKey("python.witness").verifierKey;
    const python = (file, ...keys) => {
      const result = spawnSync(PYTHON, ["-m", "irontrellis", "verify-receipt", file, ...keys.flatMap((key) => ["--verifier-key", key])], { encoding: "utf8", env: { ...process.env, PYTHONPATH: PYTHON_SRC } });
      return { code: result.status, json: JSON.parse(result.stdout), stderr: result.stderr };
    };
    const summary = (await http(server.url, "GET", `/v1/histories/${id}`)).json;
    const receipts = { latest: summary.latest.receipt };
    const entries = (await http(server.url, "GET", "/v1/entries?start=0&end=1000")).json.entries;
    const rotatedIndex = entries.findIndex((entry) => entry.kind === "ROTATED" && entry.historyId === id);
    const registeredIndex = entries.findIndex((entry) => entry.kind === "REGISTERED" && entry.historyId === id);
    // Receipts for the ROTATED and REGISTERED leaves, built from the server's own proofs and checkpoint.
    const note = (await http(server.url, "GET", "/v1/checkpoint")).text;
    for (const [kind, index] of [["rotated", rotatedIndex], ["registered", registeredIndex]]) {
      const checkpointSize = entries.length;
      const proof = (await http(server.url, "GET", `/v1/proofs/inclusion?index=${index}&size=${checkpointSize}`)).json.proof;
      receipts[kind] = { version: "irontrellis-witness-receipt/1", witness: { origin: server.origin, verifierKey: server.verifierKey }, entry: entries[index], index, checkpoint: note, inclusionProof: proof };
    }
    for (const [kind, receipt] of Object.entries(receipts)) {
      const file = space.path(`${kind}.json`);
      writeFileSync(file, JSON.stringify(receipt));
      const valid = python(file, server.verifierKey);
      assert.equal(valid.code, 0, `${kind}: ${JSON.stringify(valid.json)} ${valid.stderr}`);
      assert.equal(valid.json.status, "VALID");
      assert.equal(valid.json.index, receipt.index);
      assert.equal(valid.json.entry.kind, receipt.entry.kind);
      // The whole witness response is accepted too.
      if (kind === "latest") {
        const responseFile = space.path("response.json");
        writeFileSync(responseFile, JSON.stringify(summary));
        assert.equal(python(responseFile, server.verifierKey).json.status, "VALID");
      }
      for (const [how, tampered] of [
        ["entry", { ...receipt, entry: { ...receipt.entry, receivedAt: receipt.entry.receivedAt + 1 } }],
        ["proof", { ...receipt, inclusionProof: receipt.inclusionProof.length === 0 ? ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="] : [flip(receipt.inclusionProof[0]), ...receipt.inclusionProof.slice(1)] }],
        ["index", { ...receipt, index: receipt.index === 0 ? 1 : receipt.index - 1 }],
        ["signature", { ...receipt, checkpoint: stripSignatures(receipt.checkpoint) }],
      ]) {
        const bad = space.path(`${kind}-${how}.json`);
        writeFileSync(bad, JSON.stringify(tampered));
        const invalid = python(bad, server.verifierKey);
        assert.equal(invalid.code, 1, `${kind}/${how}: ${JSON.stringify(invalid.json)}`);
        assert.equal(invalid.json.status, "INVALID", `${kind}/${how}`);
      }
      assert.equal(python(file, impostor).json.status, "INVALID", `${kind}: another key with the same name`);
    }
  } finally {
    await space.cleanup();
  }
});

test("(9) an unauthenticated 404 (\"not registered\") from a BOUND witness contradicts the REGISTERED receipt the binding carries: verify fails REMOTE_WITNESS_INVALID, the requireOnOpen gate stays closed, writers refuse and sign nothing; a policy-only witness's 404 stays a note", { timeout: 60_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "notfound.witness" });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const cli = cliFor(history);
    await cli.ok(["init", "--owner", "ops"]);
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync", "--require-on-open", "--cache-ms", "0"]);
    await cli.ok(["agent", "create", "agent:1"]);
    // The binding carries the witness's own signed REGISTERED receipt for this history.
    const id = historyIdOf(history);
    const binding = core.openHistoryStore(history, { inspect: true, witness: false }).state();
    assert.ok(core.boundRegistrationOf(binding, server.verifierKey) !== undefined, "the binding holds a verifiable REGISTERED receipt");
    const old = snapshotFiles(history);
    for (const agent of ["agent:2", "agent:3"]) await cli.ok(["agent", "create", agent]);
    const witnessed = await witnessLatest(server, id);
    restoreFiles(history, old);
    const restoredHead = diskHead(history);
    const logFrom = proxy.log.length;
    proxy.before = (request) => (request.method === "GET" && request.path === `/v1/histories/${id}` ? { status: 404, body: { error: { code: "NOT_REGISTERED", message: "unknown history" } } } : undefined);
    const size = (await checkpointOf(server)).size;
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 1, verdict.stdout);
    assert.ok(verdict.json.failures.some((f) => f.startsWith("REMOTE_WITNESS_INVALID") && /denies a registration it signed/.test(f) && /lost data|attacker in the path/.test(f)), verdict.stdout);
    const allowed = await cli(["verify", "--allow-unreachable-witness"], { json: true });
    assert.equal(allowed.code, 1, "a denial is not unreachability");
    freshProcess();
    const reader = core.openHistoryStore(history);
    await assert.rejects(reader.checkWitnesses(), (e) => e.code === "WITNESS_INVALID_RESPONSE" && e.detail.reason === "REGISTRATION_DENIED");
    assert.throws(() => reader.state(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "NOT_CHECKED", "the requireOnOpen gate stays closed");
    reader.close();
    // The writer does not re-register (that would hide the loss) and signs nothing for this copy.
    const write = await cli(["agent", "create", "agent:on-old-copy"], { json: true });
    assert.equal(write.code, 1, write.stdout);
    assert.equal(write.json.error.context.reason, "REGISTRATION_DENIED", write.stdout);
    assert.deepEqual(diskHead(history), restoredHead, "nothing was appended to the restored copy");
    const status = await cli(["witness", "status"], { json: true });
    assert.equal(status.code, 1, "witness status reports it");
    assert.equal(status.json.remote[0].registrationDenied, true);
    assert.deepEqual(await witnessLatest(server, id), witnessed, "the witness chain is untouched");
    assert.equal((await checkpointOf(server)).size, size, "nothing was registered again or submitted");
    assert.ok(!proxy.log.slice(logFrom).some((line) => line === "POST /v1/histories"), "never re-registered");
    // A witness the history does not bind (configured out of band, never registered): its 404 is still only a note.
    proxy.before = undefined;
    const fresh = space.path("fresh.jsonl");
    await cliFor(fresh).ok(["init", "--owner", "ops"]);
    const policyOnly = await core.verifyHistoryWithWitnesses(fresh, { witness: { witnesses: [{ url: server.url, verifierKey: server.verifierKey }] } });
    assert.equal(policyOnly.ok, true, policyOnly.failures.join("\n"));
    assert.ok(policyOnly.notes.some((n) => n.startsWith("REMOTE_WITNESS_UNREGISTERED") && /configured, not bound/.test(n)), policyOnly.notes.join("\n"));
  } finally {
    await space.cleanup();
  }
});
