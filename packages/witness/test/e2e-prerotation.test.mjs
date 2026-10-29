// End to end against the REAL witness server process: review finding M2 closed (WITNESS-DESIGN §11.2–§11.4). A witness
// that has not recorded an owner key rotation accepts statements signed by the retired key; with pre-rotation the
// owner's rotation overrides whatever a thief of that key pushed there (supersede), the default rotation never leaves a
// bound witness unaware (two phases), and a witness cut off from the network takes the rotation as a bundle.
//  (a) the M2 attack: leaked old key + a witness down during an emergency rotation; the thief's head at the witness is
//      superseded by the owner's delivery; verify passes on the owner's copy with the SUPERSEDED note and fails on the
//      thief's forged copy; check-log passes;
//  (b) the same with the thief's head at a position ≤ r;
//  (c) the thief with only the current key tries to rotate or re-commit: the local replay and the witness reject it;
//  (d) the thief tries to supersede without the next key: rejected;
//  (e) two-phase with 2 witnesses, one down: abort by default, nothing written; --emergency works;
//  (f) a crash between the witness's acceptance and the local append: recovered by the next command;
//  (g) the bundle path: the witness is cut off, its operator imports the bundle offline (and over the admin route);
//  (h) a retired-key statement for a new head after a rotation is SIGNATURE_INVALID;
//  (i) the review's PoC (poc4-retired-key) replayed: the new outcome;
//  (j) third review F1: the thief floods the witness with more heads than any per-supersede cap (1,100 chained heads);
//      the owner's supersede still succeeds (the SUPERSEDED entry describes a range, its size does not grow).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { copyFileSync, existsSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  checkLog, CLI_BIN, cliFor, core, diskHead, diskState, freshProcess, historyIdOf, historyLog, http, rollbackWith, scratch, startProxy, startWitnessServer, t, witnessHistory, witnessLatest,
} from "./e2e-harness.mjs";
const { FORMAT1_TEST_TOOLING } = await import("@ramex-labs/irontrellis/internal-format1"); // A-185.3 / A-194: older formats are test tooling

const COPY_SUFFIXES = ["", ".head", ".anchors", ".witness.json", ".owner-key.json"];

/** A history created by the CLI and bound to `url` (sync), with a committed next key (the `init` default) and two agents. */
async function ownerHistory(space, server, url, name = "history.jsonl") {
  const history = space.path(name);
  const cli = cliFor(history);
  // A-39.3 made requireOnOpen the init default; these scenarios read with the witness cut off, so they turn it off.
  await cli.ok(["init", "--owner", "ops", "--witness", url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync", "--no-require-on-open"]);
  for (const agent of ["agent:1", "agent:2"]) await cli.ok(["agent", "create", agent]);
  return { history, cli, id: historyIdOf(history) };
}

/** What a thief who copied the agent host's files (the current owner key, NOT the offline next key) can do. */
function thiefOf(space, history) {
  const copy = space.path("thief.jsonl");
  for (const suffix of COPY_SUFFIXES) if (existsSync(history + suffix)) copyFileSync(history + suffix, copy + suffix);
  const key = core.loadOwnerKeyFile(`${copy}.owner-key.json`);
  const state = diskState(copy);
  const owner = () => core.openLocalOwner({ historyFile: copy, domain: state.genesis.domain, owner: "ops", controller: "ops", now: () => Date.now(), witness: false, format: state.format, [FORMAT1_TEST_TOOLING]: true });
  return { copy, key, owner, domain: state.genesis.domain };
}

/** The thief extends its copy with `events` agents signed by the stolen key and pushes the head to the witness (previous = its latest). */
async function inject(thief, server, id, events) {
  const owner = thief.owner();
  for (let n = 0; n < events; n += 1) await owner.createAgent({ id: `agent:thief:${n}` });
  owner.close();
  const head = diskHead(thief.copy);
  const latest = await witnessLatest(server, id);
  const statement = await t.signHeadStatement(thief.key, { version: t.HEAD_STATEMENT_VERSION, historyId: id, domain: thief.domain, head, previous: { hash: latest.hash, position: latest.position } });
  const reply = await http(server.url, "POST", `/v1/histories/${id}/heads`, statement);
  return { head, statement, reply };
}

async function m2Attack({ thiefEvents, label }) {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: `m2-${label}.witness` });
    const proxy = await startProxy(space, server);
    const { history, cli, id } = await ownerHistory(space, server, proxy.url);
    const L = await witnessLatest(server, id);
    assert.deepEqual(L, diskHead(history));
    // The agent host is compromised: the thief copies the history and the CURRENT owner key (the next key is offline).
    const nextKey = space.path("offline-next-key.json");
    copyFileSync(`${history}.owner-next-key.json`, nextKey);
    const thief = thiefOf(space, history);
    // The owner rotates at once, but the witness is down: the default two-phase rotation refuses, --emergency proceeds.
    proxy.down = true;
    const refused = await cli(["owner", "rotate-key", "--reason", "leaked owner key"], { json: true });
    assert.equal(refused.code, 1);
    assert.match(refused.json.error.message, /rotation needs every bound witness; retry, or rotate with --emergency/);
    const rotated = await cli(["owner", "rotate-key", "--reason", "leaked owner key", "--emergency", "--next-key", nextKey], { json: true });
    assert.equal(rotated.code, 0, rotated.stdout + rotated.stderr);
    assert.equal(rotated.json.preRotated, true);
    assert.equal(rotated.json.rotationIncomplete, true);
    const r = rotated.json.head.position;
    assert.equal(r, L.position + 1);
    // Meanwhile the thief pushes a head signed with the retired key onto the witness (it has not recorded the rotation: M2).
    const forged = await inject(thief, server, id, thiefEvents);
    assert.equal(forged.reply.status, 201, forged.reply.text);
    if (thiefEvents === 1) assert.equal(forged.head.position, r, "(b): the thief's head sits at the rotation's own position");
    else assert.ok(forged.head.position > r);
    assert.deepEqual(await witnessLatest(server, id), forged.head);
    // The witness is back: the owner's next delivery supersedes the thief's chain from the last good head L.
    proxy.down = false;
    const synced = await cli(["witness", "sync"], { json: true });
    assert.equal(synced.code, 0, synced.stdout + synced.stderr);
    const log = await historyLog(server, id);
    const at = log.indexOf("SUPERSEDED");
    assert.ok(at > 0, log.join(" | "));
    const newKeyId = core.loadOwnerKeyFile(`${history}.owner-key.json`).keyId;
    assert.deepEqual(log.slice(at, at + 3), ["SUPERSEDED", `HEAD ${r} ${thief.key.keyId}`, `ROTATED ${r - 1}->${r}`]);
    await cli.ok(["agent", "create", "agent:after"]);
    assert.equal((await historyLog(server, id)).at(-1), `HEAD ${r + 1} ${newKeyId}`);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    const info = await witnessHistory(server, id);
    assert.equal(info.supersedes, 1);
    assert.equal(info.lastSupersede.entry.chain.statement.previous.position, L.position, "the chain resumes from L");
    assert.deepEqual([info.lastSupersede.entry.supersededLatest.position, info.lastSupersede.entry.supersededCount], [forged.head.position, 1]);
    // verify on the owner's copy passes, with the note and the warning.
    const verdict = await cli(["verify"], { json: true });
    assert.equal(verdict.code, 0, verdict.stdout);
    assert.ok(verdict.json.notes.some((note) => note.startsWith("REMOTE_WITNESS_SUPERSEDED 1")), verdict.stdout);
    assert.ok(verdict.json.warnings.some((warning) => warning.code === "REMOTE_WITNESS_SUPERSEDED"), verdict.stdout);
    const human = await cli(["verify"]);
    assert.match(human.stdout, /REMOTE_WITNESS_SUPERSEDED 1/);
    assert.match(human.stdout, /the old key was probably compromised/);
    const status = await cli(["witness", "status"]);
    assert.match(status.stdout, /supersedes\s+REMOTE_WITNESS_SUPERSEDED 1/);
    // verify on the thief's forged copy fails: the witness's latest is not a prefix of it.
    const forgedVerdict = await cliFor(thief.copy)(["verify"], { json: true });
    assert.equal(forgedVerdict.code, 1, forgedVerdict.stdout);
    assert.ok(forgedVerdict.json.failures.some((failure) => failure.startsWith("REMOTE_WITNESS_ROLLBACK")), forgedVerdict.stdout);
    // The thief's statement is refused from now on: SUPERSEDED where the old key still counts (≤ r), SIGNATURE_INVALID past r.
    const again = await http(server.url, "POST", `/v1/histories/${id}/heads`, forged.statement);
    assert.equal(again.json.error.code, forged.head.position <= r ? "SUPERSEDED" : "SIGNATURE_INVALID", again.text);
    const audit = checkLog(server.dataDir);
    assert.equal(audit.status, "VALID", JSON.stringify(audit.problems));
    assert.equal(audit.kinds.SUPERSEDED, 1);
    return { server, history, id, thief, r };
  } finally {
    await space.cleanup();
  }
}

test("(a) M2: a leaked old key's head at a witness that missed the emergency rotation is superseded by the owner's pre-rotated rotation", { timeout: 180_000 }, async () => {
  await m2Attack({ thiefEvents: 3, label: "a" });
});

test("(b) M2 with the thief's head at a position ≤ r: superseded as well", { timeout: 180_000 }, async () => {
  await m2Attack({ thiefEvents: 1, label: "b" });
});

test("(c) a thief with only the current key cannot rotate or re-commit: the local replay and the witness both reject it", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "thief-rotate.witness" });
    const { history, id } = await ownerHistory(space, server, server.url);
    const thief = thiefOf(space, history);
    const state = diskState(history);
    const head = state.head;
    const thiefKey = core.keyPairFromPrivateKey("ed25519", "owner:thief", `0x${"66".repeat(32)}`);
    const thiefOwnerKey = { keyId: thiefKey.keyId, scheme: thiefKey.scheme, credential: thiefKey.credential };
    const rotation = await core.signControlEvent(thief.key, { id: "event:thief-rotation", type: "OWNER_KEYS_ROTATED", timestamp: Date.now(), data: { ownerKeys: [thiefOwnerKey] } }, thief.domain, head, "sha256");
    // Re-committing: a commitment-only rotation (the current keys kept) to the thief's own key.
    const recommit = await core.signControlEvent(thief.key, {
      id: "event:thief-commit", type: "OWNER_KEYS_ROTATED", timestamp: Date.now(), data: { ownerKeys: state.ownerKeyEpochs.at(-1).keys.map((k) => ({ ...k })), nextKeyDigests: [core.ownerKeyDigest(thiefOwnerKey)] },
    }, thief.domain, head, "sha256");
    // Local replay: a rotation out of a committed epoch must reveal a committed key, so the commitment cannot be replaced either.
    for (const [event, reason] of [[rotation, /pre-rotation|committed to/], [recommit, /committed to next keys; the rotation must reveal/]]) {
      const store = core.openHistoryStore(thief.copy, { witness: false, readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true }); // the format-1 writer by name (the fence would answer FORMAT_READ_ONLY first)
      assert.throws(() => store.append(event), (error) => error.code === "TRANSITION_INVALID" && reason.test(error.message), event.type);
      store.close();
    }
    // The owner API refuses the rotation without the next key (the thief does not have it).
    const owner = thief.owner();
    const nextKey = `${thief.copy}.owner-next-key.json`;
    assert.equal(existsSync(nextKey), false, "the next key is not on the host");
    await assert.rejects(owner.rotateOwnerKey({ emergency: true }), (error) => error.code === "KEY_UNAVAILABLE");
    owner.close();
    // The witness (which learned the commitment from the genesis it registered) runs the same rules.
    const info = await witnessHistory(server, id);
    assert.equal(info.epochs[0].nextKeyDigests.length, 1, "the witness knows the commitment");
    const hasher = new core.HistoryHasher("irontrellis-event/1");
    for (const event of state.events) hasher.push(event);
    for (const event of [rotation, recommit]) {
      const eventHead = { hash: hasher.clone().push(event), position: head.position + 1, canonicalTime: event.timestamp };
      const statement = await t.signHeadStatement(thief.key, { version: t.HEAD_STATEMENT_VERSION, historyId: id, domain: thief.domain, head: eventHead, previous: { hash: head.hash, position: head.position } });
      const reply = await http(server.url, "POST", `/v1/histories/${id}/key-events`, { event, previousHead: { hash: head.hash, position: head.position }, eventHead: { hash: eventHead.hash, position: eventHead.position }, statement });
      assert.equal(reply.status, 400, reply.text);
      assert.equal(reply.json.error.code, "KEY_EVENT_INVALID");
    }
    assert.deepEqual(await witnessLatest(server, id), head, "nothing appended");
    // After the thief got its head statement for the rotation's position accepted (M2): the witness still refuses the
    // rotation, because it knows the commitment (from the genesis it registered).
    const rotationHead = { hash: hasher.clone().push(rotation), position: head.position + 1, canonicalTime: rotation.timestamp };
    const headStatement = await t.signHeadStatement(thief.key, { version: t.HEAD_STATEMENT_VERSION, historyId: id, domain: thief.domain, head: rotationHead, previous: { hash: head.hash, position: head.position } });
    assert.equal((await http(server.url, "POST", `/v1/histories/${id}/heads`, headStatement)).status, 201);
    const bound = await http(server.url, "POST", `/v1/histories/${id}/key-events`, { event: rotation, previousHead: { hash: head.hash, position: head.position }, eventHead: { hash: rotationHead.hash, position: rotationHead.position } });
    assert.deepEqual([bound.status, bound.json.error.code], [400, "KEY_EVENT_INVALID"], bound.text);
    assert.equal((await witnessHistory(server, id)).epochs.length, 1, "the thief's rotation is not recorded");
  } finally {
    await space.cleanup();
  }
});

test("(d) a thief cannot supersede without the next key: its own rotation and a chain from a head the witness does not hold are refused", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "thief-supersede.witness" });
    const { history, id } = await ownerHistory(space, server, server.url);
    const L = diskHead(history);
    const thief = thiefOf(space, history);
    const forged = await inject(thief, server, id, 2);
    assert.equal(forged.reply.status, 201);
    const thiefKey = core.keyPairFromPrivateKey("ed25519", "owner:thief", `0x${"67".repeat(32)}`);
    const rotation = await core.signControlEvent(thief.key, {
      id: "event:thief-rotation", type: "OWNER_KEYS_ROTATED", timestamp: Date.now(), data: { ownerKeys: [{ keyId: thiefKey.keyId, scheme: thiefKey.scheme, credential: thiefKey.credential }] },
    }, thief.domain, L, "sha256");
    const eventHead = { hash: `0x${"9a".repeat(32)}`, position: L.position + 1, canonicalTime: rotation.timestamp };
    const chain = await t.signHeadStatement(thief.key, { version: t.HEAD_STATEMENT_VERSION, historyId: id, domain: thief.domain, head: eventHead, previous: { hash: L.hash, position: L.position } });
    const body = { event: rotation, previousHead: { hash: L.hash, position: L.position }, eventHead: { hash: eventHead.hash, position: eventHead.position }, chain };
    const refused = await http(server.url, "POST", `/v1/histories/${id}/key-events`, body);
    assert.deepEqual([refused.status, refused.json.error.code], [400, "KEY_EVENT_INVALID"], refused.text);
    // The same through the admin route (a bundle): the token gates the channel, the rules are the same.
    const bundle = { version: "irontrellis-key-event-bundle/1", historyId: id, ...body, statement: chain };
    const admin = await http(server.url, "POST", "/v1/admin/key-events", bundle, { authorization: `Bearer ${server.token}` });
    assert.deepEqual([admin.status, admin.json.error.code], [400, "KEY_EVENT_INVALID"], admin.text);
    const info = await witnessHistory(server, id);
    assert.equal(info.supersedes, 0);
    assert.deepEqual(info.latest.head, forged.head, "the thief's head stays (a detected disagreement) until the owner's pre-rotated rotation");
    // The owner's writers fail closed meanwhile.
    freshProcess();
    const verdict = await cliFor(history)(["agent", "create", "agent:blocked"], { json: true });
    assert.equal(verdict.code, 1);
    assert.equal(verdict.json.error.code, "ROLLBACK_DETECTED");
  } finally {
    await space.cleanup();
  }
});

test("(e) two-phase with 2 bound witnesses, one down: aborted by default with nothing written; --emergency rotates", { timeout: 180_000 }, async () => {
  const space = scratch();
  try {
    const one = await startWitnessServer(space, { name: "two-phase-1.witness" });
    const two = await startWitnessServer(space, { name: "two-phase-2.witness" });
    const proxy = await startProxy(space, two);
    const { history, cli, id } = await ownerHistory(space, one, one.url);
    // quorum 2 of 2: a head counts once both hold it, and a submission round needs one answer (n - q + 1).
    await cli.ok(["witness", "add", proxy.url, "--verifier-key", two.verifierKey, "--token", two.token, "--quorum", "2"]);
    await cli.ok(["witness", "sync"]);
    // Both up: the rotation reaches both before the local append.
    const first = await cli(["owner", "rotate-key", "--reason", "scheduled"], { json: true });
    assert.equal(first.code, 0, first.stdout + first.stderr);
    assert.equal(first.json.witnesses.accepted.length, 2);
    assert.equal(first.json.rotationIncomplete, false);
    for (const server of [one, two]) assert.deepEqual((await historyLog(server, id)).slice(-2).map((line) => line.split(" ")[0]), ["HEAD", "ROTATED"]);
    await cli.ok(["agent", "create", "agent:after-first"]);
    // One down: aborted, nothing written (history, key files, record).
    proxy.down = true;
    const before = { head: diskHead(history), key: readFileSync(`${history}.owner-key.json`), next: readFileSync(`${history}.owner-next-key.json`) };
    const aborted = await cli(["owner", "rotate-key"], { json: true });
    assert.equal(aborted.code, 1);
    assert.equal(aborted.json.error.code, "WITNESS_UNAVAILABLE");
    assert.match(aborted.json.error.message, /rotation needs every bound witness; retry, or rotate with --emergency/);
    assert.deepEqual(diskHead(history), before.head);
    assert.deepEqual(readFileSync(`${history}.owner-key.json`), before.key);
    assert.deepEqual(readFileSync(`${history}.owner-next-key.json`), before.next);
    for (const suffix of [".rotation.pending.json", ".owner-key.pending.json", ".owner-next-key.pending.json"]) assert.equal(existsSync(history + suffix), false, suffix);
    // --emergency: recorded locally, delivered to the reachable witness now and to the other one later.
    const emergency = await cli(["owner", "rotate-key", "--emergency"], { json: true });
    assert.equal(emergency.code, 0, emergency.stdout + emergency.stderr);
    assert.equal(emergency.json.emergency, true);
    assert.equal(emergency.json.rotationIncomplete, true);
    const r = emergency.json.head.position;
    assert.ok((await historyLog(one, id)).includes(`ROTATED ${r - 1}->${r}`));
    const incomplete = await cli(["witness", "status"]);
    assert.match(incomplete.stdout, /ROTATION INCOMPLETE/);
    proxy.down = false;
    await cli.ok(["witness", "sync"]);
    assert.ok((await historyLog(two, id)).includes(`ROTATED ${r - 1}->${r}`));
    await cli.ok(["verify"]);
  } finally {
    await space.cleanup();
  }
});

test("(f) a crash between the witness's acceptance and the local append: the next command appends the prepared rotation (no rollback alarm)", { timeout: 180_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "crash.witness" });
    const proxy = await startProxy(space, server);
    const { history, cli, id } = await ownerHistory(space, server, proxy.url);
    const before = diskHead(history);
    const oldKeyId = core.loadOwnerKeyFile(`${history}.owner-key.json`).keyId;
    // The owner process is killed the moment the witness has recorded the rotation, before it hears the answer.
    const child = spawn(process.execPath, [CLI_BIN, "owner", "rotate-key", "--reason", "crash test", "--json"], { env: { ...process.env, IRONTRELLIS_HISTORY: history, NO_COLOR: "1" }, stdio: "ignore" });
    const exited = new Promise((done) => child.on("exit", (code, signal) => done({ code, signal })));
    proxy.transform = (request) => {
      if (request.method === "POST" && request.path.endsWith("/key-events")) child.kill("SIGKILL");
      return undefined;
    };
    const exit = await exited;
    proxy.transform = undefined;
    assert.equal(exit.signal, "SIGKILL");
    const r = before.position + 1;
    assert.equal((await witnessLatest(server, id)).position, r, "the witness holds head r");
    assert.deepEqual(diskHead(history), before, "the file does not");
    assert.ok(existsSync(`${history}.rotation.pending.json`), "the prepared-rotation record survived the crash");
    // The dead process's writer lock goes stale after a minute; the test ages it instead of waiting.
    const lock = `${history}.writer-lock`;
    if (existsSync(lock)) {
      const holder = JSON.parse(readFileSync(lock, "utf8"));
      writeFileSync(lock, JSON.stringify({ ...holder, createdAt: Date.now() - 120_000 }));
      const old = new Date(Date.now() - 120_000);
      utimesSync(lock, old, old);
    }
    // verify: a pending rotation, not a rollback.
    const pending = await cli(["verify"], { json: true });
    assert.equal(pending.code, 0, pending.stdout);
    assert.ok(pending.json.notes.some((note) => note.startsWith("REMOTE_WITNESS_ROTATION_PENDING")), pending.stdout);
    // Any owner command completes it.
    await cli.ok(["agent", "create", "agent:after-crash"]);
    const state = diskState(history);
    assert.equal(state.events[r].type, "OWNER_KEYS_ROTATED");
    const newKeyId = core.loadOwnerKeyFile(`${history}.owner-key.json`).keyId;
    assert.notEqual(newKeyId, oldKeyId);
    for (const suffix of [".rotation.pending.json", ".owner-key.pending.json", ".owner-next-key.pending.json"]) assert.equal(existsSync(history + suffix), false, suffix);
    assert.deepEqual((await historyLog(server, id)).slice(-3), [`HEAD ${r} ${oldKeyId}`, `ROTATED ${r - 1}->${r}`, `HEAD ${r + 1} ${newKeyId}`]);
    await cli.ok(["verify"]);
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("(g) the bundle path: the witness is cut off; its operator imports the rotation bundle offline (and over the admin route); the owner continues", { timeout: 180_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "bundle.witness" });
    const proxy = await startProxy(space, server);
    const { history, cli, id } = await ownerHistory(space, server, proxy.url);
    proxy.down = true;
    const rotated = await cli(["owner", "rotate-key", "--emergency", "--reason", "witness unreachable"], { json: true });
    assert.equal(rotated.code, 0, rotated.stdout + rotated.stderr);
    const r = rotated.json.head.position;
    await cli.ok(["agent", "create", "agent:while-cut-off"]);
    // The owner regenerates the bundles (the rotation's was written already) and hands them over.
    const exported = await cli(["owner", "export-key-events", "--since", String(r)], { json: true });
    assert.equal(exported.code, 0, exported.stdout);
    const bundle = exported.json.bundles.find((b) => b.kind === "ROTATED").path;
    assert.equal(bundle, rotated.json.bundle);
    // Offline import: refused while the server runs (it holds the lock), accepted once it is stopped.
    const witnessBin = (args) => new Promise((done) => {
      const child = spawn(process.execPath, [fileURLToPath(new URL("../bin/irontrellis-witness.mjs", import.meta.url)), ...args], { env: { ...process.env, NO_COLOR: "1" } });
      let stdout = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.on("close", (code) => done({ code, stdout }));
    });
    const locked = await witnessBin(["import-key-events", "--data", server.dataDir, bundle, "--json"]);
    assert.equal(locked.code, 1);
    await server.stop();
    const imported = await witnessBin(["import-key-events", "--data", server.dataDir, bundle, "--json"]);
    assert.equal(imported.code, 0, imported.stdout);
    assert.equal(JSON.parse(imported.stdout).outcomes[0].status, 201);
    await server.start();
    assert.deepEqual((await historyLog(server, id)).slice(-2), [`HEAD ${r} ${rotated.json.signedBy}`, `ROTATED ${r - 1}->${r}`]);
    // The same bundle over the admin route: idempotent.
    const again = await http(server.url, "POST", "/v1/admin/key-events", JSON.parse(readFileSync(bundle, "utf8")), { authorization: `Bearer ${server.token}` });
    assert.equal(again.status, 200, again.text);
    // The network is back: the owner continues; the witness gets the new-key heads.
    proxy.down = false;
    await cli.ok(["witness", "sync"]);
    await cli.ok(["agent", "create", "agent:after-import"]);
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    await cli.ok(["verify"]);
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("(h) after a two-phase rotation a retired-key statement for a new head is SIGNATURE_INVALID; the old heads keep verifying", { timeout: 120_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "retired.witness" });
    const { history, cli, id } = await ownerHistory(space, server, server.url);
    const old = core.loadOwnerKeyFile(`${history}.owner-key.json`);
    const rotated = await cli(["owner", "rotate-key"], { json: true });
    assert.equal(rotated.code, 0, rotated.stdout + rotated.stderr);
    await cli.ok(["agent", "create", "agent:after"]);
    const state = diskState(history);
    const statement = await t.signHeadStatement(old, {
      version: t.HEAD_STATEMENT_VERSION, historyId: id, domain: state.genesis.domain, head: { hash: `0x${"cc".repeat(32)}`, position: state.head.position + 1, canonicalTime: Date.now() },
      previous: { hash: state.head.hash, position: state.head.position },
    });
    const reply = await http(server.url, "POST", `/v1/histories/${id}/heads`, statement);
    assert.deepEqual([reply.status, reply.json.error.code, reply.json.error.hint], [400, "SIGNATURE_INVALID", undefined]);
    const held = await http(server.url, "GET", `/v1/histories/${id}/heads/${rotated.json.head.position}`);
    assert.equal(held.json.receipt.entry.signedStatement.keyId, old.keyId);
    assert.equal(core.verifySignedStatement(held.json.receipt.entry.signedStatement, state), true);
    await cli.ok(["verify"]);
  } finally {
    await space.cleanup();
  }
});

test("(i) the review's PoC (poc4-retired-key) replayed: the retired key's head is superseded; the owner's flush and a fresh owner process write normally", { timeout: 180_000 }, async () => {
  const space = scratch();
  try {
    const server = await startWitnessServer(space, { name: "rot.witness" });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const owner = await core.createLocalOwner({
      historyFile: history, domain: core.createLocalDomain({ format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, owner: "o", controller: "o", now: () => Date.now(),
      witness: { witnesses: [{ url: proxy.url, verifierKey: server.verifierKey, token: server.token }], mode: "sync" },
    });
    await owner.createAgent({ id: "agent:0" });
    const id = historyIdOf(history);
    const K1file = JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8")); // stolen
    proxy.down = true; // witness unreachable while the owner rotates
    // NEW: the default rotation refuses while a bound witness cannot take it first (nothing is written)...
    await assert.rejects(owner.rotateOwnerKey({ reason: "key leaked" }), (error) => error.code === "WITNESS_UNAVAILABLE");
    // ...so the owner rotates in an emergency, which is pre-rotated (createLocalOwner committed a next key).
    const rotated = await owner.rotateOwnerKey({ reason: "key leaked", emergency: true });
    assert.equal(rotated.preRotated, true);
    await owner.createAgent({ id: "agent:after-rotation" });
    // Attacker: K1 signs a statement for a bogus head extending the witness latest (the PoC's exact step).
    const st = core.openHistoryStore(history, { inspect: true, witness: false }).state();
    const latest = await witnessLatest(server, id);
    const K1 = core.keyPairFromPrivateKey(K1file.scheme, K1file.keyId, K1file.privateKey);
    const signer = { keyId: K1.keyId, scheme: K1.scheme, credential: K1.credential, signHash: core.signHashWith(K1) };
    const bogus = await t.signHeadStatement(signer, {
      version: t.HEAD_STATEMENT_VERSION, historyId: id, domain: st.genesis.domain, head: { hash: `0x${"ab".repeat(32)}`, position: 1_000_000, canonicalTime: Date.now() },
      previous: { hash: latest.hash, position: latest.position },
    });
    const reply = await http(server.url, "POST", `/v1/histories/${id}/heads`, bogus);
    assert.equal(reply.status, 201, "the witness has not recorded the rotation yet (M2's window)");
    proxy.down = false;
    // PoC before the fix: "owner flush: ROLLBACK_DETECTED WITNESS_FORK" and "fresh owner process write: ROLLBACK_DETECTED".
    // Now: the flush supersedes the retired key's head and both succeed.
    await owner.flush();
    freshProcess();
    const again = core.openLocalOwner({ historyFile: history, domain: st.genesis.domain, owner: "o", controller: "o", now: () => Date.now(), format: st.format, [FORMAT1_TEST_TOOLING]: true });
    await again.createAgent({ id: "agent:later" });
    const log = await historyLog(server, id);
    assert.ok(log.includes("SUPERSEDED"), log.join(" | "));
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    const refused = await http(server.url, "POST", `/v1/histories/${id}/heads`, bogus);
    assert.equal(refused.json.error.code, "SIGNATURE_INVALID", "the retired key no longer counts past the rotation");
    assert.equal(checkLog(server.dataDir).status, "VALID");
  } finally {
    await space.cleanup();
  }
});

test("(j) third review F1: a thief floods the witness with 1,100 chained retired-key heads; the owner's pre-rotated rotation still supersedes them all, verify passes with the note, check-log is VALID", { timeout: 300_000 }, async () => {
  const space = scratch();
  try {
    // Rate limits off so the flood runs fast (with the defaults it takes the thief about two minutes).
    const server = await startWitnessServer(space, { name: "flood.witness", config: { rateLimit: { perIpPerMinute: 0, perHistoryPerMinute: 0, monitoringPerIpPerMinute: 0 } } });
    const proxy = await startProxy(space, server);
    const history = space.path("history.jsonl");
    const owner = await core.createLocalOwner({
      historyFile: history, domain: core.createLocalDomain({ format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, owner: "o", controller: "o", now: () => Date.now(),
      witness: { witnesses: [{ url: proxy.url, verifierKey: server.verifierKey, token: server.token }], mode: "sync" },
    });
    await owner.createAgent({ id: "agent:0" });
    const id = historyIdOf(history);
    const L = await witnessLatest(server, id);
    const K1file = JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8")); // stolen
    proxy.down = true;
    const rotated = await owner.rotateOwnerKey({ reason: "key leaked", emergency: true });
    assert.equal(rotated.preRotated, true);
    // The thief floods the witness: 1,100 chained heads signed with the retired key, each extending the witness's latest.
    const st = core.openHistoryStore(history, { inspect: true, witness: false }).state();
    const K1 = core.keyPairFromPrivateKey(K1file.scheme, K1file.keyId, K1file.privateKey);
    const signer = { keyId: K1.keyId, scheme: K1.scheme, credential: K1.credential, signHash: core.signHashWith(K1) };
    const FLOOD = 1_100;
    let previous = { hash: L.hash, position: L.position };
    let last;
    for (let n = 1; n <= FLOOD; n += 1) {
      const hash = `0x${n.toString(16).padStart(64, "f")}`;
      const statement = await t.signHeadStatement(signer, {
        version: t.HEAD_STATEMENT_VERSION, historyId: id, domain: st.genesis.domain, head: { hash, position: L.position + 1 + n, canonicalTime: Date.now() }, previous,
      });
      const reply = await http(server.url, "POST", `/v1/histories/${id}/heads`, statement);
      assert.equal(reply.status, 201, reply.text);
      previous = { hash, position: L.position + 1 + n };
      last = statement;
    }
    assert.equal((await witnessLatest(server, id)).position, previous.position, "the forged head is the witness's latest");
    proxy.down = false;
    // The owner's delivery supersedes the whole flood from L in one SUPERSEDED entry of fixed size.
    await owner.flush();
    await owner.createAgent({ id: "agent:after" });
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    const info = await witnessHistory(server, id);
    assert.equal(info.supersedes, 1);
    const entry = info.lastSupersede.entry;
    assert.equal(entry.supersededCount, FLOOD);
    assert.equal(entry.supersededLatest.position, previous.position);
    assert.equal(entry.supersededLatest.hash, previous.hash);
    assert.equal(entry.chain.statement.previous.position, L.position, "the chain resumes from L");
    assert.equal(entry.supersededToIndex, info.lastSupersede.index, "the range ends at the SUPERSEDED entry itself");
    assert.ok(JSON.stringify(entry).length < 16_384, "the entry does not grow with the number of superseded heads");
    const refused = await http(server.url, "POST", `/v1/histories/${id}/heads`, last);
    assert.equal(refused.json.error.code, "SIGNATURE_INVALID", "the retired key no longer counts past the rotation");
    const verdict = await cliFor(history)(["verify"], { json: true });
    assert.equal(verdict.code, 0, verdict.stdout);
    assert.ok(verdict.json.notes.some((note) => note.startsWith("REMOTE_WITNESS_SUPERSEDED 1")), verdict.stdout);
    const audit = checkLog(server.dataDir);
    assert.equal(audit.status, "VALID", JSON.stringify(audit.problems));
    assert.equal(audit.kinds.SUPERSEDED, 1);
    // A restart replays the log (the range is derived again) and serves the same state.
    await server.stop();
    await server.start();
    assert.deepEqual(await witnessLatest(server, id), diskHead(history));
    assert.equal((await witnessHistory(server, id)).supersedes, 1);
  } finally {
    await space.cleanup();
  }
});
