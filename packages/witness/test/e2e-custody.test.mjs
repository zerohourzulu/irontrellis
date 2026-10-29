// End to end, block 4 (owner-key custody): the REAL witness server, the REAL `irontrellis` CLI and a REAL OpenSSH
// ssh-agent that holds the owner key and the committed next key (neither ever exists as a file near the history).
//  (a) init bound to the witness with the owner key in the agent; grants; every head statement and pin signed through
//      the agent; verify against the witness;
//  (b) pre-rotation onto a second agent key (by reference), two-phase through the witness; the witness records the
//      rotation; later heads are signed by the new key; check-log passes;
//  (c) a key removed from the agent: KEY_UNAVAILABLE, nothing appended, nothing new at the witness;
//  (d) the agent killed (the agent refusing): SIGNER_FAILED, nothing appended; a new agent with the key resumes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { checkLog, cliFor, core, diskState, historyIdOf, scratch, startWitnessServer, witnessHistory, witnessLatest } from "./e2e-harness.mjs";
import { haveOpenSsh, scratchDir, sshKeygen, startSshAgent } from "../../core/test/helpers/ssh-agent.mjs";

const skip = haveOpenSsh ? {} : { skip: "OpenSSH is not installed" };
const bytes = (path) => (existsSync(path) ? readFileSync(path) : undefined);

test("e2e custody: a witness-bound history whose owner and next keys live only in a real ssh-agent (init, grants, two-phase pre-rotation, a removed key, a dead agent)", skip, async (t) => {
  const space = scratch("itw-cust-");
  t.after(() => space.cleanup());
  const agent = await startSshAgent(t, space.dir);
  const k1 = sshKeygen(space.dir, "owner1"), k2 = sshKeygen(space.dir, "owner2"), k3 = sshKeygen(space.dir, "owner3");
  agent.add(k1.file);
  const server = await startWitnessServer(space, { name: "custody.witness" });
  const history = space.path("history.jsonl");
  const cli = cliFor(history, { SSH_AUTH_SOCK: agent.socket });

  // (a) init: owner key in the agent, the next key committed by public key only, bound to the witness from the first write.
  const init = await cli.ok(["init", "--owner", "ops", "--signer", "ssh-agent", "--public-key", k1.pub, "--next-public-key", k2.pub,
    "--witness", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"], { json: true });
  assert.equal(init.json.ownerKeyHolder, "reference");
  assert.deepEqual(init.json.witnesses.map((w) => w.url), [server.url]);
  const id = historyIdOf(history);
  for (const agentId of ["agent:1", "agent:2"]) await cli.ok(["agent", "create", agentId]);
  await cli.ok(["grant", "g1", "--to", "agent:1", "--actions", "read", "--resources", "r:1", "--expires", "+1h"]);
  const head = diskState(history).head;
  assert.deepEqual(await witnessLatest(server, id), { hash: head.hash, position: head.position, canonicalTime: head.canonicalTime }, "sync mode: the witness holds the head, signed through the agent");
  const verified = await cli.ok(["verify"], { json: true });
  assert.equal(verified.json.report.remoteWitnessStatus, "OK");
  assert.equal(verified.json.report.pinnedAttestation, "VERIFIED");
  for (const file of [k1.file, k2.file]) assert.ok(!existsSync(`${history}.owner-key.json`) || !readFileSync(`${history}.owner-key.json`, "utf8").includes(readFileSync(file, "utf8").split("\n")[1]));

  // (b) pre-rotation onto the second agent key, by reference, two-phase through the witness; the third key becomes the next commitment.
  agent.add(k2.file);
  const ref2 = space.path("owner2.owner-next-key-ref.json");
  await cli.ok(["signer", "ref", "--out", ref2, "--next", "--key-id", "owner:2", "--signer", "ssh-agent", "--public-key", k2.pub]);
  const rotated = await cli.ok(["owner", "rotate-key", "--next-key-ref", ref2, "--new-next-public-key", k3.pub, "--reason", "scheduled"], { json: true });
  assert.equal(rotated.json.preRotated, true);
  assert.equal(rotated.json.keyId, "owner:2");
  assert.equal(rotated.json.emergency, false);
  assert.deepEqual(rotated.json.witnesses.accepted, [server.url], "two-phase: the witness recorded the rotation before the local append");
  assert.equal(rotated.json.rotationIncomplete, false);
  const info = await witnessHistory(server, id);
  assert.deepEqual(info.epochs.map((e) => e.fromPosition), [0, rotated.json.fromPosition]);
  await cli.ok(["agent", "create", "agent:3"]);
  const status = await cli.ok(["witness", "status"], { json: true });
  assert.ok(status.json.witnesses.every((w) => w.pendingRotations === 0));
  const afterRotation = await cli.ok(["verify"], { json: true });
  assert.equal(afterRotation.json.report.remoteWitnessStatus, "OK");
  const owner = await cli.ok(["owner", "status"], { json: true });
  assert.deepEqual(owner.json.custody.map((c) => [c.role, c.code]), [["current", "OWNER_KEY_REFERENCE"], ["next", "NEXT_KEY_OFF_HOST"], ["retired", "RETIRED_KEY_REFERENCE"]]);
  assert.equal(checkLog(server.dataDir).status, "VALID");

  // (c) the owner key taken out of the agent: KEY_UNAVAILABLE, nothing appended, nothing new at the witness.
  const before = [bytes(history), bytes(`${history}.head`)];
  const witnessBefore = await witnessLatest(server, id);
  agent.remove(`${k2.file}.pub`);
  const missing = await cli(["grant", "g2", "--to", "agent:1", "--actions", "read", "--resources", "r:2", "--expires", "+1h"], { json: true });
  assert.equal(missing.code, 1);
  assert.equal(missing.json.error.code, "KEY_UNAVAILABLE");
  assert.equal(missing.json.error.context.reason, "KEY_NOT_IN_AGENT");
  assert.deepEqual([bytes(history), bytes(`${history}.head`)], before);
  assert.deepEqual(await witnessLatest(server, id), witnessBefore);

  // (d) the agent dies: SIGNER_FAILED, nothing appended; a new agent with the key resumes.
  agent.add(k2.file);
  await agent.kill();
  const dead = await cli(["grant", "g2", "--to", "agent:1", "--actions", "read", "--resources", "r:2", "--expires", "+1h"], { json: true });
  assert.equal(dead.json.error.code, "SIGNER_FAILED");
  assert.deepEqual([bytes(history), bytes(`${history}.head`)], before);
  const again = await startSshAgent(t, scratchDir(t, "itw-ag-"));
  const socketLink = again.socket;
  again.add(k2.file);
  const resumed = cliFor(history, { SSH_AUTH_SOCK: socketLink });
  await resumed.ok(["grant", "g2", "--to", "agent:1", "--actions", "read", "--resources", "r:2", "--expires", "+1h"]);
  const final = diskState(history).head;
  assert.deepEqual(await witnessLatest(server, id), { hash: final.hash, position: final.position, canonicalTime: final.canonicalTime });
  assert.equal(checkLog(server.dataDir).status, "VALID");
  const report = await core.verifyHistoryWithWitnesses(history);
  assert.equal(report.ok, true, report.failures.join("\n"));
});
