// End to end, block 4 phase B: the REAL witness server, the REAL `irontrellis` CLI and a REAL Vault dev server
// (Docker hashicorp/vault:1.20, or IRONTRELLIS_VAULT_ADDR + IRONTRELLIS_VAULT_TOKEN; skipped with the reason
// otherwise) whose Transit keys hold the owner key and the committed next key.
//  (a) init bound to the witness with the owner key in Vault; grants; head statements and pins signed by Vault;
//  (b) the Vault key rotated (a new version): the pinned version keeps signing, the witness keeps accepting;
//  (c) pre-rotation onto a second Transit key, two-phase through the witness; check-log VALID;
//  (d) the token revoked: SIGNER_FAILED, nothing appended, nothing new at the witness; doctor reports it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { checkLog, cliFor, core, diskState, historyIdOf, scratch, startWitnessServer, witnessHistory, witnessLatest } from "./e2e-harness.mjs";
import { startVault, vaultAvailable, vaultSkip } from "../../core/test/helpers/vault.mjs";

const bytes = (path) => (existsSync(path) ? readFileSync(path) : undefined);
let vault;
before(async () => { if (vaultAvailable.ok) vault = await startVault(); });
after(() => vault?.stop());

test("e2e custody (Vault Transit): a witness-bound history whose owner and next keys are Transit keys (init, grants, a Vault key rotation, two-phase pre-rotation, a revoked token)", vaultSkip, async (t) => {
  const space = scratch("itw-vault-");
  t.after(() => space.cleanup());
  await vault.createKey("e2e-owner");
  const nextPk = await vault.createKey("e2e-next");
  const ownerToken = await vault.childToken(["e2e-owner"]);
  const ownerTokenFile = space.path("owner.vault-token"), nextTokenFile = space.path("next.vault-token");
  writeFileSync(ownerTokenFile, ownerToken, { mode: 0o600 });
  writeFileSync(nextTokenFile, await vault.childToken(["e2e-next"]), { mode: 0o600 });
  const server = await startWitnessServer(space, { name: "vault.witness" });
  const history = space.path("history.jsonl");
  const cli = cliFor(history, { VAULT_TOKEN: "", VAULT_ADDR: vault.address });
  const vflags = (key, tokenFile) => ["--signer", "vault-transit", "--vault-mount", vault.mount, "--vault-key", key, "--vault-token-file", tokenFile];

  // (a) init: the next key's reference (its own token), then the history bound to the witness from the first write.
  const nextRef = space.path("next.owner-next-key-ref.json");
  const ref = await cli.ok(["signer", "ref", "--out", nextRef, "--next", "--key-id", "owner:2", ...vflags("e2e-next", nextTokenFile)], { json: true });
  assert.equal(ref.json.reference.publicKey, nextPk);
  const init = await cli.ok(["init", "--owner", "ops", ...vflags("e2e-owner", ownerTokenFile), "--next-key-ref", nextRef,
    "--witness", server.url, "--verifier-key", server.verifierKey, "--token", server.token, "--mode", "sync"], { json: true });
  assert.equal(init.json.ownerKeyHolder, "reference");
  assert.equal(JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8")).signer.address, vault.address, "VAULT_ADDR is written into the reference");
  const id = historyIdOf(history);
  await cli.ok(["agent", "create", "agent:1"]);
  await cli.ok(["grant", "g1", "--to", "agent:1", "--actions", "read", "--resources", "r:1", "--expires", "+1h"]);
  let head = diskState(history).head;
  assert.deepEqual(await witnessLatest(server, id), { hash: head.hash, position: head.position, canonicalTime: head.canonicalTime }, "sync: the witness holds the head, signed by Vault");
  const verified = await cli.ok(["verify"], { json: true });
  assert.equal(verified.json.report.remoteWitnessStatus, "OK");
  assert.equal(verified.json.report.pinnedAttestation, "VERIFIED");
  const doctor = await cli.ok(["doctor"], { json: true });
  assert.ok(doctor.json.findings.some((f) => f.code === "WITNESS_REACHABLE"));
  assert.equal(doctor.json.findings.filter((f) => f.code === "SIGNER_REACHABLE").length, 2);

  // (b) a Vault key rotation does not switch the owner key.
  await vault.rotateKey("e2e-owner");
  await cli.ok(["grant", "g2", "--to", "agent:1", "--actions", "read", "--resources", "r:2", "--expires", "+1h"]);
  head = diskState(history).head;
  assert.deepEqual(await witnessLatest(server, id), { hash: head.hash, position: head.position, canonicalTime: head.canonicalTime });
  assert.equal(JSON.parse(readFileSync(`${history}.head`, "utf8")).attestation.keyId, "owner:1", "still the pinned v1 key");

  // (c) pre-rotation onto the second Transit key, two-phase through the witness; a public-key-only next commitment.
  const rotated = await cli.ok(["owner", "rotate-key", "--new-next-public-key", core.generateKeyPair("ed25519", "n3").credential, "--reason", "scheduled"], { json: true });
  assert.equal(rotated.json.preRotated, true);
  assert.equal(rotated.json.keyId, "owner:2");
  assert.deepEqual(rotated.json.witnesses.accepted, [server.url], "two-phase: the witness recorded the rotation before the local append");
  assert.equal(rotated.json.rotationIncomplete, false);
  const info = await witnessHistory(server, id);
  assert.deepEqual(info.epochs.map((e) => e.fromPosition), [0, rotated.json.fromPosition]);
  await cli.ok(["agent", "create", "agent:2"]);
  const owner = await cli.ok(["owner", "status"], { json: true });
  assert.deepEqual(owner.json.custody.map((c) => [c.role, c.code]), [["current", "OWNER_KEY_REFERENCE"], ["next", "NEXT_KEY_OFF_HOST"], ["retired", "RETIRED_KEY_REFERENCE"]]);
  assert.equal(checkLog(server.dataDir).status, "VALID");

  // (d) the next (now current) key's token revoked: SIGNER_FAILED, nothing appended, nothing new at the witness.
  const before = [bytes(history), bytes(`${history}.head`)];
  const witnessBefore = await witnessLatest(server, id);
  await vault.revokeToken(readFileSync(nextTokenFile, "utf8"));
  const denied = await cli(["grant", "g3", "--to", "agent:1", "--actions", "read", "--resources", "r:3", "--expires", "+1h"], { json: true });
  assert.equal(denied.code, 1);
  assert.equal(denied.json.error.code, "SIGNER_FAILED");
  assert.equal(denied.json.error.context.reason, "PERMISSION_DENIED");
  assert.deepEqual([bytes(history), bytes(`${history}.head`)], before);
  assert.deepEqual(await witnessLatest(server, id), witnessBefore);
  const warned = await cli(["doctor"], { json: true });
  assert.ok(warned.json.findings.some((f) => f.code === "SIGNER_UNREACHABLE" && /permission denied/.test(f.message)));
  // A new token for the key: writes resume and the witness follows.
  writeFileSync(nextTokenFile, await vault.childToken(["e2e-next"]), { mode: 0o600 });
  await cli.ok(["grant", "g3", "--to", "agent:1", "--actions", "read", "--resources", "r:3", "--expires", "+1h"]);
  const final = diskState(history).head;
  assert.deepEqual(await witnessLatest(server, id), { hash: final.hash, position: final.position, canonicalTime: final.canonicalTime });
  assert.equal(checkLog(server.dataDir).status, "VALID");
  const report = await core.verifyHistoryWithWitnesses(history);
  assert.equal(report.ok, true, report.failures.join("\n"));
});
