// Block 4 (owner-key custody): the gateway with an owner key held by a signer. The runtime writes (sessions, attempts)
// never touch the owner key; the operator's revoke signs through a key reference (here a command signer) and waits for
// its pin attestation; a signer that answers with a wrong signature writes nothing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keyReference, keyReferenceText, openHistoryStore, ownerKeyPathFor, verifyHistory } from "@ramex-labs/irontrellis";
import { setup } from "./fixtures.mjs";
import { revokeAuthority } from "../dist/operations.js";
import { createGateway } from "../dist/gateway.js";
import { commandSignerScript } from "../../core/test/helpers/ssh-agent.mjs";

test("the gateway and its operator revoke with the owner key behind a command signer (a key reference): signed, attested, verified; a wrong signature writes nothing", async (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-gw-custody-")));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 10 }));
  const f = await setup(join(root, "case"));
  const keyPath = ownerKeyPathFor(f.local.historyFile);
  const record = JSON.parse(readFileSync(keyPath, "utf8"));
  // The key material moves into the signing program's own file; the history keeps a reference.
  const refOf = (mode) => keyReference({ keyId: record.keyId, publicKey: record.credential, signer: { kind: "command", argv: [process.execPath, commandSignerScript(root, record.privateKey, mode)] } });
  writeFileSync(keyPath, keyReferenceText(refOf("ok")), { mode: 0o600 });
  const g = await createGateway({ ...f.config, local: f.local });
  t.after(() => g.close());
  assert.equal(g.why("create_incident_ticket").decision, "ALLOW");
  assert.equal((await g.run("create_incident_ticket", { title: "before" })).status, "RESPONSE_RETAINED", "runtime writes need no owner key");
  // A signer answering with another key's signature: SIGNER_FAILED, nothing written.
  writeFileSync(keyPath, keyReferenceText(refOf("wrong")), { mode: 0o600 });
  const before = readFileSync(f.local.historyFile);
  await assert.rejects(revokeAuthority({ historyFile: f.local.historyFile, authority: "write" }), (e) => e.code === "SIGNER_FAILED" && e.detail?.reason === "SIGNATURE_INVALID");
  assert.deepEqual(readFileSync(f.local.historyFile), before);
  // The right signer: the revocation is signed through it and its pin attested before the call returns.
  writeFileSync(keyPath, keyReferenceText(refOf("ok")), { mode: 0o600 });
  const revoked = await revokeAuthority({ historyFile: f.local.historyFile, authority: "write" });
  assert.equal(revoked.status, "AUTHORITY_REVOKED");
  const events = openHistoryStore(f.local.historyFile).state().events;
  assert.equal(events.at(-1).data.controlAuthorization.keyId, record.keyId);
  const report = verifyHistory(f.local.historyFile);
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.pinnedAttestation, "VERIFIED", "the pin attests the revocation's head");
  assert.equal(g.why("create_incident_ticket").decision, "DENY");
});
