import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openHistoryStore } from "@ramex-labs/irontrellis";
import { setup } from "./fixtures.mjs";
import { createGateway } from "../dist/gateway.js";
import { inspectCase, revokeAuthority } from "../dist/operations.js";

test("a full history refuses new jobs with CAPACITY_CONTROL_ONLY but still reconciles, inspects and revokes", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "irontrellis-gateway-capacity-"));
  // Room for exactly one job footprint (a declaration plus one reserved slot per lifecycle record type) after the setup events.
  const probe = await setup(join(root, "probe"));
  const used = openHistoryStore(probe.local.historyFile).state().events.length;
  const f = await setup(join(root, "case"), { maxEvents: used + 12 });
  let g = await createGateway({ ...f.config, local: f.local });
  t.after(async () => { await g.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  assert.equal((await g.run("create_incident_ticket", { title: "Synthetic drain test" })).status, "RESPONSE_RETAINED");
  const before = readFileSync(f.local.historyFile);
  assert.equal((await g.run("read_incident", { document: "incident" })).reason, "CAPACITY_CONTROL_ONLY");
  assert.deepEqual(readFileSync(f.local.historyFile), before);
  assert.equal((await g.run("create_incident_ticket", { title: "Synthetic drain test" })).status, "RECONCILIATION_ONLY");
  const diagnostic = inspectCase({ historyFile: f.local.historyFile, storage: f.config.storage });
  assert.equal(diagnostic.mode, "CONTROL_ONLY");
  assert.equal(diagnostic.canDeclareJob, false);
  assert.equal(diagnostic.declaredJobs, 1);
  assert.ok(diagnostic.capacity.lifecycleReserved > 0);
  assert.deepEqual(diagnostic.warnings, ["CAPACITY_CONTROL_ONLY"]);
  // Revocation is always admitted, whatever the capacity.
  assert.equal((await revokeAuthority({ historyFile: f.local.historyFile, authority: "read" })).status, "AUTHORITY_REVOKED");
  await g.close();
  g = await createGateway({ ...f.config, local: f.local });
  assert.equal((await g.run("read_incident", { document: "incident" })).status, "DENIED");
});
