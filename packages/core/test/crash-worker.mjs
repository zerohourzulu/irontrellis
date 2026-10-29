// Worker for the T3 store-parity test (format2-crash.test.mjs): opens the owner handle of a format-2 history and
// appends one event, killing itself with SIGKILL at the named write-interruption point (`setStoreCutHookForTests`,
// store.ts). argv: <history file> <cut name | "none"> <agent id> [<domain json>]. Prints `CUT <name>` right before dying so
// the parent can tell a cut from a crash elsewhere; with "none" it prints the result as JSON and exits 0.
import { setStoreCutHookForTests } from "../src/store.ts";
import { openLocalOwner } from "../src/owner.ts";

const [path, cut, agentId, domainJson, ownerId = "operations", controllerId = "operator"] = process.argv.slice(2);
if (cut !== "none") {
  setStoreCutHookForTests((name) => {
    if (name !== cut) return;
    process.stdout.write(`CUT ${name}\n`);
    // Flush stdout synchronously is not possible here; the write above is a pipe write issued before the kill.
    process.kill(process.pid, "SIGKILL");
  });
}
const domain = JSON.parse(domainJson);
let tick = 10_000;
try {
  const owner = openLocalOwner({ historyFile: path, domain, owner: ownerId, controller: controllerId, now: () => (tick += 1), witness: false });
  const result = await owner.createAgent({ id: agentId });
  process.stdout.write(`${JSON.stringify({ ok: true, head: result.head })}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ ok: false, code: error.code, message: error.message })}\n`);
  process.exitCode = 2;
}
