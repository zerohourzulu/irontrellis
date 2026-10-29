// Worker for the T4 migration test (format2-migrate.test.mjs): runs `migrateHistory` and kills itself with SIGKILL at
// the named step (`setMigrationCutHookForTests` for the plan and the fence; the store's `line-appended` cut for the target
// file written without its pin, SPEC §16.2 steps 1, 2/5 and 6). argv: <source> <target> <cut> <owner private key hex>.
import { setMigrationCutHookForTests, migrateHistory } from "../src/migrate.ts";
import { setStoreCutHookForTests } from "../src/store.ts";
import { keyPairFromPrivateKey } from "../src/crypto/suites.ts";
import { signerFromKeyPair } from "../src/signer.ts";

/** A-40.3: a fixed migration id so a killed and re-run migration and the pinned twins are reproducible. */
const MIGRATION_ID = `0x${"4d".repeat(32)}`;
const [source, target, cut, keyHex] = process.argv.slice(2);
const die = (name) => { if (name !== cut) return; process.stdout.write(`CUT ${name}\n`); process.kill(process.pid, "SIGKILL"); };
setMigrationCutHookForTests(die);
setStoreCutHookForTests(die);
try {
  const result = await migrateHistory({ source, target, now: () => 5000, acceptUnpinnedSource: true, nextKey: false, migrationId: MIGRATION_ID, signer: signerFromKeyPair(keyPairFromPrivateKey("ed25519", "owner:1", keyHex)) });
  process.stdout.write(`${JSON.stringify({ ok: true, phase: result.phase, head: result.targetHead, stateRoot: result.stateRoot })}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ ok: false, code: error.code, message: error.message, detail: error.detail })}\n`);
  process.exitCode = 2;
}
