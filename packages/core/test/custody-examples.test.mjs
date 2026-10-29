// The command-signer examples in examples/signers (block 4 §4.5). file-signer.mjs runs for real, as the owner key of a
// history. The Google Cloud KMS and AWS KMS examples are NOT tested against the live services: here they run against fake
// `gcloud` / `aws` programs that mimic the documented CLI calls (asymmetric-sign with --input-file/--signature-file and no
// digest; kms sign --message-type RAW --signing-algorithm ED25519_SHA_512), which checks the scripts' plumbing and the
// exact arguments they pass, nothing about the services.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { scratchDir } from "./helpers/ssh-agent.mjs";

const EXAMPLES = resolve(fileURLToPath(new URL("../../../examples/signers/", import.meta.url)));
const custody = await import("../src/custody/index.ts");
const signerLib = await import("../src/signer.ts");
const { suiteFor } = await import("../src/crypto/suites.ts");
const { createLocalOwner, createLocalDomain, verifyHistory } = await import("../src/owner.ts");
const HASH = `0x${"cd".repeat(32)}`;
let clock = 9_000_000;

const refFor = (keyId, publicKey, argv, next = false) => custody.keyReference({ keyId, publicKey, signer: { kind: "command", argv }, next });

test("examples/signers/file-signer.mjs: prints its public key, signs as a history's owner key, refuses a request for another key", async (t) => {
  const dir = scratchDir(t, "itex-");
  const keyFile = join(dir, "secure-owner-1.json");
  const local = signerLib.createOwnerKeyFile(keyFile, "owner:1");
  const script = join(EXAMPLES, "file-signer.mjs");
  const printed = spawnSync(process.execPath, [script, "--key", keyFile, "--public-key"], { encoding: "utf8" });
  assert.equal(printed.status, 0, printed.stderr);
  assert.equal(printed.stdout.trim(), local.credential);
  const argv = [process.execPath, script, "--key", keyFile];
  const historyFile = join(dir, "h.jsonl");
  const owner = await createLocalOwner({ historyFile, domain: createLocalDomain(), owner: "o", controller: "c", now: () => (clock += 1), ownerKeyReference: refFor("owner:1", local.credential, argv), nextKey: false });
  await owner.createAgent({ id: "bea" });
  owner.close();
  const report = verifyHistory(historyFile);
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.pinnedAttestation, "VERIFIED");
  const other = signerLib.createOwnerKeyFile(join(dir, "other.json"), "owner:9");
  await assert.rejects(custody.referenceSigner(refFor("owner:1", other.credential, argv)).signHash(HASH), (e) => e.code === "KEY_UNAVAILABLE" && /this program holds/.test(e.message));
});

/** A fake CLI (node script) that records its argv and signs with `seedFile` the way the real one is documented to. */
function fakeCli(dir, name, body) {
  const file = join(dir, name);
  writeFileSync(file, `#!${process.execPath}
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(${JSON.stringify(join(dir, `${name}.calls`))}, JSON.stringify(args) + "\\n");
const opt = (n) => { const i = args.indexOf(n); return i < 0 ? undefined : args[i + 1]; };
const seed = Buffer.from(readFileSync(${JSON.stringify(join(dir, "kms-seed.hex"))}, "utf8").trim(), "hex");
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const spki = createPublicKey(key).export({ format: "der", type: "spki" });
${body}
`, { mode: 0o700 });
  chmodSync(file, 0o700);
  return file;
}

test("examples/signers/gcp-kms-sign.mjs against a fake gcloud (not live Cloud KMS): get-public-key and asymmetric-sign with the raw 32 bytes, no digest", async (t) => {
  const dir = scratchDir(t, "itex-");
  const seed = Buffer.alloc(32, 5);
  writeFileSync(join(dir, "kms-seed.hex"), seed.toString("hex"));
  const gcloud = fakeCli(dir, "gcloud", `
if (args.includes("get-public-key")) { writeFileSync(opt("--output-file"), "-----BEGIN PUBLIC KEY-----\\n" + spki.toString("base64") + "\\n-----END PUBLIC KEY-----\\n"); process.exit(0); }
if (args[0] === "kms" && args[1] === "asymmetric-sign") {
  if (args.includes("--digest-algorithm")) { process.stderr.write("an Ed25519 key signs data, not a digest"); process.exit(1); }
  writeFileSync(opt("--signature-file"), sign(null, readFileSync(opt("--input-file")), key)); process.exit(0);
}
process.exit(9);`);
  const script = join(EXAMPLES, "gcp-kms-sign.mjs");
  const version = "projects/p1/locations/global/keyRings/irontrellis/cryptoKeys/owner-1/cryptoKeyVersions/1";
  const printed = spawnSync(process.execPath, [script, "--version-name", version, "--gcloud", gcloud, "--public-key"], { encoding: "utf8" });
  assert.equal(printed.status, 0, printed.stderr);
  const publicKey = printed.stdout.trim();
  assert.match(publicKey, /^0x[0-9a-f]{64}$/);
  const signer = custody.referenceSigner(refFor("owner:1", publicKey, [process.execPath, script, "--version-name", version, "--gcloud", gcloud]));
  const signature = await signer.signHash(HASH, { purpose: "head-attestation" });
  assert.equal(suiteFor("ed25519").verify(HASH, signature, publicKey), true);
  const calls = readFileSync(join(dir, "gcloud.calls"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const signCall = calls.find((c) => c[1] === "asymmetric-sign");
  assert.deepEqual(signCall.slice(0, 4), ["kms", "asymmetric-sign", "--version", "1"]);
  for (const [flag, value] of [["--project", "p1"], ["--location", "global"], ["--keyring", "irontrellis"], ["--key", "owner-1"]]) assert.equal(signCall[signCall.indexOf(flag) + 1], value);
  assert.ok(!signCall.includes("--digest-algorithm"));
});

test("examples/signers/aws-kms-sign.mjs against a fake aws CLI (not live AWS KMS): ECC_NIST_EDWARDS25519, ED25519_SHA_512 with MessageType RAW", async (t) => {
  const dir = scratchDir(t, "itex-");
  writeFileSync(join(dir, "kms-seed.hex"), Buffer.alloc(32, 6).toString("hex"));
  const aws = fakeCli(dir, "aws", `
if (args[1] === "get-public-key") { process.stdout.write(JSON.stringify({ KeyId: opt("--key-id"), KeySpec: "ECC_NIST_EDWARDS25519", KeyUsage: "SIGN_VERIFY", PublicKey: spki.toString("base64"), SigningAlgorithms: ["ED25519_SHA_512", "ED25519_PH_SHA_512"] })); process.exit(0); }
if (args[1] === "sign") {
  if (opt("--message-type") !== "RAW" || opt("--signing-algorithm") !== "ED25519_SHA_512") { process.stderr.write("ValidationException"); process.exit(254); }
  const message = readFileSync(opt("--message").replace(/^fileb:\\/\\//, ""));
  process.stdout.write(sign(null, message, key).toString("base64") + "\\n"); process.exit(0);
}
process.exit(9);`);
  const script = join(EXAMPLES, "aws-kms-sign.mjs");
  const keyId = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
  const printed = spawnSync(process.execPath, [script, "--key-id", keyId, "--aws", aws, "--public-key"], { encoding: "utf8" });
  assert.equal(printed.status, 0, printed.stderr);
  const publicKey = printed.stdout.trim();
  const signer = custody.referenceSigner(refFor("owner:1", publicKey, [process.execPath, script, "--key-id", keyId, "--region", "us-east-1", "--aws", aws]));
  assert.equal(suiteFor("ed25519").verify(HASH, await signer.signHash(HASH), publicKey), true);
  const calls = readFileSync(join(dir, "aws.calls"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const signCall = calls.find((c) => c[1] === "sign");
  assert.equal(signCall[signCall.indexOf("--region") + 1], "us-east-1");
  assert.equal(signCall[signCall.indexOf("--message-type") + 1], "RAW");
  // The AWS CLI failing (a denied kms:Sign): SIGNER_FAILED with its message.
  const denied = fakeCli(dir, "aws-denied", `process.stderr.write("An error occurred (AccessDeniedException) when calling the Sign operation"); process.exit(254);`);
  const refused = custody.referenceSigner(refFor("owner:1", publicKey, [process.execPath, script, "--key-id", keyId, "--aws", denied]));
  await assert.rejects(refused.signHash(HASH), (e) => e.code === "SIGNER_FAILED" && /AccessDeniedException/.test(e.message));
});
