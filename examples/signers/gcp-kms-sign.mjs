#!/usr/bin/env node
// IronTrellis command signer, EXAMPLE — NOT TESTED AGAINST A LIVE GOOGLE CLOUD PROJECT. Review it before use.
//
// Signs with a Google Cloud KMS asymmetric key of algorithm EC_SIGN_ED25519 (PureEdDSA: Cloud KMS signs the raw data,
// not a digest) through the gcloud CLI:
//   gcloud kms asymmetric-sign --location L --keyring R --key K --version V --project P --input-file <in> --signature-file <out>
// (no --digest-algorithm: an Ed25519 key signs the data itself). The data is the 32-byte hash IronTrellis signs; the
// signature file holds the 64-byte Ed25519 signature, which IronTrellis verifies against the pinned public key.
//
//   key:       gcloud kms keys create owner-1 --keyring irontrellis --location global --purpose asymmetric-signing \
//                --default-algorithm ec-sign-ed25519 --protection-level hsm        (or software)
//   public key: node gcp-kms-sign.mjs --version-name projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1 --gcloud /usr/bin/gcloud --public-key
//              (gcloud kms keys versions get-public-key; prints 0x + 64 hex for `irontrellis signer ref --public-key`)
//   reference: irontrellis signer ref --out owner-1.owner-key-ref.json --signer command --public-key 0x… \
//                --signer-command '["/usr/bin/node","/opt/irontrellis/gcp-kms-sign.mjs","--version-name","projects/…/cryptoKeyVersions/1","--gcloud","/usr/bin/gcloud"]' \
//                --pass-env CLOUDSDK_CONFIG,GOOGLE_APPLICATION_CREDENTIALS --signer-timeout-ms 60000
//
// The command signer gets a minimal environment (docs/CUSTODY.md §6): pass what gcloud needs with --pass-env. Give the
// signing identity roles/cloudkms.signer on that key version only, and keep that identity out of the agent's reach
// (the agent must not be able to run gcloud as it). Options: --gcloud <absolute path> (or GCLOUD), required.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

const fail = (message, code = 1, error = "SIGNER_FAILED") => {
  process.stdout.write(`${JSON.stringify({ error: { code: error, message } })}\n`);
  process.stderr.write(`gcp-kms-sign: ${message}\n`);
  process.exit(code);
};
const args = process.argv.slice(2);
const option = (name) => { const at = args.indexOf(name); return at < 0 ? undefined : args[at + 1]; };
const name = option("--version-name");
const parts = /^projects\/([^/]+)\/locations\/([^/]+)\/keyRings\/([^/]+)\/cryptoKeys\/([^/]+)\/cryptoKeyVersions\/([^/]+)$/.exec(name ?? "");
if (parts === null) fail("usage: gcp-kms-sign.mjs --version-name projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V [--public-key] [--gcloud <path>]", 2);
const [, project, location, keyring, key, version] = parts;
// The CLI is named by an absolute path (--gcloud or GCLOUD, passed with --pass-env GCLOUD): the command signer's PATH is only
// /usr/bin:/bin, and a PATH search could find a program the agent put in a writable directory.
const gcloud = option("--gcloud") ?? process.env.GCLOUD;
if (gcloud === undefined || !isAbsolute(gcloud)) fail("name the gcloud CLI by its absolute path: --gcloud /usr/bin/gcloud (or GCLOUD=/abs/path/gcloud with --pass-env GCLOUD)", 2);
const common = ["--project", project, "--location", location, "--keyring", keyring, "--key", key];
const dir = mkdtempSync(join(tmpdir(), "irontrellis-gcp-"));
try {
  if (args.includes("--public-key")) {
    const out = join(dir, "public.pem");
    const run = spawnSync(gcloud, ["kms", "keys", "versions", "get-public-key", version, ...common, "--output-file", out], { encoding: "utf8" });
    if (run.status !== 0) fail(`gcloud get-public-key failed: ${run.stderr.trim()}`);
    const der = Buffer.from(readFileSync(out, "utf8").replace(/-----[^-]+-----|\s/g, ""), "base64");
    // An Ed25519 SubjectPublicKeyInfo: 12 bytes of DER header, then the 32-byte key.
    if (der.length !== 44 || der.subarray(0, 12).toString("hex") !== "302a300506032b6570032100") fail("the key version is not an Ed25519 key (EC_SIGN_ED25519)");
    process.stdout.write(`0x${der.subarray(12).toString("hex")}\n`);
    process.exit(0);
  }
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  let request;
  try { request = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { fail("the request is not JSON", 2); }
  if (request.version !== "irontrellis-sign-request/1" || request.scheme !== "ed25519") fail(`unsupported request ${request.version} / ${request.scheme}`, 2);
  const message = Buffer.from(String(request.message), "base64");
  if (message.length !== 32) fail(`the message has ${message.length} bytes; IronTrellis signs 32-byte hashes`, 2);
  const input = join(dir, "message.bin"), output = join(dir, "signature.bin");
  writeFileSync(input, message, { mode: 0o600 });
  const run = spawnSync(gcloud, ["kms", "asymmetric-sign", "--version", version, ...common, "--input-file", input, "--signature-file", output], { encoding: "utf8" });
  if (run.status !== 0) fail(`gcloud asymmetric-sign failed: ${run.stderr.trim()}`);
  const signature = readFileSync(output);
  if (signature.length !== 64) fail(`Cloud KMS returned ${signature.length} bytes; an Ed25519 signature has 64`);
  process.stdout.write(`${JSON.stringify({ signature: signature.toString("base64") })}\n`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
