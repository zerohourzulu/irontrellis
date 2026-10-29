#!/usr/bin/env node
// IronTrellis command signer, EXAMPLE — NOT TESTED AGAINST A LIVE AWS ACCOUNT. Review it before use.
//
// Signs with an AWS KMS key of key spec ECC_NIST_EDWARDS25519 (Ed25519, supported by AWS KMS since November 2025) with
// signing algorithm ED25519_SHA_512 and MessageType RAW: AWS KMS computes PureEdDSA (RFC 8032) over the message itself,
// which is the 32-byte hash IronTrellis signs. (ED25519_PH_SHA_512 with MessageType DIGEST is the pre-hashed HashEdDSA
// variant: a different signature, which IronTrellis would reject. Do not use it.) Through the AWS CLI:
//   aws kms sign --key-id <id> --message fileb://<file> --message-type RAW --signing-algorithm ED25519_SHA_512 \
//     --output text --query Signature
// The 64-byte signature comes back base64-encoded; IronTrellis verifies it against the pinned public key.
//
//   key:        aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY --description "IronTrellis owner:1"
//   public key: node aws-kms-sign.mjs --key-id <arn> --aws /usr/local/bin/aws --public-key   (aws kms get-public-key; prints 0x + 64 hex)
//   reference:  irontrellis signer ref --out owner-1.owner-key-ref.json --signer command --public-key 0x… \
//                 --signer-command '["/usr/bin/node","/opt/irontrellis/aws-kms-sign.mjs","--key-id","arn:aws:kms:…:key/…","--aws","/usr/local/bin/aws"]' \
//                 --pass-env AWS_PROFILE,AWS_REGION,AWS_CONFIG_FILE,AWS_SHARED_CREDENTIALS_FILE --signer-timeout-ms 60000
//
// The command signer gets a minimal environment (docs/CUSTODY.md §6): pass what the AWS CLI needs with --pass-env. Grant
// the signing identity kms:Sign (and kms:GetPublicKey) on that key only, and keep that identity out of the agent's reach.
// Options: --aws <absolute path> (or AWS), required; --region <region>.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

const fail = (message, code = 1, error = "SIGNER_FAILED") => {
  process.stdout.write(`${JSON.stringify({ error: { code: error, message } })}\n`);
  process.stderr.write(`aws-kms-sign: ${message}\n`);
  process.exit(code);
};
const args = process.argv.slice(2);
const option = (name) => { const at = args.indexOf(name); return at < 0 ? undefined : args[at + 1]; };
const keyId = option("--key-id");
if (keyId === undefined) fail("usage: aws-kms-sign.mjs --key-id <arn|id|alias> [--region <region>] [--public-key] [--aws <path>]", 2);
// The CLI is named by an absolute path (--aws or AWS, passed with --pass-env AWS): the command signer's PATH is only
// /usr/bin:/bin, and a PATH search could find a program the agent put in a writable directory.
const aws = option("--aws") ?? process.env.AWS;
if (aws === undefined || !isAbsolute(aws)) fail("name the aws CLI by its absolute path: --aws /usr/bin/aws (or AWS=/abs/path/aws with --pass-env AWS)", 2);
const region = option("--region") === undefined ? [] : ["--region", option("--region")];

if (args.includes("--public-key")) {
  const run = spawnSync(aws, ["kms", "get-public-key", "--key-id", keyId, ...region, "--output", "json"], { encoding: "utf8" });
  if (run.status !== 0) fail(`aws kms get-public-key failed: ${run.stderr.trim()}`);
  const answer = JSON.parse(run.stdout);
  if (answer.KeySpec !== "ECC_NIST_EDWARDS25519") fail(`the key's spec is ${answer.KeySpec}, not ECC_NIST_EDWARDS25519`);
  const der = Buffer.from(answer.PublicKey, "base64");
  if (der.length !== 44 || der.subarray(0, 12).toString("hex") !== "302a300506032b6570032100") fail("the public key is not an Ed25519 SubjectPublicKeyInfo");
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
const dir = mkdtempSync(join(tmpdir(), "irontrellis-aws-"));
try {
  const input = join(dir, "message.bin");
  writeFileSync(input, message, { mode: 0o600 });
  const run = spawnSync(aws, ["kms", "sign", "--key-id", keyId, ...region, "--message", `fileb://${input}`, "--message-type", "RAW", "--signing-algorithm", "ED25519_SHA_512", "--output", "text", "--query", "Signature"], { encoding: "utf8" });
  if (run.status !== 0) fail(`aws kms sign failed: ${run.stderr.trim()}`);
  const signature = Buffer.from(run.stdout.trim(), "base64");
  if (signature.length !== 64) fail(`AWS KMS returned ${signature.length} bytes; an Ed25519 signature has 64`);
  process.stdout.write(`${JSON.stringify({ signature: signature.toString("base64") })}\n`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
