#!/usr/bin/env node
// IronTrellis command signer, EXAMPLE: signs with an Ed25519 key kept in a file this program can read and the process
// running IronTrellis cannot (another OS user's file, reached through sudo or a setuid wrapper; a mounted token). It is
// the template the cloud examples follow, and the one the test suite runs (packages/core/test/custody-examples.test.mjs).
//
//   reference:  { "kind": "command", "argv": ["/usr/bin/node", "/opt/irontrellis/file-signer.mjs", "--key", "/secure/owner-1.json"] }
//   key file:   an IronTrellis key file (irontrellis-owner-key/1 or irontrellis-owner-next-key/1: its "privateKey" is the
//               0x Ed25519 seed), or a file holding just the 0x seed.
//   --public-key  print the key's public key (0x + 64 hex) instead of signing: the value for `irontrellis signer ref --public-key`.
//
// Protocol (docs/CUSTODY.md §6): one JSON request on stdin
//   {"version":"irontrellis-sign-request/1","keyId","scheme":"ed25519","publicKey":"0x…","message":"<base64, 32 bytes>","purpose","historyId"?}
// and {"signature":"<base64, 64 bytes>"} on stdout, exit 0. IronTrellis verifies the signature before using it.
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";

const fail = (message, code = 1, error = "SIGNER_FAILED") => {
  process.stdout.write(`${JSON.stringify({ error: { code: error, message } })}\n`);
  process.stderr.write(`file-signer: ${message}\n`);
  process.exit(code);
};
const args = process.argv.slice(2);
const at = args.indexOf("--key");
if (at < 0 || args[at + 1] === undefined) fail("usage: file-signer.mjs --key <file> [--public-key]", 2);
let seedHex;
try {
  const text = readFileSync(args[at + 1], "utf8").trim();
  seedHex = text.startsWith("{") ? JSON.parse(text).privateKey : text;
} catch (error) { fail(`cannot read the key file: ${error.message}`, 2, "KEY_UNAVAILABLE"); }
if (typeof seedHex !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(seedHex)) fail("the key file holds no Ed25519 seed", 2, "KEY_UNAVAILABLE");
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex.replace(/^0x/, ""), "hex")]), format: "der", type: "pkcs8" });
const publicKey = `0x${Buffer.from(createPublicKey(key).export({ format: "jwk" }).x, "base64url").toString("hex")}`;
if (args.includes("--public-key")) { process.stdout.write(`${publicKey}\n`); process.exit(0); }

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
let request;
try { request = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { fail("the request is not JSON", 2); }
if (request.version !== "irontrellis-sign-request/1" || request.scheme !== "ed25519") fail(`unsupported request ${request.version} / ${request.scheme}`, 2);
if (String(request.publicKey).toLowerCase() !== publicKey) fail(`this program holds ${publicKey}, not ${request.publicKey}`, 3, "KEY_UNAVAILABLE");
const message = Buffer.from(String(request.message), "base64");
if (message.length !== 32) fail(`the message has ${message.length} bytes; IronTrellis signs 32-byte hashes`, 2);
process.stdout.write(`${JSON.stringify({ signature: sign(null, message, key).toString("base64") })}\n`);
