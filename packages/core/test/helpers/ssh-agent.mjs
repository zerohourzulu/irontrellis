// Test helpers for owner-key custody (block 4): a REAL OpenSSH agent per test (`ssh-agent -a <socket> -D`, keys made
// with `ssh-keygen -t ed25519 -N ''`), a FAKE agent speaking the same protocol with scripted misbehaviour (a wrong or
// malformed signature, silence, a FIDO key), and command-signer scripts. Imported by the core, CLI, hooks and witness
// suites by relative path. Not a test file.
import { spawn, spawnSync } from "node:child_process";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const SSH_AGENT = "/usr/bin/ssh-agent", SSH_ADD = "/usr/bin/ssh-add", SSH_KEYGEN = "/usr/bin/ssh-keygen";
export const haveOpenSsh = [SSH_AGENT, SSH_ADD, SSH_KEYGEN].every((bin) => existsSync(bin));

const waitFor = async (predicate, ms = 5000, what = "condition") => {
  const deadline = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
};

/** The longest Unix socket path the helpers create: `sun_path` holds 104 bytes on macOS (108 on Linux), the NUL included. */
export const SOCKET_PATH_MAX = 103;

/** Room left for a socket's file name in a scratch directory (the longest the suites use is `wrong-signature.sock`, 20 bytes). */
const SOCKET_NAME_RESERVE = 24;

/**
 * A scratch directory under tmpdir(), or under /tmp when a socket in it would pass SOCKET_PATH_MAX (a deep TMPDIR, as CI
 * runners and sandboxes set; docs/PLATFORMS.md). If /tmp is not writable either, tmpdir() is kept and a socket test then
 * fails at bind, naming the path.
 */
export function scratchDir(t, prefix = "itc-") {
  const fits = (base) => Buffer.byteLength(join(base, `${prefix}XXXXXX`, "x".repeat(SOCKET_NAME_RESERVE))) <= SOCKET_PATH_MAX;
  let dir;
  if (process.platform !== "win32" && !fits(tmpdir())) {
    try { dir = mkdtempSync(join("/tmp", prefix)); } catch { /* not writable here: keep tmpdir() */ }
  }
  dir ??= mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** `ssh-keygen -t ed25519 -N ''`: returns { file, pub (the ssh-ed25519 line), publicKey (0x hex) }. */
export function sshKeygen(dir, name, comment = name) {
  const file = join(dir, name);
  const made = spawnSync(SSH_KEYGEN, ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", file], { encoding: "utf8" });
  if (made.status !== 0) throw new Error(`ssh-keygen failed: ${made.stderr}`);
  const pub = readFileSync(`${file}.pub`, "utf8").trim();
  const blob = Buffer.from(pub.split(" ")[1], "base64");
  return { file, pub, publicKey: `0x${blob.subarray(blob.length - 32).toString("hex")}` };
}

/**
 * A real OpenSSH agent on `<dir>/agent.sock` (foreground, killed when the test ends). `add(file, ["-c"])` runs ssh-add
 * against it, `remove(pubFile)` ssh-add -d, `kill()` stops it (its socket then refuses connections).
 */
export async function startSshAgent(t, dir) {
  const socket = join(dir, "agent.sock");
  const child = spawn(SSH_AGENT, ["-a", socket, "-D"], { stdio: ["ignore", "ignore", "pipe"] });
  let exited = false;
  child.on("exit", () => { exited = true; });
  t.after(() => { if (!exited) child.kill("SIGKILL"); });
  await waitFor(() => existsSync(socket) || exited, 5000, "ssh-agent socket");
  if (exited) throw new Error("ssh-agent exited at start");
  const env = { ...process.env, SSH_AUTH_SOCK: socket, SSH_ASKPASS: "/nonexistent", SSH_ASKPASS_REQUIRE: "never", DISPLAY: "" };
  const ssh = (args) => {
    const result = spawnSync(SSH_ADD, args, { encoding: "utf8", env });
    if (result.status !== 0) throw new Error(`ssh-add ${args.join(" ")} failed: ${result.stderr}`);
    return result.stdout;
  };
  return {
    socket, env,
    add: (file, flags = []) => ssh([...flags, file]),
    remove: (pubFile) => ssh(["-d", pubFile]),
    list: () => ssh(["-L"]),
    async kill() { if (!exited) { child.kill("SIGTERM"); await waitFor(() => exited, 5000, "ssh-agent exit"); } },
  };
}

// ---------------------------------------------------------------- the fake agent

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const str = (b) => { const x = typeof b === "string" ? Buffer.from(b) : Buffer.from(b); return Buffer.concat([u32(x.length), x]); };
const frame = (type, body) => Buffer.concat([u32(body.length + 1), Buffer.from([type]), body]);
export const ed25519Blob = (publicKey32) => Buffer.concat([str("ssh-ed25519"), str(publicKey32)]);

/**
 * A fake ssh-agent on a Unix socket holding `keys` ({ seed: Buffer(32), publicKey: Buffer(32), type? }). `behaviour`:
 * "ok" (real signatures), "wrong-signature" (a valid signature by another key), "flipped" (one bit off), "malformed"
 * (a 10-byte signature), "rsa-type" (the signature labelled rsa-sha2-512), "silent" (never answers a sign request),
 * "refuse" (SSH_AGENT_FAILURE). `requests` records every sign request's data.
 */
export async function startFakeAgent(t, dir, { keys = [], behaviour = "ok", name = "fake.sock" } = {}) {
  const socket = join(dir, name);
  const requests = [];
  const other = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 7)]), format: "der", type: "pkcs8" });
  const privateOf = (seed) => createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const server = createServer((connection) => {
    let buffer = Buffer.alloc(0);
    connection.on("error", () => {});
    connection.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32BE(0)) {
        const length = buffer.readUInt32BE(0), message = buffer.subarray(4, 4 + length);
        buffer = buffer.subarray(4 + length);
        if (message[0] === 11) {
          const blobs = keys.map((key) => (key.type === "sk" ? Buffer.concat([str("sk-ssh-ed25519@openssh.com"), str(key.publicKey), str("ssh:")]) : ed25519Blob(key.publicKey)));
          connection.write(frame(12, Buffer.concat([u32(blobs.length), ...blobs.map((blob, i) => Buffer.concat([str(blob), str(`key-${i}`)]))])));
        } else if (message[0] === 13) {
          let at = 1;
          const blobLength = message.readUInt32BE(at); const blob = message.subarray(at + 4, at + 4 + blobLength); at += 4 + blobLength;
          const dataLength = message.readUInt32BE(at); const data = message.subarray(at + 4, at + 4 + dataLength);
          requests.push(Buffer.from(data));
          if (behaviour === "silent") continue;
          if (behaviour === "refuse") { connection.write(frame(5, Buffer.alloc(0))); continue; }
          const key = keys.find((k) => ed25519Blob(k.publicKey).equals(blob));
          if (key === undefined) { connection.write(frame(5, Buffer.alloc(0))); continue; }
          let signature = nodeSign(null, data, behaviour === "wrong-signature" ? other : privateOf(key.seed));
          if (behaviour === "flipped") { signature = Buffer.from(signature); signature[5] ^= 1; }
          if (behaviour === "malformed") signature = signature.subarray(0, 10);
          const type = behaviour === "rsa-type" ? "rsa-sha2-512" : "ssh-ed25519";
          connection.write(frame(14, str(Buffer.concat([str(type), str(signature)]))));
        } else connection.write(frame(5, Buffer.alloc(0)));
      }
    });
  });
  await new Promise((resolve) => server.listen(socket, resolve));
  t.after(() => new Promise((resolve) => server.close(() => resolve())));
  return { socket, requests, server };
}

/** An IronTrellis key pair as the fake agent holds it: { seed, publicKey } Buffers, plus the core KeyPair. */
export function fakeKey(generateKeyPair, keyId = "owner:1") {
  const pair = generateKeyPair("ed25519", keyId);
  return { pair, seed: Buffer.from(pair.privateKey.slice(2), "hex"), publicKey: Buffer.from(pair.credential.slice(2), "hex") };
}

// ---------------------------------------------------------------- command-signer scripts

/**
 * Writes an executable command-signer script (node, no dependencies) holding `seedHex`. `mode`: "ok", "sleep" (never
 * answers), "exit" (status 3 with a message on stderr), "garbage" (not JSON), "wrong" (a signature by another key),
 * "key-unavailable" (the protocol's KEY_UNAVAILABLE answer), "env" (prints the environment it got on stderr and signs).
 */
export function commandSignerScript(dir, seedHex, mode = "ok", name = `signer-${mode}.mjs`, { logFile } = {}) {
  const file = join(dir, name);
  writeFileSync(file, `#!${process.execPath}
import { createPrivateKey, sign } from "node:crypto";
import { appendFileSync } from "node:fs";
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
${logFile === undefined ? "" : `appendFileSync(${JSON.stringify(logFile)}, request.purpose + "\\n");`}
const mode = ${JSON.stringify(mode)};
if (request.version !== "irontrellis-sign-request/1") { process.stderr.write("bad version"); process.exit(4); }
if (mode === "env") process.stderr.write("ENV " + JSON.stringify(Object.keys(process.env).sort()) + " PURPOSE " + request.purpose + "\\n");
if (mode === "sleep") await new Promise(() => setInterval(() => {}, 1000));
if (mode === "exit") { process.stderr.write("kms: permission denied for key\\n"); process.exit(3); }
if (mode === "garbage") { process.stdout.write("this is not json"); process.exit(0); }
if (mode === "key-unavailable") { process.stdout.write(JSON.stringify({ error: { code: "KEY_UNAVAILABLE", message: "no such key version" } })); process.exit(2); }
const seed = mode === "wrong" ? Buffer.alloc(32, 9) : Buffer.from(${JSON.stringify(seedHex.replace(/^0x/, ""))}, "hex");
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const signature = sign(null, Buffer.from(request.message, "base64"), key);
process.stdout.write(JSON.stringify({ signature: signature.toString("base64") }) + "\\n");
`, { mode: 0o700 });
  chmodSync(file, 0o700);
  return file;
}
