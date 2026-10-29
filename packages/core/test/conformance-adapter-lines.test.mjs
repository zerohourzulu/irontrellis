// The conformance adapters' line protocol (conformance/README.md): one JSON request per `\n`-terminated line, one answer
// per request. U+2028 and U+2029 inside JSON strings, and a lone `\r` between JSON tokens (JSON whitespace), are not line
// ends; a CRLF line ending is accepted. Found by the fuzzer (VAST-FUZZ-01 F2): readline had cut such a request in two,
// giving two error answers and pairing every later answer with the wrong request. Each case runs against node.mjs,
// reference-node.mjs and, when Python can import the package, python.py. The frozen legacy adapter
// (conformance/legacy/adapters/node.mjs) still uses readline (KNOWN-ISSUES). Build first (`pnpm build`).
import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)), "../../..");
const core = await import("../dist/index.js");
const PYTHON = process.platform === "win32" ? "python" : "python3";
const pythonReady = spawnSync(PYTHON, ["-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import irontrellis", resolve(ROOT, "python/src")], { timeout: 30_000 }).status === 0;
const ADAPTERS = [
  { name: "node.mjs", command: [process.execPath, resolve(ROOT, "conformance/adapters/node.mjs")] },
  { name: "reference-node.mjs", command: [process.execPath, resolve(ROOT, "conformance/adapters/reference-node.mjs")] },
  { name: "python.py", command: [PYTHON, "-B", resolve(ROOT, "conformance/adapters/python.py")], skip: pythonReady ? false : "Python cannot import the irontrellis package here" },
];

/** Writes `chunks` to the adapter's stdin as given, closes it, and returns the answer lines. */
function exchange(adapter, chunks) {
  return new Promise((resolveAnswers, reject) => {
    const child = spawn(adapter.command[0], adapter.command.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.setEncoding("utf8").on("data", (d) => { out += d; });
    child.stderr.setEncoding("utf8").on("data", (d) => { err += d; });
    child.on("error", reject);
    child.on("close", () => resolveAnswers({ answers: out.split("\n").filter((l) => l !== "").map((l) => JSON.parse(l)), err }));
    (async () => { for (const c of chunks) { child.stdin.write(c); await new Promise((r) => setTimeout(r, 20)); } child.stdin.end(); })();
  });
}
const request = (note) => JSON.stringify({ op: "replay", operationVersion: core.REPLAY_VERSION,
  events: [{ id: "event:1", type: "DEPLOYMENT_INITIALIZED", timestamp: 1, data: { note } }] });

for (const adapter of ADAPTERS) {
  test(`${adapter.name}: U+2028 and U+2029 inside strings, and a lone CR between tokens: one request, one answer, the same as without them`, { skip: adapter.skip }, async () => {
    const { answers: plain } = await exchange(adapter, [`${request("ab")}\n`]);
    assert.equal(plain.length, 1);
    for (const ch of ["\u2028", "\u2029"]) {
      const { answers } = await exchange(adapter, [`${request(`a${ch}b`)}\n`]);
      assert.equal(answers.length, 1, `one answer for a request containing ${JSON.stringify(ch)}`);
      assert.deepEqual(answers[0], plain[0]);
    }
    const { answers: cr } = await exchange(adapter, [`${request("ab").replace('"op":', '"op":\r')}\n`]);
    assert.equal(cr.length, 1, "one answer for a request with a lone CR between JSON tokens");
    assert.deepEqual(cr[0], plain[0]);
  });

  test(`${adapter.name}: CRLF line endings, several requests in one write and a request split across writes keep one answer per request`, { skip: adapter.skip }, async () => {
    const alone = async (r) => (await exchange(adapter, [`${r}\n`])).answers;
    const [a, c] = [request("a\u2028b"), request("c")];
    const { answers: crlf } = await exchange(adapter, [`${a}\r\n${c}\r\n`]);
    assert.deepEqual(crlf, [...await alone(a), ...await alone(c)]);
    const [x, z] = [request("x\u2029y"), request("z")], line = `${x}\n`, cut = Math.floor(line.length / 2);
    const { answers: split } = await exchange(adapter, [line.slice(0, cut), line.slice(cut), z]); // the last has no newline
    assert.deepEqual(split, [...await alone(x), ...await alone(z)]);
  });
}

// The adapters read request numbers as JavaScript's JSON.parse does, so `-0` stays negative zero and is refused as a position
// (canonical U53) by both engines: verify-attestation answers prefix false in TypeScript and Python alike (fuzz VAST-FUZZ-01 F4).
test("verify-attestation with head.position -0: node.mjs and python.py give the same answer, prefix false", async () => {
  const { readFileSync } = await import("node:fs");
  const events = JSON.parse(readFileSync(resolve(ROOT, "conformance/v1/histories/handover-v1.json"), "utf8"));
  const state = core.replay(core.jsonParseWithBigints(JSON.stringify(events))).state;
  const text = JSON.stringify({ op: "verify-attestation", events, attestation: { version: "irontrellis-head-attestation/1",
    head: { hash: state.eventHistoryHashes[0], position: 987654321, canonicalTime: state.events[0].timestamp }, keyId: "owner:1", scheme: "ed25519",
    signature: `0x${"00".repeat(64)}` } }).replace(":987654321", ":-0");
  const answers = [];
  for (const adapter of ADAPTERS.filter((a) => a.name !== "reference-node.mjs" && !a.skip)) {
    const { answers: [answer] } = await exchange(adapter, [`${text}\n`]);
    assert.equal(answer.ok, true, `${adapter.name}: ${JSON.stringify(answer)}`);
    assert.equal(answer.result.prefix, false, adapter.name);
    answers.push(answer);
  }
  for (const answer of answers.slice(1)) assert.deepEqual(answer, answers[0]);
});
