// Crash safety with a real server process: SIGKILL during a burst of
// concurrent appends, then restart. Every receipt a client received must still
// verify and name the same entry, and every checkpoint a client received must
// be consistent with the restarted log (nothing acknowledged was lost or
// rewritten). check-log must pass on the killed directory.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { BIN, buildHistory, t, tempDir } from "./helpers.mjs";

function startServer(dir) {
  const child = spawn(process.execPath, [BIN, "serve", "--data", dir, "--listen", "127.0.0.1:0"], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, NO_COLOR: "1" } });
  const logs = [];
  const url = new Promise((resolve, reject) => {
    let buffer = "";
    child.stderr.on("data", (chunk) => {
      buffer += chunk;
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        try {
          const parsed = JSON.parse(line);
          logs.push(parsed);
          if (parsed.msg === "listening") resolve(parsed.url);
        } catch {
          logs.push({ raw: line });
        }
      }
    });
    child.on("exit", (code, signal) => reject(new Error(`server exited early (${code ?? signal}): ${JSON.stringify(logs.slice(-3))}`)));
  });
  const exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve({ code, signal })));
  return { child, url, logs, exited };
}

const post = async (url, path, body) => {
  const response = await fetch(`${url}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: response.status, json: await response.json() };
};

test("SIGKILL during a burst of appends: the restarted log is consistent with every checkpoint and receipt any client received", { timeout: 120_000 }, async () => {
  const { dir, cleanup } = tempDir();
  try {
    assert.equal(spawnSync(process.execPath, [BIN, "init", "--data", dir, "--name", "crash.witness"]).status, 0);
    const configPath = join(dir, "config.json");
    const config = JSON.parse(readFileSync(configPath, "utf8"));
    writeFileSync(configPath, JSON.stringify({ ...config, registration: "open", rateLimit: { perIpPerMinute: 0, perHistoryPerMinute: 0 } }), { mode: 0o600 });
    const vkey = spawnSync(process.execPath, [BIN, "verifier-key", "--data", dir], { encoding: "utf8" }).stdout.trim();

    const histories = await Promise.all(Array.from({ length: 8 }, (_, n) => buildHistory({ name: `crash-${n}`, agents: 40, seed: 0x6000 + 2 * n })));
    const statements = await Promise.all(histories.map(async (h) => {
      const list = [await h.statement(0, null)];
      for (let position = 1; position < h.heads.length; position += 1) list.push(await h.statement(position, position - 1));
      return list;
    }));

    let server = startServer(dir);
    let url = await server.url;
    for (const h of histories) assert.equal((await post(url, "/v1/histories", { genesis: h.genesis })).status, 201);

    const received = [];
    let acknowledged = 0;
    let killed = false;
    const killAt = 120;
    await Promise.all(histories.map(async (h, n) => {
      for (const statement of statements[n]) {
        if (killed) return;
        let reply;
        try {
          reply = await post(url, `/v1/histories/${h.historyId}/heads`, statement);
        } catch {
          return; // the connection died with the server
        }
        if (reply.status !== 201) continue;
        received.push(reply.json);
        acknowledged += 1;
        if (acknowledged === killAt && !killed) {
          killed = true;
          server.child.kill("SIGKILL");
        }
      }
    }));
    const exit = await server.exited;
    assert.equal(exit.signal, "SIGKILL");
    assert.ok(received.length >= killAt, `${received.length} acknowledged appends before the kill`);

    // Offline audit of the killed directory.
    const check = spawnSync(process.execPath, [BIN, "check-log", "--data", dir, "--json"], { encoding: "utf8" });
    const report = JSON.parse(check.stdout);
    assert.equal(check.status, 0, check.stdout);
    assert.equal(report.status, "VALID");
    assert.ok(report.entries >= 8 + received.length);

    server = startServer(dir);
    url = await server.url;
    const checkpointNote = await (await fetch(`${url}/v1/checkpoint`)).text();
    const current = t.parseCheckpoint(t.openNote(checkpointNote, [vkey]).body);
    assert.ok(current.size >= 8 + received.length);
    const seen = new Map();
    for (const body of received) {
      for (const receipt of [body.receipt, body.latest.receipt]) {
        const verdict = t.verifyWitnessReceipt(receipt, [vkey]);
        assert.equal(verdict.ok, true);
        const entries = await (await fetch(`${url}/v1/entries?start=${receipt.index}&end=${receipt.index + 1}`)).json();
        assert.deepEqual(entries.entries[0], receipt.entry, `entry ${receipt.index} is unchanged after the restart`);
      }
      const checkpoint = t.parseCheckpoint(t.openNote(body.checkpoint, [vkey]).body);
      seen.set(checkpoint.size, checkpoint);
    }
    for (const checkpoint of seen.values()) {
      assert.ok(checkpoint.size <= current.size);
      if (checkpoint.size === current.size) {
        assert.equal(t.encodeBase64(checkpoint.root), t.encodeBase64(current.root));
        continue;
      }
      const proof = (await (await fetch(`${url}/v1/proofs/consistency?from=${checkpoint.size}&to=${current.size}`)).json()).proof.map(t.decodeBase64);
      assert.equal(t.verifyConsistency(checkpoint.size, current.size, checkpoint.root, current.root, proof), true, `checkpoint ${checkpoint.size} is consistent with ${current.size}`);
    }

    // Clients carry on from the witnessed latest.
    for (const [n, h] of histories.entries()) {
      const latest = (await (await fetch(`${url}/v1/histories/${h.historyId}`)).json()).latest;
      const position = latest === null ? -1 : latest.head.position;
      if (position + 1 >= h.heads.length) continue;
      const next = position < 0 ? statements[n][0] : await h.statement(position + 1, position);
      assert.equal((await post(url, `/v1/histories/${h.historyId}/heads`, next)).status, 201);
    }
    server.child.kill("SIGTERM");
    const stopped = await server.exited;
    if (process.platform === "win32") {
      assert.equal(stopped.signal, "SIGTERM", "Windows: SIGTERM is TerminateProcess (no graceful shutdown to observe)");
    } else {
      assert.equal(stopped.code, 0, "graceful shutdown exits 0");
      assert.ok(server.logs.some((line) => line.msg === "stopped"));
    }
  } finally {
    cleanup();
  }
});
