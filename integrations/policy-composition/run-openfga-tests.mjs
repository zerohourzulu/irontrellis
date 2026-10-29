#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
const binary = process.env.OPENFGA_BINARY;
if (!binary || resolve(binary) !== binary)
  throw Error(
    "Set OPENFGA_BINARY to the absolute path of your verified OpenFGA 1.21.0 binary.",
  );
const version = spawnSync(binary, ["version"], { encoding: "utf8" });
if (
  version.status !== 0 ||
  !/v1\.21\.0\b/.test(version.stdout + version.stderr)
)
  throw Error("These tests require OpenFGA 1.21.0.");
const port = () =>
  new Promise((accept, reject) => {
    const s = createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => accept(p));
    });
  });
const http = await port();
let grpc = await port();
while (grpc === http) grpc = await port();
const endpoint = `http://127.0.0.1:${http}`;
const server = spawn(
  binary,
  [
    "run",
    "--datastore-engine",
    "memory",
    "--http-addr",
    `127.0.0.1:${http}`,
    "--grpc-addr",
    `127.0.0.1:${grpc}`,
    "--playground-enabled=false",
    "--metrics-enabled=false",
    "--log-level",
    "error",
  ],
  {
    env: { PATH: process.env.PATH, LANG: "C.UTF-8" },
    stdio: ["ignore", "ignore", "inherit"],
  },
);
try {
  let ready = false;
  for (let attempt = 0; attempt < 50; attempt++) {
    if (server.exitCode !== null)
      throw Error("Disposable OpenFGA exited before readiness.");
    try {
      if (
        (
          await fetch(`${endpoint}/healthz`, {
            signal: AbortSignal.timeout(500),
          })
        ).ok
      ) {
        ready = true;
        break;
      }
    } catch {}
    await new Promise((done) => setTimeout(done, 100));
  }
  if (!ready) throw Error("Disposable OpenFGA did not become ready.");
  const result = spawnSync(
    process.execPath,
    [
      "--test",
      fileURLToPath(new URL("./tests/openfga.test.mjs", import.meta.url)),
    ],
    {
      env: { ...process.env, IRONTRELLIS_TEST_FGA_URL: endpoint },
      stdio: "inherit",
      timeout: 90000,
    },
  );
  if (result.error || result.status !== 0) process.exitCode = 1;
} finally {
  if (server.exitCode === null) {
    const closed = new Promise((done) => server.once("exit", done));
    server.kill("SIGTERM");
    const timer = setTimeout(() => server.kill("SIGKILL"), 3000);
    await closed;
    clearTimeout(timer);
  }
}
