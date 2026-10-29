#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
const [socketPath, history, key, source, code] = process.argv.slice(2);
const denied = (fn) => {
  try {
    fn();
    return false;
  } catch (error) {
    return ["EACCES", "EPERM"].includes(error.code);
  }
};
const status = readFileSync("/proc/self/status", "utf8");
const isolation = {
  uid: process.getuid(),
  noNewPrivileges: /^NoNewPrivs:\s+1$/m.test(status),
  noEffectiveCapabilities: /^CapEff:\s+0+$/m.test(status),
  sourceReadDenied: denied(() => readFileSync(source)),
  sourceWriteDenied: denied(() => writeFileSync(source, "unsafe replacement")),
  historyReadDenied: denied(() => readFileSync(history)),
  historyWriteDenied: denied(() =>
    writeFileSync(history, "unsafe replacement"),
  ),
  keyReadDenied: denied(() => readFileSync(key)),
  codeWriteDenied: denied(() => writeFileSync(code, "unsafe replacement")),
};
const client = new Client(
  { name: "unprivileged-linux-agent", version: "1" },
  { versionNegotiation: { mode: { pin: "2026-07-28" } } },
);
try {
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [
        fileURLToPath(new URL("./socket-bridge.mjs", import.meta.url)),
        socketPath,
      ],
      stderr: "pipe",
    }),
  );
  console.log(JSON.stringify({ ready: true, isolation }));
  for await (const line of createInterface({ input: process.stdin })) {
    const { operationId } = JSON.parse(line);
    const answer = await client.callTool({
      name: "irontrellis_collect_evidence",
      arguments: { operationId, resource: "incident:42" },
    });
    console.log(JSON.stringify(answer.structuredContent));
  }
} finally {
  await client.close();
}
