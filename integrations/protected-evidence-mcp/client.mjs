#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
const config = process.argv[2];
if (!config) throw Error("Pass the private gateway.json configuration path.");
const client = new Client(
  { name: "irontrellis-example-client", version: JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version },
  { versionNegotiation: { mode: { pin: "2026-07-28" } } },
);
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [
    fileURLToPath(new URL("./server.mjs", import.meta.url)),
    "--config",
    config,
  ],
  stderr: "pipe",
});
try {
  await client.connect(transport);
  console.log(
    "Tools:",
    (await client.listTools()).tools.map((t) => t.name).join(", "),
  );
  for (let attempt = 0; attempt < 2; attempt++) {
    const result = await client.callTool({
      name: "irontrellis_collect_evidence",
      arguments: { operationId: "example:collection", resource: "incident:42" },
    });
    console.log(
      JSON.stringify(result.structuredContent ?? result.content, null, 2),
    );
  }
} finally {
  await client.close();
}
