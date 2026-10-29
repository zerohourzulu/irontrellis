#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { createAgent, fakeModel, AIMessage } from "langchain";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { evidenceTool } from "./tool.mjs";
const config = process.argv[2];
if (!config) throw Error("Pass the private demo gateway.json path.");
const client = new Client(
  { name: "irontrellis-langchain-example", version: "1" },
  { versionNegotiation: { mode: { pin: "2026-07-28" } } },
);
try {
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [
        fileURLToPath(
          new URL(import.meta.resolve('@ramex-labs/irontrellis-protected-evidence-mcp/server')),
        ),
        "--config",
        config,
      ],
      stderr: "pipe",
    }),
  );
  // The actual LangChain agent executes the tool. Only the model response is
  // scripted, so this example needs no account, tracing service or model call.
  const model = fakeModel()
    .respondWithTools([
      { name: "collect_evidence", args: { resource: "incident:42" } },
    ])
    .respond(
      new AIMessage(
        "Report the tool result without treating collection as proof.",
      ),
    );
  const agent = createAgent({
    model,
    tools: [
      evidenceTool(client, {
        operationId: "langchain:collection",
        resource: "incident:42",
      }),
    ],
  });
  const result = await agent.invoke(
    {
      messages: [
        { role: "user", content: "Collect the selected synthetic evidence." },
      ],
    },
    { recursionLimit: 6 },
  );
  for (const message of result.messages)
    if (message.getType() === "tool") console.log(message.content);
} finally {
  await client.close();
}
