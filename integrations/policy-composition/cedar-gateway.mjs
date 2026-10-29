#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { loadGateway } from '@ramex-labs/irontrellis-protected-evidence-mcp/config';
import { serveGateway } from '@ramex-labs/irontrellis-protected-evidence-mcp/server';
import { cedarPolicy } from "./cedar.mjs";
import { policyJournal } from "./journal.mjs";
// All three paths are chosen by the trusted launcher, never by an MCP caller.
try {
  if (process.argv.length !== 5)
    throw Error(
      "Use: cedar-gateway.mjs gateway.json policy.cedar private-audit.jsonl",
    );
  const additionalPolicy = cedarPolicy(
    readFileSync(process.argv[3], "utf8"),
    policyJournal(process.argv[4]),
  );
  serveGateway(loadGateway(process.argv[2], { additionalPolicy }));
} catch {
  process.stderr.write("POLICY_GATEWAY_CONFIGURATION_UNAVAILABLE\n");
  process.exitCode = 2;
}
