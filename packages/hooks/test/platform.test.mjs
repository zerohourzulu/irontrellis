// Windows readiness of the hook (docs/PLATFORMS.md): the control-command tripwire sees the spellings a Windows shell
// runs (npm's .cmd and .ps1 shims, backslash paths, any case), `~\` paths, and a config's history path that is
// rooted but not drive-qualified resolves against the project's drive.
import { test } from "node:test";
import assert from "node:assert/strict";
import { controlCommand, validateConfig } from "../dist/index.js";

async function asPlatform(value, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { ...descriptor, value });
  try { return await fn(); } finally { Object.defineProperty(process, "platform", descriptor); }
}

test("control commands in their Windows spellings: .cmd/.ps1/.bat/.exe shims, backslash paths, any case, PowerShell's call operator", () => {
  const cases = [
    ["irontrellis.cmd grant g --to a", "irontrellis grant"],
    ["irontrellis.ps1 revoke g1", "irontrellis revoke"],
    ["IronTrellis.CMD owner rotate-key", "irontrellis owner"],
    ["C:\\Users\\me\\AppData\\Roaming\\npm\\irontrellis.cmd delegate d1", "irontrellis delegate"],
    ["\"C:\\Program Files\\nodejs\\irontrellis-hook.cmd\" init --allow run-shell", "irontrellis-hook init"],
    ["& 'C:\\tools\\irontrellis-mcp-ops.ps1' revoke --config x", "irontrellis-mcp-ops revoke"],
    ["node C:\\repo\\node_modules\\irontrellis\\bin\\irontrellis.mjs epoch advance a", "irontrellis epoch"],
    ["cmd /c irontrellis.bat anchor", "irontrellis anchor"],
  ];
  for (const [command, expected] of cases) assert.equal(controlCommand(command), expected, command);
  assert.equal(controlCommand("C:\\tools\\irontrellis.cmd verify --json"), undefined, "reading commands stay allowed");
  assert.equal(controlCommand("irontrellis-docs.cmd grant"), undefined, "another program");
});

test("a config's history path: drive-qualified is kept; a rooted path without a drive resolves against the project's drive on win32", async () => {
  const raw = { owner: "o", agentId: "a", policy: { sideEffecting: [], readOnly: [] } };
  assert.equal(validateConfig({ ...raw, history: "/state/h.jsonl" }, "/p/irontrellis-hook.json").history, "/state/h.jsonl");
  assert.equal(validateConfig({ ...raw, history: "state/h.jsonl" }, "/p/irontrellis-hook.json").history, "/p/state/h.jsonl");
  await asPlatform("win32", () => {
    // (path.resolve stays POSIX on this host; what matters is that the rooted spelling is no longer taken as final.)
    assert.equal(validateConfig({ ...raw, history: "C:\\state\\h.jsonl" }, "/p/irontrellis-hook.json").history, "C:\\state\\h.jsonl");
    assert.notEqual(validateConfig({ ...raw, history: "\\state\\h.jsonl" }, "/p/irontrellis-hook.json").history, "\\state\\h.jsonl");
  });
});
