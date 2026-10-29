// The control-command tripwire (rule 2) against the evasions the block 3 review reported (L1,
// /tmp/review-b3/poc/hook-bypass.mjs): package specs with a version, a package's bin target run by node, command
// substitution, quote splicing, cmd carets, PowerShell backticks, xargs and the usual prefixes. The rule stays a
// tripwire, not a boundary (docs/SECURITY.md "The hook's tripwire"): the gaps it cannot see are listed at the end.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { commandSpellings, controlCommand, protection, validateConfig } from "../dist/index.js";

test("review corpus: every writing command of the block 3 review is flagged (the sanity cases stay flagged)", () => {
  const cases = [
    // The review's sanity cases.
    ["irontrellis grant --actor a", "irontrellis grant"],
    ["FOO=1 irontrellis grant", "irontrellis grant"],
    ["sh -c 'irontrellis grant x'", "irontrellis grant"],
    ["IronTrellis.CMD grant", "irontrellis grant"],
    ["C:\\tools\\irontrellis.cmd grant", "irontrellis grant"],
    ["irontrellis -- grant", "irontrellis grant"],
    ["time irontrellis grant", "irontrellis grant"],
    ["IRONTRELLIS grant", "irontrellis grant"],
    ["irontrellis\tgrant", "irontrellis grant"],
    ["irontrellis\u00a0grant", "irontrellis grant"],
    // The review's bypasses.
    ["npx irontrellis@next grant --actor a", "irontrellis grant"],
    ["pnpm dlx irontrellis@1.0.0-rc.1 revoke g:1", "irontrellis revoke"],
    ["node node_modules/irontrellis/dist/cli.js grant", "irontrellis grant"],
    ["node $(command -v irontrellis) grant", "irontrellis grant"],
    ["\"$(which irontrellis)\" owner rotate-key", "irontrellis owner"],
    ["irontrel''lis grant", "irontrellis grant"],
    ["irontrellis gr''ant", "irontrellis grant"],
    ["irontrellis 'gr'ant", "irontrellis grant"],
    ["iron\"\"trellis revoke x", "irontrellis revoke"],
    ["iron^trellis grant", "irontrellis grant"],
    ["irontrellis gr^ant", "irontrellis grant"],
    ["iron`trellis grant", "irontrellis grant"],
    ["cmd /c \"irontrellis^ grant\"", "irontrellis grant"],
    ["env irontrellis\\ grant", "irontrellis grant"],
    ["echo grant | xargs irontrellis", "irontrellis (arguments from xargs)"],
    ["irontrellis $'grant'", "irontrellis grant"],
    ["irontrellis \"gr\"ant", "irontrellis grant"],
  ];
  for (const [command, expected] of cases) assert.equal(controlCommand(command), expected, command);
});

test("package runners with a version or tag, a scope, and a package's bin target run by node", () => {
  const cases = [
    ["yarn dlx irontrellis@1 grant g --to a", "irontrellis grant"],
    ["bunx irontrellis@latest delegate d1", "irontrellis delegate"],
    ["npm exec irontrellis@next -- revoke g1", "irontrellis revoke"],
    ["npx --yes irontrellis@1.0.0-rc.1 owner rotate-key", "irontrellis owner"],
    ["pnpm dlx @ramex-labs/irontrellis-hooks@1.0.0-rc.1 init --allow run-shell", "irontrellis-hook init"],
    ["npx @ramex-labs/irontrellis-hooks session release --all", "irontrellis-hook session"],
    ["npx -p @ramex-labs/irontrellis-mcp-gateway irontrellis-mcp-ops revoke --config x", "irontrellis-mcp-ops revoke"],
    ["node ./node_modules/irontrellis/dist/cli.js anchor", "irontrellis anchor"],
    ["node /usr/lib/node_modules/irontrellis/bin/irontrellis.mjs epoch advance a", "irontrellis epoch"],
    ["node C:\\repo\\node_modules\\@ramex-labs\\irontrellis-hooks\\dist\\cli.js init", "irontrellis-hook init"],
    ["node node_modules/@ramex-labs/irontrellis-mcp-gateway/dist/ops-cli.js revoke x", "irontrellis-mcp-ops revoke"],
    ["node packages/cli/dist/cli.js grant g", "irontrellis grant"],
    ["node ~/.npm/_npx/abc/node_modules/irontrellis@1.0.0/dist/cli.js grant", "irontrellis grant"],
  ];
  for (const [command, expected] of cases) assert.equal(controlCommand(command), expected, command);
});

test("prefixes: xargs, env, command, exec, nice, timeout, sudo (and their options) before the binary", () => {
  for (const prefix of ["env", "env -i FOO=1", "command", "exec", "nice", "nice -n 10", "timeout 5", "timeout -s KILL 30s", "sudo", "sudo -u owner", "sudo -E env", "xargs", "xargs -0 -n1", "nohup", "stdbuf -oL"]) {
    assert.equal(controlCommand(`${prefix} irontrellis grant g --to a`), "irontrellis grant", prefix);
  }
  assert.equal(controlCommand("printf 'revoke\\ng1' | xargs irontrellis"), "irontrellis (arguments from xargs)");
  assert.equal(controlCommand("cat subcommands.txt | xargs -n2 irontrellis-hook"), "irontrellis-hook (arguments from xargs)");
  assert.equal(controlCommand("find . -name h.jsonl -exec irontrellis revoke g1 \\;"), "irontrellis revoke");
});

test("reading commands and unrelated mentions stay allowed through the same wrappers and normalizations", () => {
  for (const command of [
    "npx irontrellis@next verify --json", "pnpm dlx irontrellis@1.0.0-rc.2 status --json", "node node_modules/irontrellis/dist/cli.js why --actor a --action b --resource c",
    "ls | xargs irontrellis verify", "echo h.jsonl | xargs -n1 irontrellis verify --history", "sudo -u owner irontrellis verify",
    "cat node_modules/irontrellis/dist/cli.js | grep grant", "node node_modules/irontrellis/dist/other.js grant", "git grant-access; echo irontrellis",
    "npm run grant", "irontrellis-docs.cmd grant", "grep -r 'irontrellis' src/ | grep -c revoke", "echo \"irontrellis\" && echo grant",
    "irontrellis --history h why --actor a --action b --resource c", "npx irontrellis-helper@1 grant",
  ]) assert.equal(controlCommand(command), undefined, command);
});

test("commandSpellings: as written, POSIX-normalized, Windows-normalized", () => {
  const spellings = commandSpellings("iron''trel\\lis $'gr'\"a\"nt $(which x) `y`");
  assert.ok(spellings.includes("iron''trel\\lis $'gr'\"a\"nt $(which x) `y`"));
  assert.ok(spellings.some((s) => s.startsWith("irontrellis grant  which x   y ")), JSON.stringify(spellings));
  assert.ok(commandSpellings("iron^trel`lis \"gr\"ant").includes("irontrellis grant"));
  assert.deepEqual(commandSpellings("irontrellis verify"), ["irontrellis verify"]);
});

test("rule 1 sees protected paths through quote splicing too", () => {
  const config = validateConfig({ history: "/s/h.jsonl", owner: "o", agentId: "a", policy: { sideEffecting: [], readOnly: [] } }, "/p/irontrellis-hook.json");
  for (const command of ["cat ~/.iron''trellis/history.jsonl", "cat /p/.iron\"\"trellis/x", "type C:\\Users\\me\\.iron^trellis\\h.jsonl", "cat /s/h.jsonl.owner-k''ey.json", "cat /s/h.js''onl"]) {
    assert.equal(protection(config, "Bash", { command }, "/p")?.code, "PROTECTED_PATH", command);
  }
  assert.equal(protection(config, "Bash", { command: "cat 'README.md'" }, "/p"), undefined);
});

// Known gaps, kept visible: a tripwire matches text, and these need a shell to evaluate. The boundary is owner-key
// custody (a separate OS user or a KMS signer) and the protected-path checks, not this rule (docs/SECURITY.md).
test("known gaps of the tripwire (documented, not claimed)", () => {
  for (const command of ["& (\"iron\"+\"trellis\") grant", "sh ./script-written-earlier.sh", "$(printf 'iron%s' trellis) grant"]) {
    assert.equal(controlCommand(command), undefined, command);
  }
  // Closed since the block 4 review (L5): a control program assigned to a variable or an alias, then a writing subcommand.
  for (const command of ["i=irontrellis; $i grant", "alias it=irontrellis; it grant", "export B=/usr/local/bin/irontrellis-hook; $B install"]) {
    assert.match(controlCommand(command) ?? "", /through a variable or alias/, command);
  }
});

test("post5-12 (independent review A, RA-02): every irontrellis command that writes is a control command; the CLI's command list and this table stay in step", () => {
  // The CLI's own list (packages/cli/src/cli.ts GROUPS): a new command must be classified here.
  const source = readFileSync(new URL("../../cli/src/cli.ts", import.meta.url), "utf8");
  const groups = /const GROUPS[^=]*= \[([\s\S]*?)\n\];/.exec(source)[1];
  const listed = [...groups.matchAll(/\["[^"]+", \[([^\]]*)\]\]/g)].flatMap((m) => [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]));
  const WRITES = ["init", "repin", "migrate", "anchor", "checkpoint create", "owner commit-next-key", "owner rotate-key", "signer ref", "witness add", "witness sync", "witness remove",
    "agent create", "agent terminate", "role create", "appoint", "unappoint", "succession declare", "succeed", "session admit", "epoch advance", "grant", "delegate", "prohibit", "revoke",
    "budget declare", "budget update", "budget close", "counterparty register", "counterparty rotate", "counterparty retire", "duty activate", "duty dispose", "duty contest"];
  const READS = ["status", "verify", "export", "export verify", "capacity", "checkpoint list", "checkpoint verify", "doctor", "budget show", "budget headroom", "counterparty receipts",
    "duty describe", "duty inspect", "authorize", "why", "responsible", "survives", "handover", "demo"];
  // Reading commands of a group listed whole (owner, signer, witness): refused too, which fails safe.
  const OVER = ["owner status", "owner export-key-events", "signer test", "signer list", "signer to-ssh", "witness status"];
  assert.deepEqual(listed.filter((c) => ![...WRITES, ...READS, ...OVER].includes(c)), [], "a CLI command that is not classified here");
  for (const c of [...WRITES, ...OVER]) assert.notEqual(controlCommand(`irontrellis ${c} --history h.jsonl`), undefined, c);
  for (const c of READS) assert.equal(controlCommand(`irontrellis ${c} --history h.jsonl`), undefined, c);
  // The flag that makes verify write, in both spellings, and the options between a group and its command.
  assert.equal(controlCommand("irontrellis verify --history h.jsonl --accept-rollback"), "irontrellis verify --accept-rollback");
  assert.equal(controlCommand("irontrellis verify --accept-rollback=true"), "irontrellis verify --accept-rollback");
  assert.equal(controlCommand("irontrellis budget --history h.jsonl declare --name b"), "irontrellis budget declare");
  assert.equal(controlCommand("i=irontrellis; $i counterparty register x"), "irontrellis counterparty register (through a variable or alias)");
});

