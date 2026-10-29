/**
 * `irontrellis` entry point: global options, command dispatch, help, and the
 * one place errors are turned into `error: <CODE> — <sentence>` (exit 1) or,
 * with `--json`, `{ "error": { "code", "message", "detail"?, "context"? } }`
 * (`detail`: the engine's message when the sentence does not already carry it;
 * `context`: the engine's machine-readable detail, e.g. the lock path).
 */
import { formatOptions, parseArgs, type OptionSpec, type Parsed } from "./args.ts";
import { COMMANDS, type Command, type Outcome } from "./commands.ts";
import { demo } from "./demo.ts";
import { CliError, codeOf, parseTime, type Global } from "./history.ts";
import { describe } from "./messages.ts";
import { Lines, TAGLINE, VERSION, dim, header, style, toJson, type Style } from "./output.ts";

export { COMMANDS, demo };

const GLOBAL_OPTIONS: readonly OptionSpec[] = [
  { name: "history", kind: "string", help: "the history file (or IRONTRELLIS_HISTORY)", value: "<file>" },
  { name: "owner", kind: "string", help: "owner id (init: default owner; otherwise read from the history)", value: "<id>", identifier: true },
  { name: "controller", kind: "string", help: "controller id (init: default the owner; otherwise read from the history's agents)", value: "<id>", identifier: true },
  { name: "at", kind: "string", help: "evaluation time for questions (default: now)", value: "<ms|ISO>" },
  { name: "json", kind: "boolean", help: "print one JSON document (bigints as decimal strings)" },
  { name: "color", kind: "boolean", help: "--no-color: no ANSI colour (so does NO_COLOR; FORCE_COLOR gives colour without a terminal)" },
  { name: "help", kind: "boolean", help: "show help" },
  { name: "version", kind: "boolean", help: "print the version" },
];

const ALL: readonly Command[] = Object.freeze([...COMMANDS, demo]);
const VALUED_GLOBALS = new Set(GLOBAL_OPTIONS.filter((o) => o.kind !== "boolean").map((o) => `--${o.name}`));

/**
 * Locate the command words in argv: the first token that is neither an option
 * nor the value of a valued global option, plus the adjacent next token when
 * the two together name a command (`agent create`, `session admit` …).
 */
function locate(argv: readonly string[]): { command: Command | undefined; name: string; rest: string[] } {
  let index = 0;
  while (index < argv.length) {
    const token = argv[index]!;
    if (token === "--") break;
    if (token.startsWith("--")) { index += VALUED_GLOBALS.has(token) ? 2 : 1; continue; }
    if (token.startsWith("-")) { index += 1; continue; }
    break;
  }
  const first = argv[index], second = argv[index + 1];
  if (first === undefined || first === "--") return { command: undefined, name: "", rest: [...argv] };
  const two = second !== undefined && !second.startsWith("-") ? ALL.find((c) => c.name === `${first} ${second}`) : undefined;
  const command = two ?? ALL.find((c) => c.name === first);
  const width = two === undefined ? 1 : 2;
  // Removing the command words must not make an option before them and a word after them neighbours: a bare flag before
  // the command is given its value explicitly, so it cannot take a following `true`/`false` as one (`--json status false`
  // is then the stray argument `false`, a usage error, never `--json false`). Found by fuzz/targets/cli-args.mjs.
  const before = argv.slice(0, index).map((token, at) => (token.startsWith("--") && token !== "--" && !token.includes("=") && !VALUED_GLOBALS.has(token)
    && !token.startsWith("--no-") && !(at > 0 && VALUED_GLOBALS.has(argv[at - 1]!)) ? `${token}=true` : token));
  return { command, name: argv.slice(index, index + width).join(" "), rest: [...before, ...argv.slice(index + width)] };
}

const GROUPS: readonly (readonly [string, readonly string[]])[] = [
  ["history", ["init", "status", "verify", "repin", "export", "export verify", "migrate", "capacity", "anchor"]],
  ["checkpoints", ["checkpoint create", "checkpoint list", "checkpoint verify"]],
  ["owner keys", ["owner status", "owner commit-next-key", "owner rotate-key", "owner export-key-events"]],
  ["key custody", ["signer test", "signer ref", "signer list", "signer to-ssh", "doctor"]],
  ["remote witnesses", ["witness add", "witness status", "witness sync", "witness remove"]],
  ["structure", ["agent create", "agent terminate", "role create", "appoint", "unappoint", "succession declare", "succeed", "session admit", "epoch advance"]],
  ["authority", ["grant", "delegate", "prohibit", "revoke"]],
  ["budgets", ["budget declare", "budget update", "budget close", "budget show", "budget headroom"]],
  ["counterparties", ["counterparty register", "counterparty rotate", "counterparty retire", "counterparty receipts"]],
  ["investigation duties", ["duty describe", "duty activate", "duty dispose", "duty contest", "duty inspect"]],
  ["questions", ["authorize", "why", "responsible", "survives", "handover"]],
  ["start here", ["demo"]],
];

export function mainHelp(s: Style): string {
  const width = Math.max(...ALL.map((c) => c.name.length));
  const lines = [header(s), "", "usage: irontrellis <command> [options]", "       irontrellis <command> --help", ""];
  for (const [title, names] of GROUPS) {
    lines.push(dim(s, title));
    for (const name of names) lines.push(`  ${name.padEnd(width)}  ${ALL.find((c) => c.name === name)!.summary}`);
    lines.push("");
  }
  lines.push(dim(s, "global options"), formatOptions(GLOBAL_OPTIONS), "");
  lines.push(dim(s, "Every command reads or writes one history file. Questions read a captured history; they execute nothing."));
  return `${lines.join("\n")}\n`;
}

export function commandHelp(s: Style, c: Command): string {
  const lines = [header(s), "", `usage: irontrellis ${c.usage}`, "", `  ${c.summary}`, ""];
  if (c.options.length > 0) lines.push(dim(s, "options"), formatOptions(c.options), "");
  lines.push(dim(s, "global options"), formatOptions(GLOBAL_OPTIONS));
  return `${lines.join("\n")}\n`;
}

const globalOf = (p: Parsed): Global => ({
  history: p.options.get("history") as string | undefined,
  ...(p.options.has("owner") ? { owner: p.options.get("owner") as string } : {}),
  ...(p.options.has("controller") ? { controller: p.options.get("controller") as string } : {}),
  ...(p.options.has("at") ? { at: parseTime(p.options.get("at") as string, "at") } : {}),
  json: p.options.get("json") === true,
});

const wantsJson = (argv: readonly string[]): boolean => argv.includes("--json") || argv.includes("--json=true");

/** Run one invocation; returns the exit code. Output goes to stdout, errors to stderr (or stdout as JSON). */
export async function main(argv: readonly string[], io: { stdout: (text: string) => void; stderr: (text: string) => void } = { stdout: (t) => process.stdout.write(t), stderr: (t) => process.stderr.write(t) }): Promise<number> {
  // --no-color before the command is parsed, so help and errors honour it too (the parser accepts it as the global "color").
  const s = style(undefined, argv.includes("--no-color") || argv.includes("--color=false") ? false : undefined);
  const json = wantsJson(argv);
  try {
    if (argv.length === 0 || argv[0] === "--help" || argv[0] === "help") { io.stdout(mainHelp(s)); return 0; }
    if (argv[0] === "--version" || argv[0] === "version") { io.stdout(json ? toJson({ irontrellis: VERSION }) : `irontrellis ${VERSION}\n`); return 0; }
    const { command, name, rest } = locate(argv);
    if (command === undefined) throw new CliError("UNKNOWN_COMMAND", name === "" ? "no command given" : `unknown command "${name}"`);
    if (rest.includes("--help") || rest.includes("--help=true")) { io.stdout(commandHelp(s, command)); return 0; }
    const parsed = parseArgs(rest, [...GLOBAL_OPTIONS, ...command.options]);
    const g = globalOf(parsed);
    const outcome: Outcome = await command.run(parsed, g);
    if (g.json) {
      io.stdout(outcome.raw ?? toJson(outcome.json));
    } else {
      const out = new Lines();
      if (outcome.raw === undefined) { out.add(header(s)); out.blank(); }
      outcome.render(s, out);
      io.stdout(out.text());
    }
    return outcome.exit ?? 0;
  } catch (error) {
    const { code, detail, context } = codeOf(error);
    const message = code === "USAGE" || code === "UNKNOWN_COMMAND" ? detail : describe(code, detail, context);
    // The engine's own message is shown too when the sentence is the code's generic one (a specific sentence already says what was found).
    const extra = detail !== code && detail !== message && message === describe(code);
    if (json) io.stdout(toJson({ error: { code, message, ...(extra ? { detail } : {}), ...(context === undefined ? {} : { context }) } }));
    else {
      io.stderr(`error: ${s.strong(code)} — ${message}\n`);
      if (extra) io.stderr(`  ${dim(s, detail)}\n`);
      if (code === "USAGE" || code === "UNKNOWN_COMMAND") io.stderr(`  ${dim(s, "run irontrellis --help for the command list")}\n`);
    }
    // doctor: 0 without a FAIL, 1 with one, 2 on a usage error (a missing history name included).
    if ((code === "USAGE" || code === "HISTORY_REQUIRED") && locate(argv).command?.name === "doctor") return 2;
    // The event is recorded, only the pin attestation after it failed: exit 4, never the "nothing written" exit 1.
    if (code === "WRITTEN_UNATTESTED") return 4;
    return 1;
  }
}

export { TAGLINE, VERSION };
