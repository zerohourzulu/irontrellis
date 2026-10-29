/**
 * Protective rules that no configuration can turn off. They run before the
 * policy, for every tool event, and answer deny:
 *
 *   1. protected paths: any tool call whose input references the IronTrellis
 *      history (and its pin, lock, anchors, witness state and owner key, which
 *      all share the history path as a prefix), the session-key directory, the
 *      handover directory or the hook config, or contains the strings
 *      `.irontrellis`, `irontrellis-hook.json`, `.owner-key.json`, `.owner-key.`
 *      (the pending and retired key files of an owner key rotation),
 *      `.owner-next-key.` (the committed next owner key and its pending file,
 *      wherever the operator keeps a copy),
 *      `.witness.json` (the remote witness state beside the history),
 *      `.rotation.pending.` (the prepared record of a two-phase owner key rotation),
 *      `IRONTRELLIS_WITNESS_POLICY` or `irontrellis-witness-policy` (the
 *      operator's out-of-band witness policy, its variable and the file name the
 *      docs recommend), or the policy file the hook's own
 *      `IRONTRELLIS_WITNESS_POLICY` names. For file-editing tools
 *      (Write, Edit, MultiEdit, NotebookEdit, Delete) the target path is
 *      checked, for Codex apply_patch the files the patch names, and for every
 *      other tool (Bash, Read, Grep, MCP tools, …) every string anywhere in the
 *      input. Values, and the words of a shell command, are also resolved
 *      against the event's cwd and through symlinks.
 *      Key references (docs/CUSTODY.md) are covered by the same names
 *      (`<history>.owner-key.json` may be one) and by `.owner-key-ref.`,
 *      `.owner-next-key-ref.` (the file names `irontrellis signer ref` docs
 *      recommend) and the reference version literals; when the history's owner
 *      or next key is held by a signer, the signer's own paths are protected
 *      too: the ssh-agent socket, the command signer's program and
 *      arguments that are paths, and Vault Transit's token file (or
 *      ~/.vault-token) and CA file.
 *   2. control commands: a shell command that invokes `irontrellis`,
 *      `irontrellis-hook` or `irontrellis-mcp-ops` with a writing subcommand
 *      (every `irontrellis owner …` subcommand among them: `status`,
 *      `commit-next-key`, `rotate-key`; `signer` too), and, when an owner or
 *      next key of the history is held by an ssh-agent, any `ssh-add` (it can
 *      remove the owner key from the agent, or list and re-add keys); when
 *      one is held by Vault Transit, any `vault` (it can sign with the key).
 *
 * These are tripwires, not a boundary. A shell command can spell a path in
 * ways no string match sees (variables, globs, encodings, a script written
 * earlier). On the same OS user nothing stops the agent from reading the
 * owner key by such means; the real boundary is a separate OS user (or a KMS
 * signer) for the owner key. See README "Limitations".
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { retiredOwnerKeyFilesFor } from "@ramex-labs/irontrellis";
import type { HookConfig } from "./config.ts";
import { canonicalProject, choiceFile, defaultStateHome, handoversDir, physicalPath, readRegularFile, readRuntimePin, realpathLoose, sessionsDir } from "./paths.ts";

// ".owner-key." also covers the pending and retired key files an owner key rotation writes (`<history>.owner-key.pending.json`, `<history>.owner-key.<id>.retired.json`);
// ".owner-next-key." the committed next owner key (pre-rotation: `<history>.owner-next-key.json`, its pending file, and a copy under that name anywhere);
// ".witness.json" the remote witness state (`<history>.witness.json`: policy, remembered checkpoints, queued head statements);
// ".rotation.pending." the prepared-rotation record of a two-phase owner key rotation (`<history>.rotation.pending.json`);
// "IRONTRELLIS_WITNESS_POLICY" / "irontrellis-witness-policy" the operator's out-of-band minimum witness policy (the variable
// every store open reads, and the file name docs/reference/witness-policy.md §5.4 recommends for it).
// ".owner-key-ref." / ".owner-next-key-ref." and the reference version literals: key references kept away from the history
// (docs/CUSTODY.md recommends those names for `irontrellis signer ref --out`); "irontrellis-sign-request" the command
// signer's request (a script that forges one to a signing program).
export const PROTECTED_STRINGS: readonly string[] = Object.freeze([
  ".irontrellis", "irontrellis-hook.json", ".owner-key.json", ".owner-key.", ".owner-next-key.", ".witness.json", ".rotation.pending.", "IRONTRELLIS_WITNESS_POLICY", "irontrellis-witness-policy",
  ".owner-key-ref.", ".owner-next-key-ref.", "irontrellis-owner-key-ref", "irontrellis-owner-next-key-ref", "irontrellis-sign-request",
  // The per-user install-route choice (route.ts): its file name and its version literal.
  "route-choices.json", "irontrellis-route-choice",
]);
export const CONTROL_BINARIES: readonly string[] = Object.freeze(["irontrellis", "irontrellis-hook", "irontrellis-mcp-ops"]);
export const WRITING_SUBCOMMANDS: readonly string[] = Object.freeze([
  "grant", "delegate", "prohibit", "revoke", "agent", "role", "appoint", "unappoint", "succession", "succeed", "session", "epoch", "init", "migrate", "anchor", "install",
  "repin", "owner", "witness", "signer", "choose", "pin-runtime",
]);
/**
 * The writing commands of a group that also has reading ones (independent review A, RA-02): `checkpoint create` writes,
 * `checkpoint list` does not. With WRITING_SUBCOMMANDS and WRITING_FLAGS, every `irontrellis` command that writes a history,
 * its pin or its side files (packages/cli/src/cli.ts; a test keeps the two in step).
 */
export const WRITING_PAIRS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  checkpoint: ["create"], budget: ["declare", "update", "close"], counterparty: ["register", "rotate", "retire"], duty: ["activate", "dispose", "contest"],
});
/** A reading command that writes with a flag: `verify --accept-rollback` re-pins the history (RA-02). */
export const WRITING_FLAGS: Readonly<Record<string, readonly string[]>> = Object.freeze({ verify: ["--accept-rollback"] });
/** The writing command among `words` (a control binary's arguments, unquoted), or undefined. */
function writingIn(words: readonly string[]): string | undefined {
  const sub = words.find((t) => WRITING_SUBCOMMANDS.includes(t));
  if (sub !== undefined) return sub;
  for (const [group, writes] of Object.entries(WRITING_PAIRS)) {
    const at = words.indexOf(group);
    const w = at < 0 ? undefined : words.slice(at + 1).find((t) => writes.includes(t));
    if (w !== undefined) return `${group} ${w}`;
  }
  for (const [command, flags] of Object.entries(WRITING_FLAGS)) {
    const f = words.includes(command) ? words.find((t) => flags.some((flag) => t === flag || t.startsWith(`${flag}=`))) : undefined;
    if (f !== undefined) return `${command} ${f.split("=")[0]}`;
  }
  return undefined;
}
/** Run against the ssh-agent that holds an owner or next key: `ssh-add -D` / `-d` would take the owner key away, `-L` lists it. */
export const CUSTODY_BINARIES: readonly string[] = Object.freeze(["ssh-add"]);
export const CUSTODY_REASON = "protected: the owner key of this history is held by an ssh-agent; ssh-add is for the operator, not the agent (and so are ssh-keygen -Y sign and the agent socket)";
/** Run against Vault when a Transit key holds an owner or next key: `vault write <mount>/sign/<key>` would sign as the owner. */
export const VAULT_BINARIES: readonly string[] = Object.freeze(["vault", "bao"]);
export const VAULT_REASON = "protected: the owner key of this history is held by Vault Transit; the vault CLI is for the operator, not the agent (and so are the Vault token and the Transit sign path)";
export const CONTROL_REASON = "protected: IronTrellis control commands are for the operator, not the agent";
/** How the user runs a command the agent may not: in Claude Code the `!` prefix runs it as the user's own command (no hook sees it). */
const RUN_IT_YOURSELF = "You can run it yourself: in Claude Code, type it with the `!` prefix";
/**
 * The founder's wording (live check 01) for the agent's attempt to choose whether a project uses IronTrellis or to set it
 * up (`irontrellis-hook choose`, `init`, `pin-runtime`; `hit` is controlCommand's): whose act it is and how the user runs
 * it. The choice is stored per user in the route-choices file, so the text says it is saved for this project (not that
 * the history records it). Undefined for any other control command.
 */
export function setupRefusal(hit: string, host: string | undefined = "claude-code"): string | undefined {
  const sub = /^irontrellis-hook (choose|init|pin-runtime)\b/.exec(hit)?.[1];
  if (sub === undefined) return undefined;
  const policy = (what: string): string => `installation policy: only you, the human operator, may ${what}; I, the agent, am not allowed to run`;
  // Codex and Cursor have no `!` prefix: there the user runs it in their own terminal (live check B of the Codex route).
  if (host !== undefined && host !== "claude-code") {
    if (sub === "pin-runtime") return `${policy("set IronTrellis up")} \`irontrellis-hook pin-runtime\`. Run it yourself in your own terminal.`;
    return `${policy("choose whether this project uses IronTrellis")} \`irontrellis-hook ${sub}\`. Run it yourself in your own terminal.`;
  }
  if (sub === "choose") return `${policy("choose whether this project uses IronTrellis")} \`irontrellis-hook choose\`. ${RUN_IT_YOURSELF}, for example \`! irontrellis-hook choose 1\` (proceed without IronTrellis), \`! irontrellis-hook choose 2\` (set it up: the plugin route) or \`! irontrellis-hook choose 3\` (the hook route), or run it in your own terminal. Your choice is saved for this project.`;
  if (sub === "init") return `${policy("choose whether this project uses IronTrellis")} \`irontrellis-hook init\`. ${RUN_IT_YOURSELF} (\`! irontrellis-hook choose 2\` sets up the plugin route), or run it in your own terminal.`;
  return `${policy("set IronTrellis up")} \`irontrellis-hook pin-runtime\`. ${RUN_IT_YOURSELF} (\`! irontrellis-hook pin-runtime\`), or run it in your own terminal.`;
}
/** Tools whose input is a shell command, in each host's spelling. */
export const SHELL_TOOLS: readonly string[] = Object.freeze(["Bash", "Monitor", "Shell", "shell", "local_shell", "exec_command", "container.exec"]);

export type Protection = Readonly<{ code: "PROTECTED_PATH" | "PROTECTED_COMMAND"; reason: string }>;

const caseFold = process.platform === "linux" ? (s: string): string => s : (s: string): string => s.toLowerCase();

type Target = Readonly<{ path: string; prefix: boolean; what: string }>;
type Env = Readonly<Record<string, string | undefined>>;

const userHome = (env: Env): string => (env.HOME !== undefined && env.HOME !== "" ? env.HOME : homedir());
/** Claude Code's per-user directory: CLAUDE_CONFIG_DIR when it is set (an absolute path), else ~/.claude. */
export const claudeConfigDir = (env: Env = process.env): string => {
  const dir = env.CLAUDE_CONFIG_DIR;
  return dir !== undefined && dir !== "" && isAbsolute(dir) ? resolve(dir) : resolve(userHome(env), ".claude");
};
const packageRootOf = (file: string): string | undefined => {
  for (let dir = dirname(file); ; dir = dirname(dir)) {
    if (existsSync(join(dir, "package.json"))) return dir;
    if (dirname(dir) === dir) return undefined;
  }
};
/** This package's root (src/ and dist/ are one level down) and the root of the core package it runs on. */
const HOOKS_ROOT = fileURLToPath(new URL("..", import.meta.url)).replace(/[\\/]$/, "");
/** This package's launcher (bin/irontrellis-hook.mjs). */
export const OWN_LAUNCHER = join(HOOKS_ROOT, "bin", "irontrellis-hook.mjs");
const CORE_ROOT = ((): string | undefined => { try { return packageRootOf(fileURLToPath(import.meta.resolve("@ramex-labs/irontrellis"))); } catch { return undefined; } })();

/** The absolute locations the agent may not reference (each also in its symlink-resolved spelling). */
export function protectedTargets(config: HookConfig, env: Readonly<Record<string, string | undefined>> = process.env): readonly Target[] {
  const policy = env.IRONTRELLIS_WITNESS_POLICY;
  const custody = custodyOf(config, env);
  const raw: Target[] = [
    ...custody.paths.map((path) => ({ path, prefix: false, what: "the signer that holds the IronTrellis owner key" })),
    { path: config.history, prefix: true, what: "the IronTrellis history, its pin, lock, anchors, witness state and owner key" },
    { path: sessionsDir(config.history), prefix: false, what: "the IronTrellis session keys" },
    { path: handoversDir(config.history), prefix: false, what: "the IronTrellis handover records" },
    { path: config.path, prefix: false, what: "the IronTrellis hook config" },
    { path: choiceFile(env), prefix: false, what: "the IronTrellis install-route choice" },
    ...(policy !== undefined && policy !== "" && isAbsolute(policy) ? [{ path: policy, prefix: false, what: "the IronTrellis out-of-band witness policy" }] : []),
    { path: defaultStateHome(env), prefix: false, what: "the IronTrellis home (route choices, the plugin's runtime pin, session routes)" },
  ];
  const out: Target[] = [];
  for (const t of raw) {
    out.push(t);
    const real = realpathLoose(t.path);
    if (real !== t.path) out.push({ ...t, path: real });
  }
  return out;
}

/** What the history's key files say about custody: signer paths to protect, and whether an ssh-agent holds a key. Never throws. */
export function custodyOf(config: HookConfig, env: Readonly<Record<string, string | undefined>> = process.env): Readonly<{ sshAgent: boolean; vault: boolean; paths: readonly string[] }> {
  let sshAgent = false, vault = false;
  const paths: string[] = [];
  // Retired owner keys too: a retired key's signer (an ssh-agent socket, a command, a Vault token) still signs head
  // statements a witness accepts until every witness has recorded the rotation (doctor's HOOKS_PROTECT_GAP).
  for (const file of [`${config.history}.owner-key.json`, `${config.history}.owner-next-key.json`, ...retiredOwnerKeyFilesFor(config.history)]) {
    let record: { version?: unknown; signer?: { kind?: unknown; socket?: unknown; argv?: unknown; tokenFile?: unknown; caFile?: unknown } } | undefined;
    try { record = JSON.parse(readRegularFile(file, 65_536)) as typeof record; } catch (error) {
      // A key file this user cannot read (the owner's 0600 reference, with the hook running as the agent's user: the
      // recommended layout): the history declares owner keys, so every custody rule applies.
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EACCES" || code === "EPERM") {
        sshAgent = true; vault = true;
        const socket = env.SSH_AUTH_SOCK;
        if (socket !== undefined && socket !== "" && isAbsolute(socket)) paths.push(socket);
        paths.push(resolve(env.HOME !== undefined && env.HOME !== "" ? env.HOME : homedir(), ".vault-token"));
      }
      continue;
    }
    if (record?.version !== "irontrellis-owner-key-ref/1" && record?.version !== "irontrellis-owner-next-key-ref/1") continue;
    const signer = record.signer;
    if (signer?.kind === "ssh-agent") {
      sshAgent = true;
      const socket = typeof signer.socket === "string" ? signer.socket : env.SSH_AUTH_SOCK;
      if (socket !== undefined && socket !== "" && isAbsolute(socket)) paths.push(socket);
    } else if (signer?.kind === "command" && Array.isArray(signer.argv)) {
      for (const arg of signer.argv) if (typeof arg === "string" && isAbsolute(arg)) paths.push(arg);
    } else if (signer?.kind === "vault-transit") {
      // The Vault token (the reference's tokenFile, else the Vault CLI's ~/.vault-token; a VAULT_TOKEN in the agent's
      // environment cannot be hidden by a hook: docs/CUSTODY.md §7) and the CA bundle the client trusts.
      vault = true;
      if (typeof signer.tokenFile === "string" && isAbsolute(signer.tokenFile)) paths.push(signer.tokenFile);
      else paths.push(resolve(env.HOME !== undefined && env.HOME !== "" ? env.HOME : homedir(), ".vault-token"));
      if (typeof signer.caFile === "string" && isAbsolute(signer.caFile)) paths.push(signer.caFile);
    }
  }
  return Object.freeze({ sshAgent, vault, paths: Object.freeze([...new Set(paths)]) });
}

const within = (candidate: string, target: Target): boolean => {
  const c = caseFold(candidate), p = caseFold(target.path);
  if (c === p) return true;
  if (target.prefix) return c.startsWith(p);
  return c.startsWith(p.endsWith(sep) ? p : p + sep);
};

/** Every string value in the tool input (depth- and count-limited). */
function strings(value: unknown, out: string[] = [], depth = 0): string[] {
  if (out.length > 4096 || depth > 16) return out;
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) strings(v, out, depth + 1);
  else if (value !== null && typeof value === "object") for (const [k, v] of Object.entries(value)) { out.push(k); strings(v, out, depth + 1); }
  return out;
}

// Any single line could be a path relative to the cwd (a bare "notes.json" may be a symlink into the state directory).
const looksLikePath = (s: string): boolean => s.length > 0 && s.length <= 4096 && !/[\n\r\0]/.test(s);
// `~\x` too: PowerShell expands it, and the Windows separator is either slash.
const expandHome = (s: string): string => (s === "~" || s.startsWith("~/") || s.startsWith("~\\") ? homedir() + s.slice(1) : s);

/** File-editing tools: only their target path is checked, so a file that merely mentions IronTrellis can still be written. */
export const FILE_TOOLS: readonly string[] = Object.freeze(["Write", "Edit", "MultiEdit", "NotebookEdit", "Delete"]);
const PATH_KEYS = ["file_path", "notebook_path", "path", "target_file"];
const PATCH_TOOLS: readonly string[] = Object.freeze(["apply_patch"]);

/** The strings of a tool input that name what the call touches. */
function inspected(toolName: string, toolInput: Readonly<Record<string, unknown>>): string[] {
  if (FILE_TOOLS.includes(toolName)) return PATH_KEYS.map((k) => toolInput[k]).filter((v): v is string => typeof v === "string");
  if (PATCH_TOOLS.includes(toolName)) {
    // Codex apply_patch: the files are named on "*** Add/Update/Delete File:" and "*** Move to:" lines.
    const text = strings(toolInput).join("\n");
    return [...text.matchAll(/^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/gm)].map((m) => m[1]!.trim());
  }
  return strings(toolInput);
}

/** Rule 1: does the tool input reference protected state? Returns what it references. */
export function referencesProtected(config: HookConfig, toolName: string, toolInput: Readonly<Record<string, unknown>>, cwd: string | undefined): string | undefined {
  const targets = protectedTargets(config);
  const base = cwd !== undefined && isAbsolute(cwd) ? cwd : config.project;
  // Each value also in its quote-normalized spellings (`cat ~/.iron''trellis/…`, `type C:\\x\\.iron^trellis\\…`).
  // A file tool's path is a literal name: quotes and backslashes in it are characters of the name, not shell quoting (RA-09).
  const literal = FILE_TOOLS.includes(toolName) || PATCH_TOOLS.includes(toolName);
  const values = inspected(toolName, toolInput).flatMap((s) => (!literal && s.length <= 16_384 && /['"\\^`$()]/.test(s) ? commandSpellings(s) : [s]));
  for (const s of new Set(values)) {
    const folded = caseFold(s);
    for (const needle of PROTECTED_STRINGS) if (folded.includes(caseFold(needle))) return `"${needle}"`;
    for (const t of targets) if (folded.includes(caseFold(t.path))) return t.what;
    // The whole value, and each word of it (shell commands), when it could be a path.
    // Each word unescaped as a POSIX shell would, and as written (a Windows path keeps its backslashes).
    const words = !literal && s.length <= 16_384 ? s.split(/\s+/).flatMap((word) => [unquote(word), stripQuotes(word)]) : [];
    for (const candidate of new Set([s, ...words])) {
      if (!looksLikePath(candidate)) continue;
      // The lexical path and the one the file system takes (each symlink followed before a later `..`: RA-01).
      const abs = resolve(base, expandHome(candidate));
      const real = physicalPath(expandHome(candidate), base);
      for (const t of targets) if (within(abs, t) || within(real, t)) return t.what;
    }
  }
  return undefined;
}

const SEGMENT = /\|\||&&|[;|&\n\r`()]|\$\(|<\(|>\(/;
const stripQuotes = (token: string): string => token.replace(/^['"]+|['"]+$/g, "");
const unquote = (token: string): string => stripQuotes(token).replace(/\\(.)/g, "$1");
/** npm package names that run a control binary under `npx`, `pnpm dlx`, `yarn dlx`, `bunx` or `npm exec` (unscoped part). */
const PACKAGE_BINARIES: Readonly<Record<string, string>> = Object.freeze({ "irontrellis": "irontrellis", "irontrellis-hooks": "irontrellis-hook" });
/** An npm package spec's version or tag suffix (`irontrellis@next`, `@ramex-labs/irontrellis-hooks@1.0.0-rc.2`). */
const withoutVersion = (name: string): string => name.replace(/(?<=.)@[^@/\\]*$/, "");
/**
 * The control binary a path runs when it is a package's bin target rather than the bin itself
 * (`node node_modules/irontrellis/dist/cli.js`, `node …/@ramex-labs/irontrellis-hooks/dist/cli.js`,
 * `node …/irontrellis-mcp-gateway/dist/ops-cli.js`, and the same in a checkout: `packages/cli/dist/cli.js`).
 */
const binaryOfPath = (parts: readonly string[]): string | undefined => {
  if (parts.length < 2) return undefined;
  const file = (parts[parts.length - 1] ?? "").toLowerCase();
  if (!/\.(m?js|cjs)$/.test(file)) return undefined;
  const dirs = parts.slice(0, -1).map((part) => withoutVersion(part).toLowerCase());
  if (file.startsWith("ops-cli.") && (dirs.includes("irontrellis-mcp-gateway") || dirs.join("/").includes("packages/mcp-gateway"))) return "irontrellis-mcp-ops";
  if (dirs.includes("irontrellis-hooks") || dirs.join("/").includes("packages/hooks/")) return file.startsWith("cli.") || file.startsWith("irontrellis-hook.") ? "irontrellis-hook" : undefined;
  if (dirs.includes("irontrellis") || dirs.join("/").includes("packages/cli/")) return file.startsWith("cli.") || file.startsWith("irontrellis.") ? "irontrellis" : undefined;
  return undefined;
};
// npm installs a bin as `name`, `name.cmd` and `name.ps1` on Windows, where command names are case-insensitive: every
// spelling is matched, in any case (a stricter tripwire on POSIX, where `IRONTRELLIS` would be another program).
// The name is taken both after shell unescaping and with quotes only stripped: `unquote` drops the backslashes of a
// Windows path (`C:\tools\irontrellis.cmd`), which are separators there, not escapes. A package spec's version suffix is
// ignored (`npx irontrellis@next`), and so is its scope (`@ramex-labs/irontrellis-hooks`).
const binaryOf = (token: string): string | undefined => {
  for (const spelling of [unquote(token), stripQuotes(token)]) {
    const parts = spelling.split(/[\\/]/);
    const name = withoutVersion(parts[parts.length - 1] ?? "");
    const bare = name.replace(/\.(m?js|cjs|cmd|bat|ps1|exe)$/i, "").toLowerCase();
    if (CONTROL_BINARIES.includes(bare)) return bare;
    const packaged = Object.hasOwn(PACKAGE_BINARIES, bare) ? PACKAGE_BINARIES[bare] : undefined;
    if (packaged !== undefined) return packaged;
    const target = binaryOfPath(parts);
    if (target !== undefined) return target;
  }
  return undefined;
};
const baseName = (token: string): string => (unquote(token).split(/[\\/]/).pop() ?? "").toLowerCase();

/**
 * The spellings of a shell command the tripwire matches: as written, and with shell quoting normalized so
 * that quoting cannot splice a name or a subcommand together:
 *   - POSIX: `$'…'` and `$"…"` become plain quotes, every `'` and `"` is deleted (`irontrel''lis`, `gr""ant`, `'gr'ant`),
 *     backslash escapes are resolved, and command substitutions (`$(…)`, backticks) and parentheses no longer split
 *     the command, so `node $(command -v irontrellis) grant` keeps the binary and the subcommand together;
 *   - Windows: `cmd` carets (`iron^trellis`) and PowerShell backticks (`iron\`trellis`) are deleted, quotes too, and
 *     backslashes are kept (they are path separators there).
 * A command is flagged when any spelling is. This is still a tripwire: a variable (`i=irontrellis; $i grant`), an
 * alias, a script written earlier or PowerShell string arithmetic is not seen (docs/SECURITY.md).
 */
export function commandSpellings(command: string): string[] {
  let posix = "";
  for (let i = 0; i < command.length; i += 1) {
    const c = command[i] as string, next = command[i + 1];
    if (c === "\\" && next !== undefined) { posix += next === "\n" ? " " : next; i += 1; continue; } // an escaped character is literal
    if (c === "$" && (next === "'" || next === "\"")) continue; // $'…' and $"…": quoting like '…' and "…"
    if (c === "'" || c === "\"") continue;
    if ((c === "$" || c === "<" || c === ">") && next === "(") { posix += " "; i += 1; continue; }
    if (c === "`" || c === "(" || c === ")") { posix += " "; continue; }
    posix += c;
  }
  const windows = command.replace(/[\^`'"]/g, "").replace(/\$\(|[()]/g, " ");
  return [...new Set([command, posix, windows, posix.replace(/\^/g, "")])];
}

/** Rule 2 on one spelling. */
function controlIn(command: string): string | undefined {
  for (const segment of command.split(SEGMENT)) {
    const tokens = segment.trim().split(/\s+/).filter((t) => t.length > 0);
    const at = tokens.findIndex((t) => binaryOf(t) !== undefined);
    if (at < 0) continue;
    const binary = binaryOf(tokens[at]!) as string;
    const rest = tokens.slice(at + 1).map(unquote);
    const sub = writingIn(rest);
    if (sub !== undefined) return `${binary} ${sub}`;
    // `echo grant | xargs irontrellis`: the arguments, subcommand included, come from xargs's input.
    if (tokens.slice(0, at).some((t) => baseName(t) === "xargs") && !rest.some((t) => !t.startsWith("-"))) return `${binary} (arguments from xargs)`;
  }
  return undefined;
}

/** Rule 2: does this shell command run an IronTrellis control command with a writing subcommand? */
export function controlCommand(command: string): string | undefined {
  for (const spelling of commandSpellings(command)) {
    const hit = controlIn(spelling);
    if (hit !== undefined) return hit;
    // Variable or alias indirection (`i=irontrellis; $i grant`, `alias it=irontrellis; it grant`): a
    // control program assigned to a name, and a writing subcommand anywhere in the same command.
    const assigned = /(?:^|[\s;&|(])(?:alias\s+)?[A-Za-z_][A-Za-z0-9_-]*=([^\s;&|()]+)/g;
    for (let m = assigned.exec(spelling); m !== null; m = assigned.exec(spelling)) {
      const binary = binaryOf(m[1]!);
      if (binary === undefined) continue;
      const sub = writingIn(spelling.slice(m.index + m[0].length).split(/[\s;&|()]+/).map(unquote));
      if (sub !== undefined) return `${binary} ${sub} (through a variable or alias)`;
    }
  }
  return undefined;
}

/**
 * Beyond the programs, what reaches an ssh-agent or Vault without them: `ssh-keygen -Y sign` (signs
 * through the agent), anything naming `SSH_AUTH_SOCK` (socat, nc, a script's raw socket), and anything naming the Vault
 * token or the Transit sign path (`VAULT_TOKEN`, `X-Vault-Token`, `.vault-token`, `…/sign/…` under `/v1/`). Best effort.
 */
export const SSH_AGENT_PATTERNS: readonly RegExp[] = Object.freeze([/\bssh-keygen(?:\.exe)?\b[^;&|]*\s-Y\s*sign\b/, /SSH_AUTH_SOCK/]);
export const VAULT_PATTERNS: readonly RegExp[] = Object.freeze([/VAULT_TOKEN/, /X-Vault-Token/i, /\.vault-token\b/, /\/v1\/\S*\/sign\//, /\btransit\/sign\//]);
const matchesAny = (command: string, patterns: readonly RegExp[]): boolean => commandSpellings(command).some((spelling) => patterns.some((pattern) => pattern.test(spelling)));

/** Rule 2, custody: does this shell command run `ssh-add` (or another of `binaries`, in any spelling the tripwire sees)? */
export function custodyCommand(command: string, binaries: readonly string[] = CUSTODY_BINARIES): string | undefined {
  for (const spelling of commandSpellings(command)) {
    // Variable indirection of a known program (`s=ssh-add; $s -D`, `export V=vault`): the name as an assignment's value.
    const assigned = new RegExp(`(?:^|[\\s;&|(])[A-Za-z_][A-Za-z0-9_]*=(?:\\S*[\\\\/])?(${binaries.map((b) => b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})(?:\\.exe)?(?=$|[\\s;&|)])`).exec(spelling);
    if (assigned !== null) return assigned[1];
    for (const segment of spelling.split(SEGMENT)) {
      const hit = segment.trim().split(/\s+/).map((token) => baseName(token).replace(/\.exe$/, "")).find((name) => binaries.includes(name));
      if (hit !== undefined) return hit;
    }
  }
  return undefined;
}

const shellCommands = (toolInput: Readonly<Record<string, unknown>>): string[] => {
  const c = toolInput.command ?? toolInput.cmd;
  if (typeof c === "string") return [c];
  if (Array.isArray(c)) return [c.filter((x): x is string => typeof x === "string").join(" ")];
  return [];
};

// ---------------------------------------------------------------- Claude Code's own configuration (rule 3)

/** Claude Code's settings files that hold hooks and enabled plugins: the user's (in CLAUDE_CONFIG_DIR when set), the project's, the local one. */
export const claudeSettingsFiles = (project: string, env: Env = process.env): readonly string[] =>
  [join(claudeConfigDir(env), "settings.json"), resolve(project, ".claude", "settings.json"), resolve(project, ".claude", "settings.local.json")];
/** Codex's user directory: CODEX_HOME when set (absolute), else ~/.codex (as setup.ts codexConfigFiles reads it). */
export const codexHomeDir = (env: Env = process.env): string => {
  const dir = env.CODEX_HOME;
  return dir !== undefined && dir !== "" && isAbsolute(dir) ? resolve(dir) : resolve(userHome(env), ".codex");
};
/** Under Codex's user directory, the data Codex itself keeps (session rollouts, logs): left out of the .codex name rule. */
export const CODEX_DATA_DIRS: readonly string[] = Object.freeze(["sessions", "archived_sessions", "log", "logs"]);
/** Under the user's Claude Code directory, the data Claude Code itself has the agent write with its file tools: auto memory and transcripts, plans, todos. */
export const CLAUDE_DATA_DIRS: readonly string[] = Object.freeze(["projects", "plans", "todos"]);
/**
 * Tools that write nothing themselves, so may name Claude Code's configuration (reading it, searching it, mentioning it
 * in a todo or in a subagent's prompt, whose own tool calls come through this guard). An explicit list.
 */
export const NO_WRITE_TOOLS: readonly string[] = Object.freeze([
  "Read", "Glob", "Grep", "LS", "NotebookRead", "WebFetch", "WebSearch", "TodoWrite", "TodoRead", "Task", "Agent", "AskUserQuestion",
  "ExitPlanMode", "EnterPlanMode", "ToolSearch", "Skill",
]);

/** The words of a shell command or hook entry, with single and double quotes honoured (no expansion). */
export function shellWords(command: string): string[] {
  const out: string[] = [];
  let word = "", inWord = false, quote: string | undefined;
  for (let i = 0; i < command.length; i += 1) {
    const c = command[i] as string;
    if (quote !== undefined) { if (c === quote) quote = undefined; else if (c === "\\" && quote === "\"" && i + 1 < command.length) { word += command[i + 1]; i += 1; } else word += c; continue; }
    if (c === "'" || c === "\"") { quote = c; inWord = true; continue; }
    if (c === "\\" && i + 1 < command.length) { word += command[i + 1]; i += 1; inWord = true; continue; }
    if (/\s/.test(c)) { if (inWord) out.push(word); word = ""; inWord = false; continue; }
    word += c; inWord = true;
  }
  if (inWord) out.push(word);
  return out;
}
/**
 * The hook entry `install claude-code --write` writes, by absolute path and without PATH: `/bin/sh -c '<HOOK_WRAPPER>'
 * <node> <launcher> claude-code <Event>`. The wrapper refuses when the node or the launcher is missing (exit 2 for
 * PreToolUse, 1 for the other events) instead of letting the host see exit 127, which it treats as non-blocking; for
 * PreToolUse it runs the guard as a child and turns any failure other than a refusal (a crash, a deleted dist/) into exit 2.
 */
export const HOOK_WRAPPER = `[ -f "$0" ] && [ -x "$0" ] && [ -f "$1" ] || { [ "$3" = PreToolUse ] && exit 2; exit 1; }; if [ "$3" = PreToolUse ]; then "$0" "$@"; s=$?; [ "$s" -eq 0 ] || [ "$s" -eq 2 ] || s=2; exit "$s"; fi; exec "$0" "$@"`;
/** Earlier wrappers install wrote (3177443): their entries are IronTrellis's own and are rewritten, never a hook route. */
export const EARLIER_HOOK_WRAPPERS: readonly string[] = Object.freeze([`[ -x "$0" ] && [ -f "$1" ] || { [ "$3" = PreToolUse ] && exit 2; exit 1; }; exec "$0" "$@"`]);
/** Characters a node or launcher path in a hook entry may not contain (the shell would read them). */
export const HOOK_PATH_UNSAFE = /[$`"'\\\n\r;&|<>(){}*?[\]!#~]/;
export const hookEntryProgram = (node: string, launcher: string): string => `/bin/sh -c '${HOOK_WRAPPER}' ${shellQuote(node)} ${shellQuote(launcher)}`;
/** A path quoted for a POSIX shell when it needs it. */
export const shellQuote = (s: string): string => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`);
/** The path below `home` as `~/…` for reading (POSIX only; elsewhere, or outside `home`, the path as is). */
export const homeShort = (p: string, home: string | undefined): string =>
  process.platform !== "win32" && home !== undefined && home.length > 1 && p.startsWith(`${home.replace(/\/+$/, "")}/`) ? `~${p.slice(home.replace(/\/+$/, "").length)}` : p;
/** A path for a command line the user may copy: `~/` (left unquoted, so the shell expands it) and the rest quoted when it needs it. */
export const shellPath = (p: string, home: string | undefined): string => {
  const short = homeShort(p, home);
  return short.startsWith("~/") ? `~/${shellQuote(short.slice(2))}` : shellQuote(p);
};

/** `program` (a bare name) on PATH, as the PATH entry spells it; undefined when absent. */
export function onPath(program: string, env: Env): string | undefined {
  for (const dir of (env.PATH ?? "").split(delimiter)) {
    if (dir === "" || !isAbsolute(dir)) continue;
    const candidate = join(dir, program);
    try { if (statSync(candidate).isFile()) return candidate; } catch { /* next */ }
  }
  return undefined;
}

/** The absolute programs of IronTrellis's hook entries in a settings file (`<node> <launcher> claude-code <Event>`). */
const hookPrograms = (file: string): string[] => {
  let doc: unknown;
  try { doc = JSON.parse(readRegularFile(file)); } catch { return []; }
  const hooks = doc !== null && typeof doc === "object" ? (doc as Record<string, unknown>).hooks : undefined;
  if (hooks === null || typeof hooks !== "object") return [];
  const out: string[] = [];
  for (const groups of Object.values(hooks as Record<string, unknown>)) {
    if (!Array.isArray(groups)) continue;
    for (const group of groups) {
      const handlers = group !== null && typeof group === "object" ? (group as Record<string, unknown>).hooks : undefined;
      if (!Array.isArray(handlers)) continue;
      for (const h of handlers) {
        const command = h !== null && typeof h === "object" && typeof (h as Record<string, unknown>).command === "string" ? (h as { command: string }).command : "";
        const words = shellWords(command);
        if (words.length >= 4 && words[words.length - 2] === "claude-code") out.push(...words.slice(0, -2).filter((w) => isAbsolute(w)));
      }
    }
  }
  return out;
};

type Guarded = Readonly<{ protect: readonly Target[]; exempt: readonly Target[] }>;

/**
 * Whether `path` is inside the IronTrellis checkout itself: one of the projects whose root package.json is the workspace,
 * and not under any node_modules folder in it (a project that installs the hooks package keeps it protected). Only
 * there is the guard's own code left out of rule 3.
 */
export function inIronTrellisCheckout(projects: readonly string[], path: string): boolean {
  return projects.some((project) => {
    let name: unknown;
    try { name = (JSON.parse(readRegularFile(join(project, "package.json"), 1_048_576)) as { name?: unknown }).name; } catch { return false; }
    const root = { path: realpathLoose(project), prefix: false, what: "" }, real = realpathLoose(path);
    return name === IRONTRELLIS_WORKSPACE && within(real, root) && !relative(root.path, real).split(/[\\/]/).includes("node_modules");
  });
}

/**
 * What rule 3 protects, for the projects the guard serves (the route's project and the config's): the project's .claude/
 * tree and .mcp.json; the user's Claude Code directory (CLAUDE_CONFIG_DIR, and ~/.claude), its CLAUDE_DATA_DIRS
 * excepted; ~/.claude.json (and its copy in CLAUDE_CONFIG_DIR); the hosts' other configuration (GUARD-CODEX-CURSOR-01):
 * the project's .codex/ and .cursor/ trees, Codex's config.toml and hooks.json in CODEX_HOME (else ~/.codex), and
 * ~/.cursor/hooks.json, where an agent could switch its own hooks off; the plugin's root and the plugin cache; the installed hooks
 * and core packages; and the interpreter and launcher paths the guard runs with (process.execPath, PATH's node, the
 * plugin's runtime pin, the programs of the hook entries), each as written. Code, interpreter and launcher paths inside a
 * project are left out: that is IronTrellis developed in its own checkout (README).
 */
function guardedPaths(projects: readonly string[], env: Env, extra: readonly Target[] = []): Guarded {
  const t = (path: string, what: string): Target => ({ path: resolve(path), prefix: false, what });
  const userDirs = [...new Set([claudeConfigDir(env), resolve(userHome(env), ".claude")])];
  const plugin = env.CLAUDE_PLUGIN_ROOT, cache = env.CLAUDE_CODE_PLUGIN_CACHE_DIR;
  const config: Target[] = [
    ...projects.flatMap((p) => [t(join(p, ".claude"), "the project's Claude Code configuration (.claude/)"), t(join(p, ".mcp.json"), "the project's MCP servers (.mcp.json)")]),
    ...userDirs.map((d) => t(d, "the user's Claude Code configuration (~/.claude or CLAUDE_CONFIG_DIR)")),
    ...[...new Set([resolve(userHome(env), ".claude.json"), join(claudeConfigDir(env), ".claude.json")])].map((f) => t(f, "Claude Code's state file (.claude.json: folder trust and MCP servers)")),
    ...(cache !== undefined && cache !== "" && isAbsolute(cache) ? [t(cache, "the Claude Code plugin cache (CLAUDE_CODE_PLUGIN_CACHE_DIR)")] : []),
    ...projects.flatMap((p) => [t(join(p, ".codex"), "the project's Codex configuration (.codex/: config.toml and hooks.json)"), t(join(p, ".cursor"), "the project's Cursor configuration (.cursor/: hooks.json)")]),
    ...["config.toml", "hooks.json"].map((name) => t(join(codexHomeDir(env), name), `Codex's user configuration (${name} in CODEX_HOME or ~/.codex)`)),
    t(join(userHome(env), ".cursor", "hooks.json"), "Cursor's user hooks (~/.cursor/hooks.json)"),
  ];
  const pin = readRuntimePin(env);
  const runtime = [process.execPath, OWN_LAUNCHER, onPath("node", env), pin?.node, pin?.launcher, ...projects.flatMap((p) => claudeSettingsFiles(p, env).flatMap(hookPrograms))]
    .filter((p): p is string => p !== undefined && isAbsolute(p));
  const code: Target[] = [
    ...(plugin !== undefined && plugin !== "" && isAbsolute(plugin) ? [t(plugin, "the IronTrellis plugin for Claude Code")] : []),
    t(HOOKS_ROOT, "the installed IronTrellis guard (the hooks package)"),
    ...(CORE_ROOT !== undefined ? [t(CORE_ROOT, "the installed IronTrellis core package")] : []),
    ...runtime.map((p) => t(p, "the interpreter or launcher the IronTrellis guard runs with")),
  ];
  const inCheckout = (p: string): boolean => inIronTrellisCheckout(projects, p);
  const protect: Target[] = [];
  for (const target of [...config, ...extra, ...code.filter((c) => !inCheckout(c.path))]) {
    // Each path as written and as its target now (a `brew upgrade` that moves the target is covered at the next check).
    for (const path of new Set([target.path, realpathLoose(target.path)])) if (!protect.some((p) => p.path === path)) protect.push({ ...target, path });
  }
  const exempt = [
    ...userDirs.flatMap((d) => CLAUDE_DATA_DIRS.flatMap((name) => [...new Set([join(d, name), join(realpathLoose(d), name)])].map((path) => t(path, "")))),
    ...CODEX_DATA_DIRS.flatMap((name) => [...new Set([join(codexHomeDir(env), name), join(realpathLoose(codexHomeDir(env)), name)])].map((path) => t(path, ""))),
  ];
  return { protect, exempt };
}

/** The name of the IronTrellis workspace's root package.json (the in-checkout development exemption). */
const IRONTRELLIS_WORKSPACE = "irontrellis-workspace";
/** A shell command that could write a file it names (best effort: a path built at run time is not seen). */
const SHELL_WRITERS = /(?:^|[\s;&|(])(?:>|>>|tee|sed|perl|awk|mv|cp|rm|ln|truncate|dd|install|python3?|node|ruby|sponge|ed|ex|vi|vim|nano|chmod|chown|rsync|ditto|tar|unzip|curl|wget|git|mkfifo|mknod)(?=$|[\s;&|)<>])|>/;
/**
 * Programs that only read what they are given: a shell command segment that names a guarded or Claude Code configuration
 * path is refused unless its program is one of these (git only with a reading subcommand, jq only without --in-place).
 */
export const READ_ONLY_PROGRAMS: readonly string[] = Object.freeze([
  "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ls", "stat", "wc", "file", "sha256sum", "sha1sum", "sha512sum", "shasum", "md5", "md5sum",
  "b2sum", "diff", "cmp", "jq", "git", "cd", "pushd", "popd", "pwd", "echo", "printf", "test", "[", "realpath", "readlink", "basename", "dirname", "which", "type",
  "od", "xxd", "hexdump", "sort", "uniq", "cut", "tr",
]);
const GIT_READ_ONLY: readonly string[] = Object.freeze(["show", "diff", "log", "status", "blame", "ls-files", "rev-parse", "cat-file", "grep"]);
/** Leading words that run the next one: the segment's program is the word after them (and after VAR=value assignments). */
const RUNNERS: readonly string[] = Object.freeze(["env", "command", "builtin", "exec", "nohup", "time", "nice", "sudo", "doas", "xargs", "timeout", "stdbuf", "ionice", "chrt", "caffeinate", "npx", "corepack"]);
/** A runner's options that take their value as the next word (`nice -n 5`, `sudo -u root`, `timeout -s KILL 5`). */
const RUNNER_VALUE_FLAGS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  nice: ["-n", "--adjustment"], sudo: ["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"], doas: ["-u", "-C"], env: ["-u", "-C", "-S", "--unset", "--chdir"],
  timeout: ["-s", "-k", "--signal", "--kill-after"], npx: ["-p", "--package", "-c", "--call"], stdbuf: ["-i", "-o", "-e"], xargs: ["-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"], time: ["-f", "-o"], ionice: ["-c", "-n", "-p"], chrt: ["-p"],
});
/** Shells whose `-c` runs the next word as a command (in the quote-stripped spelling its words follow). */
const SHELL_PROGRAMS: readonly string[] = Object.freeze(["sh", "bash", "zsh", "dash", "ksh", "fish"]);
/** Claude Code configuration named without a resolvable path: `.claude/…`, the state files, and a bare settings file name (after `cd .claude`). */
// Case-insensitive where the file system is (macOS, Windows); on Linux `.CLAUDE` is another folder (RA-08).
const CONFIG_NAMES = new RegExp(/(?:^|[\s'"=:/\\<>])\.(?:claude|codex|cursor)(?:[\\/]|$|[\s'"])|\.claude\.json|\.mcp\.json|settings\.local\.json/.source, process.platform === "linux" ? "" : "i");
/** A token without a redirection glued to its front (`>.claude/x`, `>>f`, `2>f`, `&>f`, `<f`), for the path checks. */
const unredirected = (w: string): string => w.replace(/^(?:\d*|&)>>?\|?|^\d*</, "");
/** The paths a token may name: itself (without a glued redirection), an option's value (`--output=x`) and a short option's glued value (`-ox`). */
const candidates = (token: string): string[] => {
  const w = unredirected(token);
  return [w, ...(/^--[^=]+=/.test(w) ? [w.slice(w.indexOf("=") + 1)] : []), ...(/^-[A-Za-z]./.test(w) && !w.startsWith("--") ? [w.slice(2)] : [])].filter((x) => x !== "");
};
/** A path (case-folded off Linux) with a `.claude` segment, or a `.claude.json` / `.mcp.json` file: Claude Code reads such files in nested folders too. */
const CONFIG_SEGMENT = /(?:^|[\\/])\.(?:claude|codex|cursor)(?:[\\/]|$)|(?:^|[\\/])\.(?:claude|mcp)\.json$/;
// `.codex` and `.cursor` as folder names, never bare `config.toml` or `hooks.json`: a project's own file of that name stays writable.
const BARE_CONFIG_NAMES: readonly string[] = Object.freeze(["settings.json", "settings.local.json", ".claude.json", ".mcp.json", ".claude", ".codex", ".cursor"]);
/** Programs that move or delete whatever path they are given (and below it). */
const REMOVERS: readonly string[] = Object.freeze(["mv", "rm", "rmdir", "unlink", "trash", "shred", "find", "srm"]);
/** Programs that write into the last path they are given (a directory holding protected files would be overwritten). */
const COPIERS: readonly string[] = Object.freeze(["cp", "rsync", "ditto", "ln", "install"]);
const expandShellHome = (token: string, env: Env): string => token.replace(/^(?:\$\{HOME\}|\$HOME)(?=$|[\\/])/, userHome(env)).replace(/^~(?=$|[\\/])/, userHome(env));
const programOf = (token: string): string => (token.split(/[\\/]/).pop() ?? "").replace(/\.exe$/i, "").toLowerCase();
/** `git clean …` and `git stash -u|-a|--include-untracked|--all`: they remove untracked files, the IronTrellis config and .claude/settings.local.json among them. */
/** A segment's program, the words after it, and the VAR=value assignments before it (through runners and `sh -c`). */
const programAndArgs = (tokens: readonly string[]): readonly [string, readonly string[], readonly string[]] => {
  let i = 0;
  const assignments: string[] = [];
  while (i < tokens.length) {
    const token = tokens[i]!, program = programOf(token);
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) { assignments.push(token); i += 1; continue; }
    if (RUNNERS.includes(program)) {
      i += 1;
      while (i < tokens.length && tokens[i]!.startsWith("-")) { const flag = tokens[i]!; i += (RUNNER_VALUE_FLAGS[program] ?? []).includes(flag) ? 2 : 1; }
      if (program === "timeout" && i < tokens.length) i += 1; // the duration
      continue;
    }
    if (SHELL_PROGRAMS.includes(program) && /^-[A-Za-z]*c[A-Za-z]*$/.test(tokens[i + 1] ?? "")) { i += 2; continue; }
    break;
  }
  return [withoutVersion(programOf(tokens[i] ?? "")), tokens.slice(i + 1), assignments]; // `npx npm@10 …` runs npm
};
const gitSubcommand = (args: readonly string[]): string | undefined => {
  let i = 0;
  while (i < args.length && args[i]!.startsWith("-")) i += ["-C", "-c", "--git-dir", "--work-tree", "--namespace"].includes(args[i]!) ? 2 : 1;
  return args[i];
};
/** Whether a READ_ONLY_PROGRAMS program, with these words, only reads: the forms that write or run something are not. */
const readsOnly = (program: string, args: readonly string[]): boolean => {
  if (!READ_ONLY_PROGRAMS.includes(program) || args.some((a) => /^(?:\d*|&)>/.test(a))) return false;
  const positional = args.filter((a) => !a.startsWith("-"));
  const has = (...flags: string[]): boolean => args.some((a) => flags.some((f) => a === f || (f.startsWith("--") && a.startsWith(`${f}=`)) || (!f.startsWith("--") && f.length === 2 && a.startsWith(f) && a.length > 2)));
  switch (program) {
    case "git": {
      const sub = gitSubcommand(args), before = args.slice(0, Math.max(0, args.indexOf(sub ?? "")));
      if (sub === undefined || !GIT_READ_ONLY.includes(sub) || before.some((a) => a === "-c" || a.startsWith("--config-env") || a.startsWith("--exec-path"))) return false;
      if (args.some((a) => a === "--output" || a.startsWith("--output=") || a.startsWith("--ext-diff"))) return false;
      return sub !== "grep" || !args.some((a) => a === "-O" || a.startsWith("--open-files-in-pager") || /^-[A-Za-z]*O/.test(a));
    }
    case "jq": return !has("-i", "--in-place");
    case "sort": return !has("-o", "--output") && !args.some((a) => /^-[A-Za-z]*o/.test(a)); // -o, also clustered (-uo F)
    case "uniq": return positional.length < 2;
    case "xxd": return !has("-r", "-revert") && !args.some((a) => /^-[A-Za-z]*r/.test(a)) && positional.length < 2; // -r, also clustered (-pr)
    case "rg": return !has("--pre", "--pre-glob");
    case "file": return !has("-C", "--compile");
    case "less": return !has("-o", "-O", "--log-file", "--LOG-FILE");
    default: return true;
  }
};
const NPM_LIKE: readonly string[] = Object.freeze(["npm", "pnpm", "yarn", "bun"]);
const NPM_WRITES: readonly string[] = Object.freeze(["install", "i", "add", "uninstall", "remove", "rm", "un", "r", "unlink", "link", "ln", "update", "up", "upgrade", "global"]);
const BREW_WRITES: readonly string[] = Object.freeze(["unlink", "uninstall", "remove", "rm", "upgrade", "reinstall", "link", "switch", "cleanup"]);
/**
 * Best effort: a package-manager command that could replace or remove the installed IronTrellis guard or the node it
 * runs with: npm, pnpm, yarn or bun installing, removing or linking globally or naming an IronTrellis package; brew
 * changing node (or upgrading everything).
 */
const packageManagerHit = (program: string, args: readonly string[], assignments: readonly string[] = []): boolean => {
  const sub = args.find((a) => !a.startsWith("-"));
  if (NPM_LIKE.includes(program) && sub !== undefined && NPM_WRITES.includes(sub)) {
    const named = args.filter((a) => !a.startsWith("-") && a !== sub);
    // `npm link` with no package links the current one globally; npm_config_global / npm_config_location and --prefix install elsewhere.
    return sub === "global" || ((sub === "link" || sub === "ln") && named.length === 0) || args.some((a) => a === "-g" || a === "--global" || a === "--location=global" || a === "--prefix" || a.startsWith("--prefix=")) ||
      assignments.some((a) => /^npm_config_(global|location|prefix)=/i.test(a)) || args.some((a) => /irontrellis/i.test(a));
  }
  if (program === "brew" && sub !== undefined && BREW_WRITES.includes(sub)) {
    const formulae = args.filter((a) => !a.startsWith("-") && a !== sub);
    return formulae.some((f) => /^node(@\d+)?$/.test(f)) || ((sub === "upgrade" || sub === "cleanup") && formulae.length === 0);
  }
  return false;
};
/**
 * Where a segment extracts, patches or checks out files: tar -x (its -C), unzip (its -d), patch (its -d), git apply, am,
 * checkout, switch, restore, stash, pull, merge, rebase, cherry-pick, revert, read-tree -u and reset --hard|--merge|--keep
 * (git -C), else the cwd.
 */
const extractsInto = (program: string, args: readonly string[], cwd: string): string | undefined => {
  const value = (...flags: string[]): string | undefined => {
    for (let i = 0; i < args.length; i += 1) {
      const a = args[i]!;
      for (const f of flags) { if (a === f) return args[i + 1]; if (f.startsWith("--") && a.startsWith(`${f}=`)) return a.slice(f.length + 1); if (!f.startsWith("--") && a.startsWith(f) && a.length > f.length) return a.slice(f.length); }
    }
    return undefined;
  };
  if (program === "tar" && args.some((a) => a === "--extract" || a === "--get" || /^-?[A-Za-z]*x/.test(a))) return value("-C", "--directory") ?? cwd;
  if (program === "unzip") return value("-d") ?? cwd;
  if (program === "patch") return value("-d", "--directory") ?? cwd;
  if (program === "git") {
    const sub = gitSubcommand(args), rest = args.slice(args.indexOf(sub ?? "") + 1), dir = value("-C") ?? cwd;
    if (["apply", "am", "checkout", "switch", "restore", "stash", "pull", "merge", "rebase", "cherry-pick", "revert"].includes(sub ?? "")) return dir;
    if (sub === "read-tree" && rest.some((a) => a === "-u" || a === "--reset" || /^-[A-Za-z]*u/.test(a))) return dir;
    if (sub === "reset" && rest.some((a) => a === "--hard" || a === "--merge" || a === "--keep")) return dir;
  }
  return undefined;
};
const gitRemovesUntracked = (tokens: readonly string[]): boolean => {
  const at = tokens.findIndex((t) => programOf(t) === "git");
  if (at < 0) return false;
  let i = at + 1;
  while (i < tokens.length && tokens[i]!.startsWith("-")) i += ["-C", "-c", "--git-dir", "--work-tree", "--namespace"].includes(tokens[i]!) ? 2 : 1;
  const sub = tokens[i], rest = tokens.slice(i + 1);
  return sub === "clean" || (sub === "stash" && rest.some((t) => /^-[A-Za-z]*[ua]/.test(t) || t === "--include-untracked" || t === "--all"));
};

/**
 * Rule 3 (states plugin, hook and both): the agent may not change Claude Code's own configuration (guardedPaths) or the
 * IronTrellis state (`extra`, for the folder rules). File tools may not write, edit or delete a guarded path or any path
 * with a `.claude` segment, `.claude.json` or `.mcp.json` (a nested project's .claude/ too; the CLAUDE_DATA_DIRS excepted),
 * nor delete a folder holding one; any other tool but the explicit NO_WRITE_TOOLS may not name one (a tool that moves,
 * renames or deletes, not a folder holding one either). Shell, best effort: a segment naming one runs a READ_ONLY_PROGRAMS
 * program or is refused; a writing program with a configuration name anywhere in the command; a program that moves or
 * deletes a folder holding a guarded path; `git clean`, `git stash -u`; package-manager commands that could replace the
 * guard or its node. Paths are compared as written and through symlinks (a dangling one followed), case-insensitively off Linux.
 */
export function configProtection(projects: readonly string[], toolName: string, toolInput: Readonly<Record<string, unknown>>, cwd: string | undefined, env: Env = process.env, extra: readonly Target[] = []): string | undefined {
  const { protect, exempt } = guardedPaths(projects, env, extra);
  const strictlyInside = (p: string, dir: string): boolean => caseFold(p).startsWith(caseFold(dir.endsWith(sep) ? dir : dir + sep));
  const exempted = (p: string): boolean => exempt.some((e) => strictlyInside(p, e.path));
  const guardedBy = (p: string): Target | undefined => (exempted(p) ? undefined : protect.find((t) => within(p, t)));
  const CONFIG = "Claude Code's configuration (.claude/, its settings files, .claude.json, .mcp.json), or Codex's (.codex/) or Cursor's (.cursor/)";
  const configNamed = (p: string): boolean => !exempted(p) && CONFIG_SEGMENT.test(caseFold(p));
  const base = cwd !== undefined && isAbsolute(cwd) ? cwd : projects[0]!;
  // The lexical path and the one the file system takes (each symlink followed before a later `..`: RA-01).
  const at = (raw: string): readonly [string, string] => { const home = expandShellHome(raw, env); return [resolve(base, home), physicalPath(home, base)]; };
  const hit = (raw: string): string | undefined => {
    const [abs, real] = at(raw);
    return (guardedBy(abs) ?? guardedBy(real))?.what ?? (configNamed(abs) || configNamed(real) ? CONFIG : undefined);
  };
  const holds = (raw: string): Target | undefined => { const [abs, real] = at(raw); return protect.find((t) => strictlyInside(t.path, abs) || strictlyInside(t.path, real)); };
  if (FILE_TOOLS.includes(toolName)) {
    const raw = PATH_KEYS.map((k) => toolInput[k]).find((v): v is string => typeof v === "string");
    if (raw === undefined) return undefined;
    return hit(raw) ?? (toolName === "Delete" ? holds(raw)?.what : undefined);
  }
  if (NO_WRITE_TOOLS.includes(toolName)) return undefined;
  const words = (s: string): string[] => (s.length <= 16_384 ? shellWords(s) : []).filter((w) => looksLikePath(w));
  const bare = (w: string): boolean => BARE_CONFIG_NAMES.includes(caseFold(w.replace(/[\\/]+$/, "")));
  if (SHELL_TOOLS.includes(toolName)) {
    const command = shellCommands(toolInput).join(" ");
    for (const spelling of commandSpellings(command)) {
      let writes = false; // some segment writes (a writing program that is not only reading, or a redirection)
      for (const segment of spelling.split(SEGMENT)) {
        const tokens = words(segment);
        if (tokens.length === 0) continue;
        if (gitRemovesUntracked(tokens)) return "the IronTrellis config and Claude Code's local settings (git clean and git stash -u remove untracked files)";
        const [program, args, assignments] = programAndArgs(tokens);
        if (SHELL_WRITERS.test(segment) && !readsOnly(program, args)) writes = true;
        if (packageManagerHit(program, args, assignments)) return "the installed IronTrellis guard or the node it runs with (a package manager could replace them)";
        const into = extractsInto(program, args, base);
        if (into !== undefined && (holds(into) !== undefined || hit(into) !== undefined || [".claude", ".mcp.json", ".claude.json", ".codex", ".cursor"].some((n) => at(into).some((dir) => existsSync(join(dir, n)))))) {
          return "a folder holding Claude Code's configuration or IronTrellis state (extracting, patching or checking out into it could overwrite them)";
        }
        const paths = args.filter((w) => !w.startsWith("-")).map(unredirected);
        if (REMOVERS.includes(program)) {
          const held = paths.map(holds).find((x) => x !== undefined);
          if (held !== undefined) return `a folder holding ${held.what}`;
        }
        if (COPIERS.includes(program) && paths.length > 0) {
          const held = holds(paths[paths.length - 1]!);
          if (held !== undefined) return `a folder holding ${held.what}`;
        }
        // A segment that names a guarded or configuration path may only read it.
        const named = tokens.flatMap(candidates).map((w) => hit(w) ?? (bare(w) ? CONFIG : undefined)).find((x) => x !== undefined);
        if (named !== undefined && !readsOnly(program, args)) return named;
      }
      // Across segments (`cd .claude && echo x > notes.txt`): a writing segment and a configuration name anywhere.
      if (writes && (CONFIG_NAMES.test(spelling) || words(spelling).map(unredirected).some(bare))) return CONFIG;
    }
    return undefined;
  }
  // Any other tool (an MCP server's file tools, Codex apply_patch, …); one that moves, renames or deletes, not a folder holding one either.
  const mover = /move|rename|delete|remove|unlink|trash|(?:^|_)rm(?:$|_)/i.test(toolName);
  for (const s of strings(toolInput)) {
    if (CONFIG_NAMES.test(s)) return CONFIG;
    const found = words(s).map(hit).find((x) => x !== undefined);
    if (found !== undefined) return found;
    if (mover) { const held = words(s).map(holds).find((x) => x !== undefined); if (held !== undefined) return `a folder holding ${held.what}`; }
  }
  return undefined;
}

/** The projects the guard serves: the config's, the directory holding the config, and the route's (CLAUDE_PROJECT_DIR). */
export const guardProjects = (config: HookConfig, env: Env = process.env): readonly string[] => {
  const route = env.CLAUDE_PROJECT_DIR;
  return [...new Set([config.project, dirname(config.path), ...(route !== undefined && route !== "" && isAbsolute(route) ? [canonicalProject(route)] : [])].map((p) => realpathLoose(p)))];
};

/** All three rules for one tool call; undefined when none applies. */
export function protection(config: HookConfig, toolName: string, toolInput: Readonly<Record<string, unknown>>, cwd: string | undefined, env: Env = process.env): Protection | undefined {
  const isShell = SHELL_TOOLS.includes(toolName) || config.policy.sideEffecting.some((r) => r.action === "run-shell" && r.tool === toolName);
  if (isShell) {
    const commands = shellCommands(toolInput);
    for (const command of commands) {
      const hit = controlCommand(command);
      if (hit !== undefined) return { code: "PROTECTED_COMMAND", reason: setupRefusal(hit, config.protocol) ?? `${CONTROL_REASON} (${hit})` };
    }
    const custody = custodyOf(config);
    if (custody.sshAgent && commands.some((command) => custodyCommand(command) !== undefined || matchesAny(command, SSH_AGENT_PATTERNS))) return { code: "PROTECTED_COMMAND", reason: CUSTODY_REASON };
    if (custody.vault && commands.some((command) => custodyCommand(command, VAULT_BINARIES) !== undefined || matchesAny(command, VAULT_PATTERNS))) return { code: "PROTECTED_COMMAND", reason: VAULT_REASON };
  }
  const ref = referencesProtected(config, toolName, toolInput, cwd);
  if (ref !== undefined) return { code: "PROTECTED_PATH", reason: `protected: the tool input references ${ref}; IronTrellis state is for the operator, not the agent` };
  const guarded = configProtection(guardProjects(config, env), isShell && !SHELL_TOOLS.includes(toolName) ? "Bash" : toolName, toolInput, cwd, env, protectedTargets(config, env));
  if (guarded !== undefined) return { code: "PROTECTED_PATH", reason: `protected: ${guarded}. In a guarded project the agent cannot change Claude Code's own configuration; the user changes it in their own terminal` };
  return undefined;
}
