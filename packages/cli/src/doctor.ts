/**
 * `irontrellis doctor [history] [--json] [--as-agent] [--offline] [--hook-config <file>]`: a read-only custody and
 * deployment audit (docs/CUSTODY.md §11). Each finding is `{ level: OK | WARN | FAIL, code, message, fix }`; the exit
 * status is 0 without a FAIL, 1 with one, 2 on a usage error.
 *
 * Doctor never signs, never writes and never contacts a signer in a way a person would have to approve: for an
 * ssh-agent it only LISTS identities; for Vault it only READS the key (`GET <mount>/keys/<key>`); a command signer is
 * never started ("not checked"). Remote witnesses get one `GET /v1/witness` each. `--offline` skips every network
 * and socket contact.
 *
 * `--as-agent` is for running doctor as the OS user the agent runs as (`sudo -u agent irontrellis doctor …`): what
 * that user can read or use becomes a FAIL (key material it can read, a Vault token it has) or a WARN (an ssh-agent
 * or command signer it can reach, which may still ask a person for each use).
 */
import { accessSync, constants, existsSync, readFileSync, statSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import {
  HISTORY_FILE_LIMITS, TRELLIS2_FORMAT, TRELLIS_FORMAT, agentSocketPath, checkVaultKey, isLoopbackHost, listAgentIdentities, nextOwnerKeyPathFor,
  openHistoryStore, ownerKeyPathFor, ownerKeyStatusOf, pendingNextOwnerKeyPathFor, pendingOwnerKeyPathFor, refusalSpoolPathFor, remoteWitness, retiredOwnerKeyFilesFor, signerBackend, spooledRefusalCount,
  vaultCaFile, vaultTokenSource, inspectKeyFile, ownerKeysAt, ownerKeyDigest, canonicalPath,
  type OwnerKeyReference, type SignerSpec,
} from "@ramex-labs/irontrellis";
import { UsageError, flag, str, type OptionSpec, type Parsed } from "./args.ts";
import { CliError, type Global } from "./history.ts";
import { dim, type Lines, type Style } from "./output.ts";

export type Level = "OK" | "WARN" | "FAIL";
export type Finding = Readonly<{ level: Level; area: string; code: string; message: string; fix: string | null }>;

/** docs/OPERATOR.md §4: plan a successor history at about 500,000 events or 500 MiB. */
export const SUCCESSOR_EVENTS = 500_000;
export const SUCCESSOR_BYTES = 500 * 1024 * 1024;
const SOCKET_TIMEOUT_MS = 5_000;

type Env = Readonly<Record<string, string | undefined>>;
const finding = (area: string, level: Level, code: string, message: string, fix: string | null = null): Finding => Object.freeze({ level, area, code, message, fix });

/** What a Codex config.toml says about hooks (`[features] hooks` or `codex_hooks`; the last wins), as irontrellis-hook reads it. */
function codexHooksSetting(text: string): boolean | undefined {
  let table = "", value: boolean | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s#.*$|^#.*$/, "").trim();
    const header = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (header !== null) { table = header[1]!.replace(/\s+/g, ""); continue; }
    const kv = /^([A-Za-z0-9_.-]+)\s*=\s*(true|false)$/.exec(line);
    if (kv === null) continue;
    const key = table === "" ? kv[1]! : `${table}.${kv[1]}`;
    if (key === "features.hooks" || key === "features.codex_hooks") value = kv[2] === "true";
  }
  return value;
}

// ---------------------------------------------------------------- pure checks (unit-tested directly)

/** History size against the hard file limit and the successor-history guideline. */
export function sizeFindings(bytes: number, events: number, format: string): readonly Finding[] {
  const limit = (HISTORY_FILE_LIMITS as Readonly<Record<string, number>>)[format] ?? HISTORY_FILE_LIMITS[TRELLIS_FORMAT];
  const mib = (n: number): string => `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  const successor = "plan a successor history (docs/OPERATOR.md §4): irontrellis init a new history, re-create what is still live, keep this one as a read-only archive";
  if (bytes >= limit * 0.9) {
    return [finding("history", "FAIL", "HISTORY_NEAR_FILE_LIMIT", `${mib(bytes)} of the ${mib(limit)} hard limit for ${format}: writes stop with HISTORY_FILE_LIMIT at the limit`, successor)];
  }
  const legacyGuide = format === "continuity-event/0.2" ? limit / 2 : SUCCESSOR_BYTES;
  if (events >= SUCCESSOR_EVENTS || bytes >= legacyGuide) {
    return [finding("history", "WARN", "HISTORY_SUCCESSOR_ADVISED", `${events} events, ${mib(bytes)}: past the successor guideline (about ${SUCCESSOR_EVENTS} events or ${mib(legacyGuide)}); opening and verifying grow with the history`, successor)];
  }
  return [finding("history", "OK", "HISTORY_SIZE", `${events} events, ${mib(bytes)} (successor guideline: about ${SUCCESSOR_EVENTS} events or ${mib(legacyGuide)}; hard limit ${mib(limit)})`)];
}

/** Platform notes: mode checks are off on Windows (ACLs decide), root reads everything. */
export function platformFindings(platform: NodeJS.Platform, uid: number | undefined): readonly Finding[] {
  if (platform === "win32") {
    return [finding("platform", "WARN", "PLATFORM_WIN32_MODES_OFF",
      "Windows: the 0600 mode and owner-uid checks on key files and references are off (POSIX modes do not exist there); NTFS ACLs alone decide who can read the owner key",
      "keep the history's key files readable only by the owner account (icacls <file> /inheritance:r /grant:r \"%USERNAME%:F\") and run the agent as another account (docs/CUSTODY.md §8)")];
  }
  const out: Finding[] = [finding("platform", "OK", "PLATFORM_POSIX", `${platform}: key files and references must be mode 0600 and owned by the user that runs IronTrellis (checked on every load)`)];
  if (uid === 0) {
    out.push(finding("platform", "WARN", "RUNNING_AS_ROOT", "running as root: root can read every key file and reach every signer socket, so the user separation below says nothing about root",
      "run IronTrellis as the owner's own OS user, and never run the agent as root"));
  }
  return out;
}

// ---------------------------------------------------------------- helpers

const readable = (path: string): boolean => { try { accessSync(path, constants.R_OK); return true; } catch { return false; } };
const executable = (path: string): boolean => { try { accessSync(path, constants.X_OK); return true; } catch { return false; } };
const who = (): string => {
  let name = "this user";
  try { name = userInfo().username; } catch { /* no passwd entry */ }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  return uid === undefined ? name : `${name} (uid ${uid})`;
};
/**
 * What a key file holds, read ONLY through the core loaders' checks (no symbolic link; POSIX: 0600, and a reference
 * owned by this user): a signer named by a file the loaders would refuse is never contacted and its token or CA file
 * never read. `unreadable`: this OS user cannot open it (the point, judged as the agent's user).
 */
type KeyFileView = Readonly<{ path: string; state: "material" | "reference" | "unreadable" | "refused"; reference?: OwnerKeyReference; why?: string; rawMaterial?: boolean }>;
function inspectKey(path: string, kind: "owner" | "next"): KeyFileView {
  try {
    const { reference } = inspectKeyFile(path, kind);
    return reference === undefined ? { path, state: "material" } : { path, state: "reference", reference };
  } catch (error) {
    const cause = (error as { detail?: { cause?: unknown } }).detail?.cause;
    if (cause === "EACCES" || cause === "EPERM" || !readable(path)) return { path, state: "unreadable" };
    // Refused (a loose mode, a foreign owner, a link, a malformed file): does it hold key material anyway (for KEY_FILE_MODE)?
    let rawMaterial = false;
    try { rawMaterial = typeof (JSON.parse(readFileSync(path, "utf8")) as { privateKey?: unknown }).privateKey === "string"; } catch { /* not JSON */ }
    return { path, state: "refused", why: error instanceof Error ? error.message : String(error), rawMaterial };
  }
}
const loadedReference = (path: string, kind: "owner" | "next"): OwnerKeyReference | undefined => (existsSync(path) ? inspectKey(path, kind).reference : undefined);
const looseMode = (path: string): boolean => {
  if (process.platform === "win32") return false;
  try { return (statSync(path).mode & 0o077) !== 0; } catch { return false; }
};

// ---------------------------------------------------------------- signer reachability (non-signing)

const SEPARATE_USER = "run the agent as another OS user than the owner (docs/CUSTODY.md §8: sudo -u agent, a service account, or another Windows account), so it cannot read the owner's files or use the owner's signer";

async function signerFindings(role: string, ref: OwnerKeyReference, asAgent: boolean, offline: boolean, env: Env): Promise<Finding[]> {
  const spec: SignerSpec = ref.signer;
  const area = "signer";
  const backend = signerBackend(spec.kind);
  const what = `${role} key ${ref.keyId} (${backend?.describe(spec) ?? spec.kind})`;
  if (offline) return [finding(area, "OK", "SIGNER_NOT_CHECKED", `${what}: not checked (--offline)`)];
  if (spec.kind === "ssh-agent") {
    const socket = agentSocketPath(spec, env);
    if (socket === undefined) {
      return [asAgent ? finding(area, "OK", "SIGNER_NOT_REACHABLE", `${what}: no ssh-agent socket for this user (SSH_AUTH_SOCK is not set and the reference names none)`)
        : finding(area, "WARN", "SIGNER_UNREACHABLE", `${what}: no ssh-agent socket here (SSH_AUTH_SOCK is not set and the reference names none): owner writes fail until one is`, "start the agent (or 1Password / gpg-agent) and export SSH_AUTH_SOCK, or name the socket in the reference")];
    }
    let keys;
    try { keys = await listAgentIdentities({ socket, timeoutMs: SOCKET_TIMEOUT_MS }); } catch (error) {
      const why = error instanceof Error ? error.message : String(error);
      return [asAgent ? finding(area, "OK", "SIGNER_NOT_REACHABLE", `${what}: this user cannot reach the ssh-agent at ${socket} (${why})`)
        : finding(area, "WARN", "SIGNER_UNREACHABLE", `${what}: the ssh-agent at ${socket} cannot be reached (${why}); owner writes fail until it can`, "start the agent, or fix the socket path in the reference / SSH_AUTH_SOCK")];
    }
    const held = keys.some((k) => k.type === "ssh-ed25519" && k.publicKey !== undefined && `0x${k.publicKey.toString("hex")}` === ref.publicKey);
    if (!held) {
      return [asAgent ? finding(area, "OK", "SIGNER_KEY_NOT_LISTED", `${what}: the ssh-agent at ${socket} that this user reaches does not list the key`)
        : finding(area, "WARN", "SIGNER_KEY_NOT_LISTED", `${what}: the ssh-agent at ${socket} does not list the key (${keys.length} keys listed; nothing was signed): owner writes fail until it is added`, "ssh-add the key (or unlock it in 1Password / insert the card for gpg-agent); irontrellis signer list shows what the agent offers")];
    }
    return [asAgent ? finding(area, "FAIL", "SIGNER_USABLE_BY_THIS_USER", `${what}: this user can ask the ssh-agent at ${socket} to sign as the owner (it lists the key); an agent that asks a person for every use (1Password approval, ssh-add -c with an askpass) would still stop it, but doctor cannot confirm that`, SEPARATE_USER)
      : finding(area, "OK", "SIGNER_REACHABLE", `${what}: the ssh-agent at ${socket} lists the key (only listed; nothing was signed)`)];
  }
  if (spec.kind === "vault-transit") {
    const out: Finding[] = [];
    const source = vaultTokenSource(spec, env);
    if (source.path !== undefined && existsSync(source.path) && looseMode(source.path)) {
      out.push(finding(area, "WARN", "VAULT_TOKEN_FILE_LOOSE", `${what}: the Vault token file ${source.path} is readable by other users`, `chmod 600 ${source.path}`));
    }
    const ca = vaultCaFile(spec, env);
    if (ca !== undefined && !existsSync(ca)) out.push(finding(area, "WARN", "VAULT_CA_FILE_MISSING", `${what}: the CA file ${ca} does not exist`, "fix caFile in the reference (irontrellis signer ref --vault-ca-file) or VAULT_CACERT"));
    if (asAgent && source.path !== undefined && existsSync(source.path) && readable(source.path)) {
      out.push(finding(area, "FAIL", "VAULT_TOKEN_READABLE", `${what}: this user can read the Vault token file ${source.path}`, `${SEPARATE_USER}; the token file must be readable by the owner only`));
    }
    if (asAgent && ca !== undefined && existsSync(ca)) {
      let writable = false;
      try { accessSync(ca, constants.W_OK); writable = true; } catch { /* not writable */ }
      // A CA bundle is public (reading it gives nothing); replacing it lets this user put itself between the owner and Vault.
      if (writable) out.push(finding(area, "FAIL", "VAULT_CA_FILE_WRITABLE", `${what}: this user can write the CA file ${ca}, and so make the owner's process trust a server it runs`, "make the CA file owned by root or the owner and not writable by the agent's user"));
    }
    const check = await checkVaultKey(spec, { keyId: ref.keyId, publicKey: ref.publicKey }, env);
    const tokenFrom = source.source === "VAULT_TOKEN" ? "VAULT_TOKEN in this environment" : `the token in ${source.path!}`;
    if (check.ok) {
      out.push(asAgent ? finding(area, "FAIL", "SIGNER_USABLE_BY_THIS_USER", `${what}: this user has a Vault token (${tokenFrom}) that reads the owner's Transit key; a token that can read it is normally one that can sign with it`, `${SEPARATE_USER}; give the agent's user no Vault token for this key (no VAULT_TOKEN in its environment, no readable ~/.vault-token or token file)`)
        : finding(area, "OK", "SIGNER_REACHABLE", `${what}: ${check.message} (key read with ${tokenFrom}; nothing was signed)`));
    } else if (check.code === "KEY_UNAVAILABLE") {
      out.push(finding(area, "FAIL", "SIGNER_KEY_UNAVAILABLE", `${what}: ${check.message}`, "point the reference at the right key and pinned version (irontrellis signer ref --signer vault-transit …), or restore the key in Vault; if it is gone for good, rotate with the next key (docs/CUSTODY.md §10)"));
    } else if (asAgent && check.reason === "PERMISSION_DENIED") {
      // A token whose policy grants sign but not read gets PERMISSION_DENIED on the key read: not proven unusable.
      out.push(finding(area, "WARN", "SIGNER_NOT_PROVEN_UNUSABLE", `${what}: this user has a Vault token (${tokenFrom}) that Vault refuses to read the key with; it may still be allowed to sign (a policy with update on sign/<key> only), and doctor never asks for a signature`, `${SEPARATE_USER}; give the agent's user no Vault token at all`));
    } else if (asAgent) {
      out.push(finding(area, "OK", "SIGNER_NOT_REACHABLE", `${what}: this user cannot use Vault for this key (${check.reason ?? "failed"}: ${check.message})`));
    } else {
      out.push(finding(area, "WARN", "SIGNER_UNREACHABLE", `${what}: ${check.message}`, check.reason === "NO_TOKEN" || check.reason === "PERMISSION_DENIED"
        ? "give the owner's process a token whose policy reads and signs with this key (vault login, VAULT_TOKEN, or tokenFile in the reference)"
        : "check the Vault address, its TLS CA (--vault-ca-file / VAULT_CACERT) and that it is unsealed"));
    }
    return out;
  }
  if (spec.kind === "command") {
    const program = (spec.argv as readonly string[])[0]!;
    if (!existsSync(program)) {
      return [finding(area, asAgent ? "OK" : "WARN", "SIGNER_PROGRAM_MISSING", `${what}: the program ${program} does not exist${asAgent ? " for this user" : "; owner writes fail until it does"}`, asAgent ? null : "install the signing program at that path, or fix the reference's argv")];
    }
    if (asAgent && executable(program)) {
      return [finding(area, "WARN", "SIGNER_USABLE_BY_THIS_USER", `${what}: this user can run ${program}; whether it signs without a person or a credential this user lacks depends on the program (not checked: it is only started to sign)`, SEPARATE_USER)];
    }
    return [finding(area, "OK", "SIGNER_NOT_CHECKED", `${what}: not checked (a command signer is only started to sign; irontrellis signer test --key ${role === "next" ? "next" : "current"} runs it once)`)];
  }
  return [finding(area, "OK", "SIGNER_NOT_CHECKED", `${what}: a host-registered signer kind; not checked`)];
}

// ---------------------------------------------------------------- hooks

type HookView = Readonly<{ path: string; history: string; project: string }>;

function findHookConfig(explicit: string | undefined, env: Env): string | undefined {
  if (explicit !== undefined) return resolve(explicit);
  if (env.IRONTRELLIS_HOOK_CONFIG !== undefined && env.IRONTRELLIS_HOOK_CONFIG !== "") return resolve(env.IRONTRELLIS_HOOK_CONFIG);
  for (let dir = process.cwd(); ; dir = dirname(dir)) {
    const candidate = join(dir, "irontrellis-hook.json");
    if (existsSync(candidate)) return candidate;
    if (dirname(dir) === dir) return undefined;
  }
}

/** The signer paths the hooks derive from a reference (packages/hooks/src/protect.ts `custodyOf`, same rules). */
export function hookSignerPaths(ref: OwnerKeyReference | undefined, env: Env): string[] {
  const spec = ref?.signer;
  if (spec === undefined) return [];
  if (spec.kind === "ssh-agent") {
    const socket = typeof spec.socket === "string" ? spec.socket : env.SSH_AUTH_SOCK;
    return socket !== undefined && socket !== "" && isAbsolute(socket) ? [socket] : [];
  }
  if (spec.kind === "command") return (spec.argv as readonly string[]).filter((arg) => isAbsolute(arg));
  if (spec.kind === "vault-transit") {
    const out: string[] = [];
    const source = vaultTokenSource(spec, env);
    if (source.path !== undefined) out.push(source.path);
    if (typeof spec.caFile === "string") out.push(spec.caFile);
    return out;
  }
  return [];
}

function hookFindings(history: string, explicit: string | undefined, env: Env, sensitive: readonly Readonly<{ path: string; what: string }>[]): Finding[] {
  const area = "hooks";
  const file = findHookConfig(explicit, env);
  const install = "irontrellis-hook init (in the agent's project), then irontrellis-hook install claude-code|codex|cursor --write";
  if (file === undefined || !existsSync(file)) {
    return [finding(area, "WARN", "HOOKS_NOT_FOUND", `no irontrellis-hook.json names this history (looked: ${explicit !== undefined ? explicit : env.IRONTRELLIS_HOOK_CONFIG ? "IRONTRELLIS_HOOK_CONFIG" : `${process.cwd()} and its parents`}): the agent's tool calls are not checked and the protect list is not enforced`, `${install}; or pass --hook-config <file>`)];
  }
  let view: HookView;
  try {
    const raw = JSON.parse(readFileSync(file, "utf8")) as { history?: unknown };
    if (typeof raw.history !== "string") throw new Error("no history field");
    const project = dirname(resolve(file));
    view = { path: resolve(file), project, history: isAbsolute(raw.history) ? raw.history : resolve(project, raw.history) };
  } catch (error) {
    return [finding(area, "WARN", "HOOKS_CONFIG_INVALID", `${file} cannot be read as a hook config (${error instanceof Error ? error.message : String(error)})`, "fix it or re-create it with irontrellis-hook init")];
  }
  // A-184.1: paths are compared after canonicalising both sides (symlinks resolved), never as strings.
  if (canonicalPath(view.history) !== canonicalPath(history)) {
    return [finding(area, "WARN", "HOOKS_OTHER_HISTORY", `${view.path} names another history (${view.history}): its hooks do not guard this one`, `pass the right --hook-config, or point that config's "history" at ${history}`)];
  }
  const out: Finding[] = [];
  const hosts = [[".claude/settings.json", "Claude Code"], [".codex/hooks.json", "Codex"], [".cursor/hooks.json", "Cursor"]]
    .filter(([rel]) => { try { return readFileSync(join(view.project, rel!), "utf8").includes("irontrellis-hook"); } catch { return false; } }).map(([, name]) => name!);
  // The Claude Code plugin route (the IronTrellis plugin runs the same guard): enabled in the user, project or local settings.
  const claude = claudeRoutes(view.project, env);
  if (claude.plugin && !hosts.includes("Claude Code")) hosts.push("Claude Code (the IronTrellis plugin)");
  out.push(hosts.length > 0 ? finding(area, "OK", "HOOKS_INSTALLED", `${view.path} guards this history; hooks installed for ${hosts.join(", ")} in ${view.project}`)
    : finding(area, "WARN", "HOOKS_NOT_INSTALLED", `${view.path} names this history, but no host settings in ${view.project} run irontrellis-hook (.claude/settings.json, .codex/hooks.json, .cursor/hooks.json) and the irontrellis Claude Code plugin is not enabled`, "irontrellis-hook install claude-code|codex|cursor --write (in that project), or enable the irontrellis plugin"));
  // Codex runs no hook when its config turns hooks off (live check B of the Codex route): user (CODEX_HOME, else ~/.codex),
  // then project; the last value wins. The same reading as irontrellis-hook init's (packages/hooks/src/setup.ts).
  if (hosts.includes("Codex")) {
    const home = env.CODEX_HOME !== undefined && env.CODEX_HOME !== "" ? env.CODEX_HOME : join(env.HOME !== undefined && env.HOME !== "" ? env.HOME : homedir(), ".codex");
    let off: string | undefined;
    for (const file of [join(home, "config.toml"), join(view.project, ".codex", "config.toml")]) {
      let text: string;
      try { text = readFileSync(file, "utf8"); } catch { continue; }
      const setting = codexHooksSetting(text);
      if (setting !== undefined) off = setting ? undefined : file;
    }
    if (off !== undefined) out.push(finding(area, "WARN", "HOOKS_DISABLED", `${off} sets [features] hooks = false: Codex runs no hooks, so the Codex hooks in ${view.project} guard nothing`, `remove the setting in ${off} (in your own terminal), or set hooks = true`));
  }
  if (claude.plugin && claude.hookEvents.length === 4) out.push(finding(area, "WARN", "HOOKS_INSTALLED_TWICE", `the IronTrellis plugin for Claude Code and the hook entries in ${view.project}/.claude are both present; the plugin steps aside and the hook is the one guard`, "choose one route per project: disable the plugin, or remove the hook entries"));
  for (const entry of claude.unrecognized) out.push(finding(area, "WARN", "HOOKS_ENTRY_UNRECOGNIZED", `unrecognized IronTrellis hook entry: ${entry}; it is not the entry irontrellis-hook install writes, so it does not count as the hook route`, "remove it, or re-run irontrellis-hook install claude-code --write"));
  // The protect list: the history path is a prefix (every <history>.* side file, key files and references included),
  // the hook config, and the signer paths of the current, next and retired key references.
  const covered = new Set([
    ...hookSignerPaths(loadedReference(ownerKeyPathFor(history), "owner"), env), ...hookSignerPaths(loadedReference(nextOwnerKeyPathFor(history), "next"), env), view.path,
    ...retiredOwnerKeyFilesFor(history).flatMap((file) => hookSignerPaths(loadedReference(file, "owner"), env)),
    ...(env.IRONTRELLIS_WITNESS_POLICY !== undefined && isAbsolute(env.IRONTRELLIS_WITNESS_POLICY) ? [env.IRONTRELLIS_WITNESS_POLICY] : []),
  ]);
  const gaps = sensitive.filter((s) => !s.path.startsWith(history) && !covered.has(s.path));
  out.push(gaps.length === 0 ? finding(area, "OK", "HOOKS_PROTECT_COVERS", `the hooks' protect list covers the history and its key files${sensitive.length > 0 ? ` and ${sensitive.filter((s) => !s.path.startsWith(history)).map((s) => s.path).join(", ") || "nothing else"}` : ""}`)
    : finding(area, "WARN", "HOOKS_PROTECT_GAP", `the hooks do not protect ${gaps.map((g) => `${g.path} (${g.what})`).join(", ")}`, "keep these where only the owner's OS user can read them (the hooks are a tripwire, not a boundary), or use an absolute IRONTRELLIS_WITNESS_POLICY path"));
  return out;
}

// ---------------------------------------------------------------- witnesses

/** The out-of-band minimum witness policy (IRONTRELLIS_WITNESS_POLICY): presence, absolute path, who can write it. */
function policyFindings(env: Env, asAgent: boolean): Finding[] {
  const area = "witness";
  const out: Finding[] = [];
  const policyFile = env.IRONTRELLIS_WITNESS_POLICY;
  if (policyFile === undefined || policyFile === "") {
    out.push(finding(area, "OK", "WITNESS_POLICY_NOT_SET", "IRONTRELLIS_WITNESS_POLICY is not set (no out-of-band minimum witness policy; the policy bound in the history applies)"));
  } else if (!isAbsolute(policyFile)) {
    out.push(finding(area, "WARN", "WITNESS_POLICY_RELATIVE", `IRONTRELLIS_WITNESS_POLICY is a relative path (${policyFile}): it resolves differently per working directory and the hooks cannot protect it`, "use an absolute path"));
  } else if (!existsSync(policyFile)) {
    out.push(finding(area, "FAIL", "WITNESS_POLICY_MISSING", `IRONTRELLIS_WITNESS_POLICY names ${policyFile}, which does not exist`, "restore the file or unset the variable (docs/reference/witness-policy.md §5.4)"));
  } else {
    let writableByUs = false;
    try { accessSync(policyFile, constants.W_OK); writableByUs = true; } catch { /* not writable */ }
    const others = process.platform !== "win32" && (statSync(policyFile).mode & 0o022) !== 0;
    if (others) out.push(finding(area, "WARN", "WITNESS_POLICY_WRITABLE", `${policyFile} (IRONTRELLIS_WITNESS_POLICY) is writable by group or others: whoever can write it can lower the minimum witness policy`, `chmod go-w ${policyFile}`));
    else if (asAgent && writableByUs) out.push(finding(area, "FAIL", "WITNESS_POLICY_WRITABLE", `${policyFile} (IRONTRELLIS_WITNESS_POLICY) is writable by this user`, "make it owned by the owner's OS user and not writable by the agent's"));
    else out.push(finding(area, "OK", "WITNESS_POLICY", `IRONTRELLIS_WITNESS_POLICY ${policyFile} is present and not writable by group or others`));
  }
  return out;
}

async function witnessFindings(store: ReturnType<typeof openHistoryStore>, asAgent: boolean, offline: boolean, env: Env): Promise<Finding[]> {
  const area = "witness";
  const out: Finding[] = [];
  const st = store.witnessStatus();
  if (st === undefined || st.bound.length === 0) {
    out.push(finding(area, "WARN", "NO_WITNESS", "no remote witness is bound to this history: a restored older copy of the file (a rollback) cannot be told from the latest one, beyond the local pin",
      "irontrellis witness add <url> --verifier-key <key> (docs/WITNESS.md)"));
    return out;
  }
  out.push(...witnessStateFindings(st));
  for (const w of st.witnesses.filter((x) => x.bound)) {
    if (offline) { out.push(finding(area, "OK", "WITNESS_NOT_CHECKED", `${w.url}: not contacted (--offline)`)); continue; }
    const config = st.bound.find((b) => b.url === w.url);
    try {
      const info = await remoteWitness({ url: w.url, verifierKey: w.verifierKey, timeoutMs: SOCKET_TIMEOUT_MS, ...(config?.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}) }).info();
      out.push(finding(area, "OK", "WITNESS_REACHABLE", `${w.url} answers as ${info.origin} with the bound verifier key`));
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      const message = error instanceof Error ? error.message : String(error);
      out.push(/verifier key/.test(message) ? finding(area, "FAIL", "WITNESS_KEY_MISMATCH", `${w.url}: ${message}`, "the URL now serves another witness: check it with the witness operator before writing")
        : finding(area, "WARN", "WITNESS_UNREACHABLE", `${w.url} cannot be reached (${typeof code === "string" ? `${code}: ` : ""}${message}); writes queue their statements, and readers that require the witness fail`, "check the witness and the network; irontrellis witness status"));
    }
  }
  if (out.every((f) => f.level === "OK")) out.push(finding(area, "OK", "WITNESS_BOUND", `${st.bound.length} bound witness(es), quorum ${st.policy.quorum}, mode ${st.policy.mode}; witnessed up to position ${st.witnessedPosition ?? "unknown"}`));
  return out;
}

/** What the remote witness side file says (no network): alarms, refusals, rotations in flight, the queue, plain http, missing receipts. */
export function witnessStateFindings(st: Readonly<{
  alarm?: Readonly<{ code: string; message: string }>; rejected?: Readonly<{ url: string; code: string; message: string }>; rotationPending?: Readonly<{ position: number }>;
  rotationIncomplete: boolean; unwitnessedEvents: number; witnesses: readonly Readonly<{ url: string; bound: boolean; registered: boolean }>[];
}>): Finding[] {
  const area = "witness";
  const out: Finding[] = [];
  if (st.alarm !== undefined) out.push(finding(area, "FAIL", "WITNESS_ALARM", `${st.alarm.code}: ${st.alarm.message}`, "docs/OPERATOR.md §6 (remote witness rollback / split view)"));
  if (st.rejected !== undefined) out.push(finding(area, "FAIL", "WITNESS_REJECTED", `${st.rejected.url} refused the history (${st.rejected.code}: ${st.rejected.message}); owner writes refuse until the policy for it changes`, "fix the registration token or remove the witness (irontrellis witness remove)"));
  if (st.rotationPending !== undefined) out.push(finding(area, "WARN", "ROTATION_PENDING", `a prepared two-phase owner key rotation is outstanding (position ${st.rotationPending.position}): writes wait until an owner process completes or discards it`, "run irontrellis owner rotate-key again with the same next key to finish it"));
  if (st.rotationIncomplete) out.push(finding(area, "WARN", "ROTATION_INCOMPLETE", "a bound witness has not recorded an owner key rotation yet: until it does, it still accepts head statements signed by the retired key", "irontrellis witness sync (with the retired key's file or reference still in place)"));
  if (st.unwitnessedEvents > 0) out.push(finding(area, "WARN", "UNWITNESSED_EVENTS", `${st.unwitnessedEvents} event(s) not yet held by a quorum of witnesses`, "irontrellis witness sync"));
  for (const w of st.witnesses.filter((x) => x.bound)) {
    const url = new URL(w.url);
    if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) out.push(finding(area, "WARN", "WITNESS_INSECURE_HTTP", `${w.url} is plain http to a host that is not loopback: anyone on the path can read and suppress statements`, "serve the witness over https and bind the https URL"));
    if (!w.registered) out.push(finding(area, "WARN", "WITNESS_UNREGISTERED", `${w.url} has no registration receipt for this history recorded here`, "irontrellis witness sync (or witness status to see why)"));
  }
  return out;
}

// ---------------------------------------------------------------- the history's directory and the agent's environment

/**
 * Who can change the history. Judged as the agent's user: writing the directory or any owner side
 * file is a FAIL (it could swap references, pins, the next key). As the owner: a group- or other-writable directory
 * without the sticky bit is a WARN.
 */
function directoryFindings(history: string, keyPaths: readonly string[], asAgent: boolean): Finding[] {
  const dir = dirname(history);
  const writable = (path: string): boolean => { try { accessSync(path, constants.W_OK); return true; } catch { return false; } };
  if (asAgent) {
    const out: Finding[] = [];
    if (writable(dir)) out.push(finding("access", "FAIL", "HISTORY_DIR_WRITABLE", `this user can write ${dir}: it can rename or replace the history's key references, pin and next key`, "make the directory owned by the owner and not writable by the agent's user (e.g. owner:group 0750, docs/CUSTODY.md §8)"));
    const side = [history, `${history}.head`, `${history}.anchors`, `${history}.witness.json`, `${history}.rotation.pending.json`, `${history}.lock`, ...keyPaths].filter((p) => existsSync(p) && writable(p));
    if (side.length > 0) out.push(finding("access", "FAIL", "SIDE_FILE_WRITABLE", `this user can write ${side.join(", ")}`, "the history and its side files must be the owner's; the agent's user may read the history and its pin only (chmod 0640, a shared group)"));
    if (out.length === 0) out.push(finding("access", "OK", "HISTORY_NOT_WRITABLE", `this user cannot write ${dir} or the history's files`));
    return out;
  }
  if (process.platform === "win32") return [];
  try {
    const mode = statSync(dir).mode;
    if ((mode & 0o022) !== 0 && (mode & 0o1000) === 0) {
      return [finding("access", "WARN", "HISTORY_DIR_LOOSE", `${dir} is writable by group or others (mode 0${(mode & 0o7777).toString(8)}) without the sticky bit: they can rename or replace the history's references and pin`, `chmod go-w ${dir} (the agent's user needs to read the history, never to write its directory)`)];
    }
  } catch { /* the store opened it: stat is not expected to fail */ }
  return [];
}

/**
 * Judged as the agent's user: signer credentials this user's environment offers, whatever the
 * references say (the agent's user usually cannot read them). The ssh-agent is only asked to LIST its keys.
 */
async function environmentFindings(state: Readonly<Parameters<typeof ownerKeysAt>[0]> & { head: { position: number }; ownerKeyEpochs: readonly { nextKeyDigests?: readonly string[] }[] }, asAgent: boolean, offline: boolean, env: Env): Promise<Finding[]> {
  const area = "environment";
  const out: Finding[] = [];
  if (env.VAULT_TOKEN !== undefined && env.VAULT_TOKEN !== "") {
    out.push(finding(area, "FAIL", "VAULT_TOKEN_IN_ENVIRONMENT", "VAULT_TOKEN is set in this user's environment: an agent started from it can use that token (whatever the Vault reference says, which this user may not be able to read)", "start the agent without VAULT_TOKEN; the owner's token belongs in a tokenFile only the owner can read"));
  }
  const home = env.HOME !== undefined && env.HOME !== "" ? env.HOME : undefined;
  if (home !== undefined && existsSync(join(home, ".vault-token")) && readable(join(home, ".vault-token"))) {
    out.push(finding(area, "FAIL", "VAULT_TOKEN_FILE_READABLE", `this user can read ${join(home, ".vault-token")} (a Vault token, the Vault CLI's default): if it can use the owner's Transit key, the agent can sign as the owner`, "remove the agent user's ~/.vault-token (vault token revoke -self first), or make sure its policy has no access to the owner's keys"));
  }
  const socket = env.SSH_AUTH_SOCK;
  if (socket !== undefined && socket !== "") {
    if (offline) out.push(finding(area, "WARN", "SSH_AUTH_SOCK_NOT_CHECKED", `SSH_AUTH_SOCK is set (${socket}); not contacted (--offline), so whether that agent holds an owner key is not known`, "run without --offline, or start the agent without SSH_AUTH_SOCK"));
    else {
      let keys: Awaited<ReturnType<typeof listAgentIdentities>> | undefined;
      try { keys = await listAgentIdentities({ socket, timeoutMs: SOCKET_TIMEOUT_MS }); } catch { keys = undefined; }
      if (keys !== undefined) {
        const next = state.head.position + 1;
        const inForce = new Set(ownerKeysAt(state as Parameters<typeof ownerKeysAt>[0], next).map((k) => k.credential.toLowerCase()));
        const digests = new Set(state.ownerKeyEpochs.at(-1)?.nextKeyDigests ?? []);
        const held = keys.filter((k) => k.type === "ssh-ed25519" && k.publicKey !== undefined).map((k) => `0x${k.publicKey!.toString("hex")}`)
          .filter((pk) => inForce.has(pk) || digests.has(ownerKeyDigest({ scheme: "ed25519", credential: pk })));
        out.push(held.length > 0
          ? finding(area, "FAIL", "SSH_AGENT_HOLDS_OWNER_KEY", `the ssh-agent at SSH_AUTH_SOCK (${socket}) holds ${held.length === 1 ? "an owner or committed next key" : `${held.length} owner or committed next keys`} of this history (${held.join(", ")}); this user can ask it to sign (only listed; nothing was signed)`, `${SEPARATE_USER}; start the agent without SSH_AUTH_SOCK, or with an agent that holds no owner key`)
          : finding(area, "OK", "SSH_AGENT_NO_OWNER_KEY", `the ssh-agent at SSH_AUTH_SOCK (${socket}) holds no owner or committed next key of this history (${keys.length} keys listed)`));
      }
    }
  }
  if (out.length === 0 && asAgent) out.push(finding(area, "OK", "NO_SIGNER_CREDENTIALS", "no VAULT_TOKEN, no readable ~/.vault-token, no SSH_AUTH_SOCK with an owner key in this user's environment"));
  return out;
}

// ---------------------------------------------------------------- the audit

const CUSTODY_FIX: Readonly<Record<string, string>> = {
  OWNER_KEY_FILE_ON_HOST: "move the key into a signer (irontrellis signer to-ssh --key current, then ssh-add; or a Vault Transit key) and replace the file by a reference, or keep it readable only by an owner OS user the agent does not run as (docs/CUSTODY.md)",
  KEY_FILE_UNREADABLE: "restore the owner key file or reference (0600, owned by this user); irontrellis signer test --key current checks it",
  NO_NEXT_KEY_COMMITMENT: "irontrellis owner commit-next-key --public-key <a key held elsewhere> (or --next-key-ref <reference>): pre-rotation (docs/CUSTODY.md)",
  NEXT_KEY_SAME_SIGNER: "keep the next key in another signer: another agent socket, a hardware key kept offline, a Vault key behind its own token (tokenFile with a policy for that key only)",
  NEXT_KEY_ON_HOST: "move the next-key file offline (it is needed only to rotate; owner rotate-key --next-key <file> brings it back)",
  RETIRED_KEY_FILE: "move the retired key file offline once every bound witness recorded the rotation (irontrellis witness status)",
  NEXT_KEY_STALE: "remove the stale next-key file", NEXT_KEY_RETIRED: "archive it offline with the retired keys", NEXT_KEY_UNCOMMITTED: "remove it, or commit it: irontrellis owner commit-next-key",
  NEXT_KEY_UNREADABLE: "restore the next-key file (0600, owned by this user)", KEY_FILE_PENDING: "open the history as the owner (any owner write, or irontrellis owner status) to complete or discard it",
};

export type DoctorReport = Readonly<{
  history: string; user: string; asAgent: boolean; platform: string; findings: readonly Finding[]; summary: Readonly<{ ok: number; warn: number; fail: number }>; ok: boolean;
}>;

export async function doctor(history: string, options: Readonly<{ asAgent?: boolean; offline?: boolean; hookConfig?: string; env?: Env }> = {}): Promise<DoctorReport> {
  const env = options.env ?? process.env, asAgent = options.asAgent === true, offline = options.offline === true;
  const findings: Finding[] = [];
  const add = (...items: readonly Finding[]): void => { findings.push(...items); };
  add(...platformFindings(process.platform, typeof process.getuid === "function" ? process.getuid() : undefined));
  add(...policyFindings(env, asAgent));
  const done = (): DoctorReport => {
    const summary = { ok: findings.filter((f) => f.level === "OK").length, warn: findings.filter((f) => f.level === "WARN").length, fail: findings.filter((f) => f.level === "FAIL").length };
    return Object.freeze({ history, user: who(), asAgent, platform: process.platform, findings: Object.freeze([...findings]), summary, ok: summary.fail === 0 });
  };
  if (!existsSync(history)) {
    add(finding("history", "FAIL", "HISTORY_NOT_FOUND", `no history at ${history}`, "name the history (doctor <file>, --history or IRONTRELLIS_HISTORY), or create one with irontrellis init"));
    return done();
  }
  const bytes = statSync(history).size;
  let store: ReturnType<typeof openHistoryStore>;
  let state: ReturnType<ReturnType<typeof openHistoryStore>["state"]>;
  try {
    store = openHistoryStore(history, { inspect: true, allowUnpinned: true });
    try { state = store.state(); } catch (error) { store.close(); throw error; }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    add(finding("history", "FAIL", "HISTORY_UNREADABLE", `the history cannot be opened: ${(error as { code?: string }).code ?? "ERROR"}: ${message}`, /EACCES|EPERM/.test(message)
      ? "the hooks run as the agent's OS user and must read the history and its pin (never its key files): give that user read access to <history>, <history>.head and the bundles, e.g. a shared group and mode 0640 (docs/CUSTODY.md §8)"
      : "irontrellis verify says more; docs/OPERATOR.md §6 lists the recoveries"));
    return done();
  }
  try {
    add(...sizeFindings(bytes, state.events.length, state.format));
    // Refusals not written within the recording budget wait in the spool, outside the history, until that agent is refused again.
    const spooled = spooledRefusalCount(history);
    if (spooled > 0) add(finding("history", "WARN", "REFUSALS_SPOOLED", `${spooled} refusal${spooled === 1 ? "" : "s"} wait in ${refusalSpoolPathFor(history)}, not yet in the history: they were not recorded within the recording budget and are recorded when the same agent is refused again (decided again then; one that no longer reproduces goes to <history>.refusals.log instead)`,
      "keep the spool file; the agent's next recorded refusal drains it"));
    const report = store.verify();
    add(report.ok ? finding("history", "OK", "HISTORY_VERIFIES", `the chain, pin (${report.pinnedHeadStatus}) and control signatures verify (local check; irontrellis verify also asks the witnesses)`)
      : finding("history", "FAIL", "HISTORY_VERIFY_FAILED", report.failures.join("; "), "irontrellis verify, then docs/OPERATOR.md §6"));
    if (state.format !== TRELLIS2_FORMAT) {
      // Legacy and format-1 files are read only in this release (SPEC §16.1): custody of their keys no longer protects new writes.
      add(finding("custody", "WARN", state.format === TRELLIS_FORMAT ? "FORMAT_1_READ_ONLY" : "LEGACY_FORMAT", `${state.format}: this release reads the history but does not write it${state.format === TRELLIS_FORMAT ? "" : " (a legacy history has no owner key)"}`, "irontrellis migrate <history> <new> (a format-2 successor under an owner key)"));
      add(...await witnessFindings(store, asAgent, offline, env));
      add(...hookFindings(history, options.hookConfig, env, []));
      return done();
    }
    // Custody per key (owner status), and what weakens pre-rotation.
    const status = ownerKeyStatusOf(history, state);
    for (const entry of status.custody) {
      // Judged as the agent's user, a key file it cannot read is the point: the access section reports it.
      if (asAgent && entry.code === "KEY_FILE_UNREADABLE" && existsSync(ownerKeyPathFor(history)) && !readable(ownerKeyPathFor(history))) continue;
      add(finding("custody", entry.level, entry.code, `${entry.role}${entry.keyId === undefined ? "" : ` ${entry.keyId}`}: ${entry.message}`, entry.level === "OK" ? null : CUSTODY_FIX[entry.code] ?? null));
    }
    const seen = new Set(status.custody.map((c) => c.code));
    for (const w of status.warnings) if (!seen.has(w.code) && !(asAgent && w.code === "NEXT_KEY_UNREADABLE" && !readable(nextOwnerKeyPathFor(history)))) add(finding("custody", "WARN", w.code, w.message, CUSTODY_FIX[w.code] ?? null));
    // Every key file, read through the loaders' checks only: material, reference, unreadable (as this user), refused.
    const user = who();
    const views: KeyFileView[] = [
      ...[[ownerKeyPathFor(history), "owner"], [nextOwnerKeyPathFor(history), "next"], [pendingOwnerKeyPathFor(history), "owner"], [pendingNextOwnerKeyPathFor(history), "next"]] as const,
      ...retiredOwnerKeyFilesFor(history).map((path) => [path, "owner"] as const),
    ].filter(([path]) => existsSync(path)).map(([path, kind]) => inspectKey(path, kind));
    const keyPaths = views.map((v) => v.path);
    const materialReadable = views.filter((v) => v.state === "material" || (v.state === "refused" && v.rawMaterial === true)).map((v) => v.path);
    const unreadable = views.filter((v) => v.state === "unreadable").map((v) => v.path);
    if (materialReadable.length > 0) {
      add(finding("access", asAgent ? "FAIL" : "WARN", "KEY_MATERIAL_READABLE",
        `${user} can read owner key material: ${materialReadable.join(", ")}${asAgent ? ": the agent, running as this user, can sign as the owner" : ": an agent running as this user can sign as the owner"}`, SEPARATE_USER));
    } else if (!views.some((v) => v.state === "refused" || v.state === "unreadable")) {
      add(finding("access", "OK", "NO_KEY_MATERIAL_ON_HOST", "no owner key material beside the history (the keys are held by signers, or only public keys are committed)"));
    }
    if (unreadable.length > 0) {
      // Judged as the agent's user, that is the point. As the owner, its own key files must be its own: an unreadable one
      // means owner writes fail, or that someone else put a file there (a directory others can write).
      add(finding("access", asAgent ? "OK" : "FAIL", "KEY_FILES_NOT_READABLE", `${user} cannot read ${unreadable.join(", ")} (key files or key references: which, this user cannot tell)`,
        asAgent ? null : "the history's key files and references must be the owner's (owned by this user, mode 0600); if you did not put an unreadable file there, someone who can write the directory did: restore the reference you wrote (docs/CUSTODY.md §8)"));
    }
    for (const v of views.filter((x) => x.state === "refused" && x.rawMaterial === true && looseMode(x.path))) add(finding("access", "FAIL", "KEY_FILE_MODE", `${v.path} is readable by group or others`, `chmod 600 ${v.path}`));
    for (const v of views.filter((x) => x.state === "refused" && x.rawMaterial !== true)) {
      add(finding("access", "FAIL", "REFERENCE_REFUSED", `${v.path} is refused by the key loaders, so its signer was not contacted and no token or CA file it names was read: ${v.why}`,
        "replace it with a reference you wrote (irontrellis signer ref --out …): mode 0600, owned by the user that runs IronTrellis, not a symbolic link; if you did not put it there, someone who can write the history's directory did (docs/CUSTODY.md §8)"));
    }
    // Who can change the history and its side files: whoever can write the directory can swap references and pins.
    add(...directoryFindings(history, keyPaths, asAgent));
    // Signers that hold the current and the next key: reachable, holding the key, and by whom (loaded references only).
    const refs: Array<[string, OwnerKeyReference]> = [];
    const currentView = views.find((v) => v.path === ownerKeyPathFor(history)), nextView = views.find((v) => v.path === nextOwnerKeyPathFor(history));
    if (currentView?.reference !== undefined) refs.push(["current", currentView.reference]);
    if (nextView?.reference !== undefined && status.nextKeyFile?.state === "COMMITTED") refs.push(["next", nextView.reference]);
    for (const [role, ref] of refs) add(...await signerFindings(role, ref, asAgent, offline, env));
    if (asAgent) {
      for (const [role, view] of [["current", currentView], ["next", nextView]] as const) {
        if (view?.state === "unreadable") {
          add(finding("signer", "WARN", "SIGNER_NOT_EVALUATED", `${role} key: not checked: ${view.path} is unreadable as this user, so the signer it names is unknown here; this run cannot confirm the agent lacks access to it`,
            "run doctor as the owner too (irontrellis doctor <history>, the owner's run names the signers), and keep the agent's environment free of signer credentials (docs/CUSTODY.md §8, the two runs)"));
        }
      }
      add(...await environmentFindings(state, asAgent, offline, env));
    }
    // Witnesses, then the hooks and their protect list.
    add(...await witnessFindings(store, asAgent, offline, env));
    const sensitive: Array<{ path: string; what: string }> = keyPaths.map((path) => ({ path, what: "owner key file" }));
    for (const v of views.filter((x) => x.state === "reference" && retiredOwnerKeyFilesFor(history).includes(x.path))) for (const p of hookSignerPaths(v.reference, env)) sensitive.push({ path: p, what: "the signer of a retired key" });
    for (const [, ref] of refs) for (const p of hookSignerPaths(ref, env)) sensitive.push({ path: p, what: `the ${ref.signer.kind} signer` });
    if (env.IRONTRELLIS_WITNESS_POLICY !== undefined && env.IRONTRELLIS_WITNESS_POLICY !== "") sensitive.push({ path: env.IRONTRELLIS_WITNESS_POLICY, what: "the out-of-band witness policy" });
    add(...hookFindings(history, options.hookConfig, env, sensitive));
    if (!asAgent && refs.some(([, r]) => r.signer.kind === "vault-transit") && env.VAULT_TOKEN !== undefined && env.VAULT_TOKEN !== "") {
      add(finding("hooks", "WARN", "VAULT_TOKEN_IN_ENVIRONMENT", "VAULT_TOKEN is set in this environment: an agent started from it inherits the token, and no hook can hide an environment variable", "start the agent from an environment without VAULT_TOKEN (or as another OS user); keep the owner's token in a tokenFile only the owner can read"));
    }
  } finally {
    store.close();
  }
  return done();
}

// ---------------------------------------------------------------- the command

export const DOCTOR_OPTIONS: readonly OptionSpec[] = [
  { name: "as-agent", kind: "boolean", help: "judge as the agent's OS user (run as that user: sudo -u <agent> irontrellis doctor …): owner key material or a Vault token it can use is a FAIL" },
  { name: "offline", kind: "boolean", help: "contact no signer socket, Vault or witness (files only)" },
  { name: "hook-config", kind: "string", help: "the irontrellis-hook.json guarding the agent (default IRONTRELLIS_HOOK_CONFIG, else found upward from the working directory)", value: "<file>" },
];

export async function runDoctor(p: Parsed, g: Global): Promise<Readonly<{ json: unknown; render: (s: Style, out: Lines) => void; exit: number }>> {
  if (p.positionals.length > 1) throw new UsageError(`unexpected argument "${p.positionals[1]}"`);
  if (p.positionals.length === 1 && g.history !== undefined) throw new UsageError("name the history once: doctor <history> or --history <history>");
  const named = p.positionals[0] ?? g.history ?? process.env.IRONTRELLIS_HISTORY;
  if (named === undefined || named === "") throw new CliError("HISTORY_REQUIRED");
  const report = await doctor(resolve(named), { asAgent: flag(p, "as-agent"), offline: flag(p, "offline"), ...(str(p, "hook-config") === undefined ? {} : { hookConfig: str(p, "hook-config")! }) });
  return {
    json: report,
    exit: report.ok ? 0 : 1,
    render: (s, out) => {
      out.add(`DOCTOR  ${report.history} · as ${report.user}${report.asAgent ? " (judged as the agent's user)" : ""}`);
      let area = "";
      for (const f of report.findings) {
        if (f.area !== area) { area = f.area; out.add(dim(s, area)); }
        // OK, WARN and FAIL are not state words: they print in bold, without a state colour (BRAND-001 p. 6).
        out.add(`  ${s.strong(f.level.padEnd(4))}  ${f.code}  ${f.message}`);
        if (f.fix !== null) out.add(dim(s, `        fix: ${f.fix}`));
      }
      out.add(`${report.summary.ok} OK · ${report.summary.warn} WARN · ${report.summary.fail} FAIL${report.ok ? "" : " — exit 1"}`);
      out.add(dim(s, "Read-only: nothing was signed or written. Run it again as the agent's OS user with --as-agent to see what the agent can reach."));
    },
  };
}

/** The words of a hook command, with single and double quotes honoured (as install quotes a path). */
const commandWords = (command: string): string[] => [...command.matchAll(/'([^']*)'|"((?:[^"\\]|\\.)*)"|(\S+)/g)].map((m) => m[1] ?? m[2]?.replace(/\\(.)/g, "$1") ?? m[3]!);
const sameKeys = (o: object, keys: readonly string[]): boolean => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
/** The hooks package's HOOK_WRAPPER (protect.ts), which install writes as `/bin/sh -c '<it>' <node> <launcher>`; doctor.test checks they match. */
export const HOOK_WRAPPER = `[ -f "$0" ] && [ -x "$0" ] && [ -f "$1" ] || { [ "$3" = PreToolUse ] && exit 2; exit 1; }; if [ "$3" = PreToolUse ]; then "$0" "$@"; s=$?; [ "$s" -eq 0 ] || [ "$s" -eq 2 ] || s=2; exit "$s"; fi; exec "$0" "$@"`;

/** The Claude Code side of the two install routes (the hooks package's route.ts has the exact check, against its own
 * launcher): whether the IronTrellis plugin is enabled, the events whose hook entry is the one install writes
 * (`/bin/sh -c '<HOOK_WRAPPER>' <absolute node> <absolute …/bin/irontrellis-hook.mjs> claude-code <Event>`, both present, exactly install's keys and
 * timeout, in a catch-all group), and any other handler that mentions irontrellis-hook. The user's settings are in
 * CLAUDE_CONFIG_DIR when that is set. */
function claudeRoutes(project: string, env: Readonly<Record<string, string | undefined>>): { plugin: boolean; hookEvents: string[]; unrecognized: string[] } {
  const timeouts: Record<string, number> = { SessionStart: 30, PreToolUse: 30, Stop: 30, SessionEnd: 10 };
  const home = env.HOME !== undefined && env.HOME !== "" ? env.HOME : process.env.HOME ?? "";
  const configDir = env.CLAUDE_CONFIG_DIR !== undefined && env.CLAUDE_CONFIG_DIR !== "" && isAbsolute(env.CLAUDE_CONFIG_DIR) ? env.CLAUDE_CONFIG_DIR : join(home, ".claude");
  let plugin = false;
  const hookEvents = new Set<string>(), unrecognized: string[] = [];
  for (const file of [join(configDir, "settings.json"), join(project, ".claude", "settings.json"), join(project, ".claude", "settings.local.json")]) {
    let doc: { enabledPlugins?: unknown; hooks?: unknown };
    try { doc = JSON.parse(readFileSync(file, "utf8")) as typeof doc; } catch { continue; }
    if (doc.enabledPlugins !== null && typeof doc.enabledPlugins === "object") {
      for (const [key, value] of Object.entries(doc.enabledPlugins as Record<string, unknown>)) if (key.split("@")[0] === "irontrellis" && typeof value === "boolean") plugin = value;
    }
    if (doc.hooks === null || typeof doc.hooks !== "object") continue;
    for (const [event, groups] of Object.entries(doc.hooks as Record<string, unknown>)) {
      if (!Array.isArray(groups)) continue;
      for (const group of groups as { matcher?: unknown; hooks?: unknown }[]) {
        for (const handler of Array.isArray(group?.hooks) ? (group.hooks as Record<string, unknown>[]) : []) {
          const command = typeof handler?.command === "string" ? handler.command.trim() : "";
          const words = commandWords(command);
          const node = words[3] ?? "", launcher = words[4] ?? "";
          const exact = words.length === 7 && words[0] === "/bin/sh" && words[1] === "-c" && words[2] === HOOK_WRAPPER && words[5] === "claude-code" && words[6] === event &&
            !/[$`"'\\;&|<>(){}*?[\]!#~]/.test(node + launcher) && isAbsolute(node) && /(^|[\\/])node(\.exe)?$/i.test(node) && existsSync(node) &&
            isAbsolute(launcher) && /[\\/]bin[\\/]irontrellis-hook\.mjs$/.test(launcher) && existsSync(launcher);
          const catchAll = (group.matcher === undefined || group.matcher === "" || group.matcher === "*") && (sameKeys(group, ["hooks"]) || sameKeys(group, ["matcher", "hooks"]));
          if (exact && catchAll && sameKeys(handler, ["type", "command", "timeout"]) && handler.type === "command" && handler.timeout === timeouts[event]) hookEvents.add(event);
          else if (JSON.stringify(handler).replace(/['"\\`^]/g, "").toLowerCase().includes("irontrellis-hook")) unrecognized.push(`${file}: ${event}: ${command || JSON.stringify(handler)}`);
        }
      }
    }
  }
  return { plugin, hookEvents: [...hookEvents], unrecognized };
}
