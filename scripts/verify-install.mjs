#!/usr/bin/env node
/**
 * Install verification: build, pack every publishable package with pnpm, and install the tarballs
 * in fresh projects OUTSIDE the workspace, the way a user would, then run what the READMEs say.
 *
 *   node scripts/verify-install.mjs [--keep] [--skip-build] [--no-python] [--json <file>] [--verbose]
 *                                   [--upstream-registry <url>] [--tarballs <dir>]
 *
 * `--tarballs <dir>` verifies tarballs packed earlier (one `<name>-<version>.tgz` per publishable package, as
 * `pnpm pack` names them) instead of building and packing: the release workflow packs once, verifies those files
 * with this mode and publishes exactly them (.github/workflows/release.yml). The sha512 of every verified tarball is
 * printed (and written to --json), so the log shows what was verified.
 *
 * Third-party tooling is pinned: the MCP SDK, TypeScript and @types/node the consumer projects install are the
 * versions in pnpm-lock.yaml (exact, never a range); the optional peers our packages declare (exact versions) are
 * installed as declared, and the workspace's `overrides` (pnpm-workspace.yaml) apply in every consumer; and the Python build frontend, backend and twine come from
 * scripts/requirements-release.txt (exact versions with hashes, `pip install --require-hashes`).
 *
 * Steps (each one row of the PASS/FAIL table printed at the end; exit 1 when any row fails):
 *   1. `pnpm -r build`, then `pnpm pack` of every publishable package into a temporary directory.
 *   2. Tarball checks, publint-style, by reading the tarballs themselves: the allowed file set
 *      (dist, README, LICENSE, NOTICE and what `files` lists, including ES modules and `.d.mts`
 *      declarations at the root of a package shipped without a build step; no tests, sources, keys
 *      or secrets),
 *      LICENSE equal to the repository's, NOTICE beginning with it, sizes, `workspace:*` rewritten to the packed
 *      version, `exports` (every target present, `types` first, `default` last), `bin` (packed,
 *      `#!/usr/bin/env node`, executable), `engines`, no install scripts, MCP `server.json` in step
 *      with the package, and every import in dist/ (or in root ES modules) resolvable (relative files
 *      present, bare specifiers declared as dependencies and, for our own packages, exported).
 *   3. npm consumer installing the tarball FILES only (the scoped registry is pointed at a dead
 *      port, so nothing of ours can come from npm): one copy of the core, from its tarball;
 *      `npm ls` clean; every bin's --help and --version; ESM import and require() of every public
 *      subpath; `tsc --noEmit` of a consumer importing every subpath that publishes declarations
 *      (module/moduleResolution nodenext and bundler, skipLibCheck off); the README quickstarts (core JS block, CLI, witness,
 *      hooks, MCP gateway, evidence server); the CLI end to end (init with and without a witness
 *      started from its tarball, writes, verify, status, owner rotate-key with pre-rotation,
 *      witness add/status/sync); `irontrellis-hook` fed realistic Claude Code payloads through
 *      the command `install --write` put in .claude/settings.json and through
 *      `npx --no-install irontrellis-hook`; the MCP gateway and evidence servers driven by a real
 *      `@modelcontextprotocol/client` over stdio, in the 2025 era and at protocol revision 2026-07-28.
 *   4. A throwaway local registry that serves only the packed tarballs (anything else is
 *      redirected to the upstream registry) for: a pnpm consumer (strict node_modules: an
 *      undeclared dependency fails here; `workspace:*` must resolve to the packed core); the
 *      README install commands run verbatim (`npm install -g …@next`, `npm install …@next`,
 *      `npx irontrellis@next demo`); `npm i -g <cli tarball>` into a temporary prefix.
 *   5. Python: sdist + wheel with `python -m build` (the wheel is built from the sdist; falls back
 *      to the project's own setuptools backend when `build` cannot be installed), `twine check`,
 *      content checks, then a fresh venv with only the wheel: `python -m irontrellis verify` on
 *      histories the packed CLI wrote, `authorize`, `survives`, `verify-receipt` on a receipt the
 *      packed witness signed; a second venv installs from the sdist.
 *
 * Deterministic: fixed ids and inputs, ports chosen by the OS, fresh npm/pnpm caches inside the
 * temporary directory. Everything is written under one temporary directory, removed at the end
 * (and on SIGINT/SIGTERM) unless --keep; every child process is killed. POSIX only (Linux, macOS).
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { builtinModules } from "node:module";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES = join(ROOT, "packages");

// ------------------------------------------------------------------ options

const USAGE = `usage: node scripts/verify-install.mjs [--keep] [--skip-build] [--no-python] [--json <file>] [--verbose] [--upstream-registry <url>] [--tarballs <dir>]

  --keep                  keep the temporary directory (its path is printed) instead of removing it
  --skip-build            do not run pnpm -r build first (dist/ must be current)
  --no-python             skip the Python sdist/wheel checks
  --json <file>           also write the results as JSON
  --verbose               print each command as it runs
  --upstream-registry <u> where the local registry sends everything that is not ours (default https://registry.npmjs.org)
  --tarballs <dir>        verify the tarballs in <dir> (one per publishable package) instead of building and packing
`;
const OPT = { keep: false, skipBuild: false, python: true, json: undefined, verbose: false, upstream: "https://registry.npmjs.org", tarballs: undefined };
{
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--keep") OPT.keep = true;
    else if (arg === "--skip-build") OPT.skipBuild = true;
    else if (arg === "--no-python") OPT.python = false;
    else if (arg === "--verbose") OPT.verbose = true;
    else if (arg === "--json" && argv[i + 1]) OPT.json = resolve(argv[++i]);
    else if (arg === "--upstream-registry" && argv[i + 1]) OPT.upstream = argv[++i].replace(/\/+$/, "");
    else if (arg === "--tarballs" && argv[i + 1]) { OPT.tarballs = resolve(argv[++i]); OPT.skipBuild = true; }
    else if (arg === "--help" || arg === "-h") { process.stdout.write(USAGE); process.exit(0); }
    else { process.stderr.write(`unknown argument ${arg}\n${USAGE}`); process.exit(2); }
  }
}
if (process.platform === "win32") { console.error("verify-install runs on Linux and macOS only"); process.exit(2); }

// ------------------------------------------------------------------ temporary directory, children, cleanup

if (!relative(ROOT, realpathSync(tmpdir())).startsWith("..")) { console.error(`the temporary directory ${tmpdir()} is inside the workspace; set TMPDIR elsewhere`); process.exit(2); }
const TMP = mkdtempSync(join(realpathSync(tmpdir()), "irontrellis-verify-install-"));
const dirs = {
  tarballs: join(TMP, "tarballs"), extract: join(TMP, "extract"), npmCache: join(TMP, "npm-cache"), pnpmStore: join(TMP, "pnpm-store"),
  pnpmCache: join(TMP, "pnpm-cache"), home: join(TMP, "irontrellis-home"), tmp: join(TMP, "tmp"), offline: join(TMP, "offline"),
};
for (const dir of Object.values(dirs)) mkdirSync(dir, { recursive: true });

const children = new Set();
const servers = new Set();
const killTree = (child, signal = "SIGKILL") => {
  try { process.kill(-child.pid, signal); } catch { try { child.kill(signal); } catch { /* gone */ } }
};
/** Short folders for Unix sockets whose path under TMP would pass the socket limit (removed with TMP). */
const socketDirs = [];
let cleaned = false;
function cleanup() {
  if (cleaned) return;
  cleaned = true;
  for (const child of children) killTree(child);
  for (const server of servers) { try { server.closeAllConnections?.(); server.close(); } catch { /* closed */ } }
  if (!OPT.keep) for (const dir of [TMP, ...socketDirs]) { try { rmSync(dir, { recursive: true, force: true, maxRetries: 3 }); } catch (error) { console.error(`could not remove ${dir}: ${error.message}`); } }
}
process.on("exit", cleanup);
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => { console.error(`\n${signal}: cleaning up`); cleanup(); process.exit(130); });

// The environment every child gets: the caller's, minus anything that could steer npm/pnpm or
// IronTrellis toward the workspace or the user's own state (proxy and CA settings are kept).
const KEEP_NPM_CONFIG = /^npm_config_(https?_proxy|proxy|no_?proxy|cafile|ca|strict_ssl|userconfig)$/i;
const BASE_ENV = (() => {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^npm_/i.test(key) && !KEEP_NPM_CONFIG.test(key)) continue;
    if (/^(pnpm_|PNPM_|IRONTRELLIS_|INIT_CWD$|COREPACK_)/.test(key)) continue;
    env[key] = value;
  }
  return Object.assign(env, {
    NO_COLOR: "1", FORCE_COLOR: "0", CI: env.CI ?? "1", TMPDIR: dirs.tmp, IRONTRELLIS_HOME: dirs.home,
    npm_config_update_notifier: "false", npm_config_fund: "false", npm_config_audit: "false", npm_config_cache: dirs.npmCache,
    npm_config_loglevel: "warn", PIP_DISABLE_PIP_VERSION_CHECK: "1", PYTHONDONTWRITEBYTECODE: "1",
  });
})();
const envWith = (binDirs = [], extra = {}) => ({ ...BASE_ENV, PATH: [...binDirs, BASE_ENV.PATH].join(delimiter), ...extra });

const tail = (text, lines = 12) => text.trim().split("\n").slice(-lines).join("\n");
const shown = (command, args) => [command, ...args].map((a) => (/[\s"'$]/.test(a) ? JSON.stringify(a) : a)).join(" ").replaceAll(TMP, "$TMP");

/** Run a command; resolves { code, stdout, stderr } when the exit code is in `codes`, rejects otherwise. */
function run(command, args = [], { cwd = TMP, env = BASE_ENV, input, timeout = 120_000, codes = [0] } = {}) {
  if (OPT.verbose) console.log(`    $ ${shown(command, args)}${cwd === TMP ? "" : `   (in ${cwd.replaceAll(TMP, "$TMP")})`}`);
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"], detached: true });
    children.add(child);
    let stdout = "", stderr = "", timedOut = false;
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.stdin.on("error", () => { /* the child may exit before reading its input */ });
    const timer = setTimeout(() => { timedOut = true; killTree(child); }, timeout);
    child.on("error", (error) => { clearTimeout(timer); children.delete(child); reject(new Error(`${shown(command, args)}: ${error.message}`)); });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      children.delete(child);
      if (timedOut) return reject(new Error(`${shown(command, args)} timed out after ${timeout / 1000}s\n${tail(stderr || stdout)}`));
      if (!codes.includes(code)) return reject(new Error(`${shown(command, args)} exited ${code ?? signal} (expected ${codes.join("/")})\n${tail(stderr || stdout)}`));
      resolveRun({ code, stdout, stderr });
    });
    child.stdin.end(input ?? "");
  });
}

/** Start a long-running process and wait for a line on stderr or stdout that `ready` accepts. */
function start(command, args, { cwd = TMP, env = BASE_ENV, ready, timeout = 30_000 }) {
  if (OPT.verbose) console.log(`    $ ${shown(command, args)} &`);
  return new Promise((resolveStart, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
    children.add(child);
    let buffer = "", settled = false, log = "";
    const exited = new Promise((resolveExit) => child.on("close", (code, signal) => { children.delete(child); resolveExit({ code, signal }); }));
    const onData = (chunk) => {
      log += chunk;
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        const value = settled ? undefined : ready(line);
        if (value !== undefined) { settled = true; clearTimeout(timer); resolveStart({ child, value, exited, log: () => log }); }
      }
    };
    child.stdout.setEncoding("utf8").on("data", onData);
    child.stderr.setEncoding("utf8").on("data", onData);
    const timer = setTimeout(() => { if (!settled) { settled = true; killTree(child); reject(new Error(`${shown(command, args)} not ready after ${timeout / 1000}s\n${tail(log)}`)); } }, timeout);
    exited.then(({ code, signal }) => { if (!settled) { settled = true; clearTimeout(timer); reject(new Error(`${shown(command, args)} exited ${code ?? signal} before it was ready\n${tail(log)}`)); } });
  });
}

// ------------------------------------------------------------------ results

const results = [];
async function check(section, name, fn, ready = true) {
  const started = Date.now();
  let status = "PASS", detail = "";
  if (!ready) { status = "SKIP"; detail = "a step it needs failed"; }
  else {
    try { detail = (await fn()) ?? ""; } catch (error) { status = "FAIL"; detail = String(OPT.verbose && !(error instanceof CheckError) ? error?.stack ?? error : error?.message ?? error); }
  }
  const ms = Date.now() - started;
  results.push({ section, name, status, ms, detail: String(detail).replaceAll(TMP, "$TMP") });
  const first = String(detail).replaceAll(TMP, "$TMP").split("\n");
  console.log(`${status.padEnd(4)}  ${section.padEnd(8)} ${name}  (${(ms / 1000).toFixed(1)}s)${first[0] ? `  ${first[0]}` : ""}`);
  if (status === "FAIL") for (const line of first.slice(1, 16)) console.log(`        ${line}`);
  return status === "PASS";
}
class CheckError extends Error {}
const fail = (message) => { throw new CheckError(message); };
const expect = (condition, message) => { if (!condition) fail(message); };
const problems = (list, ok) => { if (list.length) fail(list.join("\n")); return ok; };
const parseJson = (text, what) => { try { return JSON.parse(text); } catch { return fail(`${what} is not JSON: ${tail(text, 4)}`); } };

// ------------------------------------------------------------------ tarballs

/** Read a .tgz without a tar binary: [{ path, mode, size, data }] for regular files. */
function readTarGz(file) {
  const buffer = gunzipSync(readFileSync(file));
  const entries = [];
  let offset = 0, paxPath, longName;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const str = (start, length) => { const bytes = header.subarray(start, start + length); const end = bytes.indexOf(0); return bytes.subarray(0, end < 0 ? length : end).toString("utf8"); };
    const octal = (start, length) => parseInt(str(start, length).trim() || "0", 8);
    let name = str(0, 100);
    const mode = octal(100, 8), size = octal(124, 12), type = str(156, 1) || "0";
    const prefix = str(257, 6).startsWith("ustar") ? str(345, 155) : "";
    if (prefix) name = `${prefix}/${name}`;
    const data = buffer.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
    if (type === "x") { paxPath = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(data.toString("utf8"))?.[1]; continue; }
    if (type === "g") continue;
    if (type === "L") { longName = data.toString("utf8").replace(/\0[\s\S]*$/, ""); continue; }
    if (paxPath !== undefined) { name = paxPath; paxPath = undefined; }
    if (longName !== undefined) { name = longName; longName = undefined; }
    if (type === "0" || type === "\0") entries.push({ path: name, mode: mode & 0o7777, size, data: Buffer.from(data) });
    else if (type !== "5") entries.push({ path: name, mode, size, type, data: Buffer.alloc(0) });
  }
  return entries;
}
const sha512 = (buffer) => `sha512-${createHash("sha512").update(buffer).digest("base64")}`;
const sha1 = (buffer) => createHash("sha1").update(buffer).digest("hex");
const tarballName = (name, version) => `${name.replace(/^@/, "").replace("/", "-")}-${version}.tgz`;
const pep440 = (version) => version.replace(/-(alpha|a)\.?(\d+)$/, "a$2").replace(/-(beta|b)\.?(\d+)$/, "b$2").replace(/-rc\.?(\d+)$/, "rc$1");

const rootManifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const LICENSE = readFileSync(join(ROOT, "LICENSE"));
const NOTICE = readFileSync(join(ROOT, "NOTICE"));
const workspace = readdirSync(PACKAGES, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && existsSync(join(PACKAGES, entry.name, "package.json")))
  .map((entry) => ({ dir: join(PACKAGES, entry.name), manifest: JSON.parse(readFileSync(join(PACKAGES, entry.name, "package.json"), "utf8")) }))
  .filter(({ manifest }) => manifest.private !== true);
const byName = new Map(workspace.map((pkg) => [pkg.manifest.name, pkg]));
const VERSION = workspace[0]?.manifest.version;
const packed = new Map(); // name -> { file, integrity, shasum, manifest, files: Map(path -> entry) }

const ALWAYS = /^(package\.json|README\.md|LICENSE|NOTICE|dist\/.+\.(js|mjs|d\.ts|d\.mts|js\.map))$/;
// Root ES modules: packages shipped without a build step list `*.mjs` and `*.d.mts` in `files` (and then need no dist/).
const OPTIONAL = [
  { entry: "bin", pattern: /^bin\/[^/]+\.(mjs|js)$/ }, { entry: "server.json", pattern: /^server\.json$/ }, { entry: "docs", pattern: /^docs\/[^/]+\.md$/ },
  { entry: "*.mjs", pattern: /^[^/]+\.mjs$/ }, { entry: "*.d.mts", pattern: /^[^/]+\.d\.mts$/ },
  { entry: "LICENSING.md", pattern: /^LICENSING\.md$/ }, { entry: "THIRD-PARTY-NOTICES.md", pattern: /^THIRD-PARTY-NOTICES\.md$/ },
];
const rootModules = (manifest) => (manifest.files ?? []).includes("*.mjs") && (manifest.files ?? []).includes("*.d.mts");
const FORBIDDEN = [
  [/(^|\/)(test|tests|__tests__|fixtures?)\//, "test files"], [/\.test\.|\.spec\./, "test files"], [/(^|\/)src\/|(?<!\.d)\.ts$/, "TypeScript sources"],
  [/\.tsbuildinfo$|(^|\/)tsconfig[^/]*\.json$/, "build config"], [/(^|\/)\.(env|npmrc|git|DS_Store)/, "dotfiles"], [/\.(pem|key|p12|pfx|tgz)$|\.owner-(next-)?key[^/]*\.json$|witness-key\.json$|\.sessions\//, "keys or archives"],
  [/(^|\/)history\.jsonl/, "a history"],
];
const SECRETS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "a PEM private key"], [/"privateKey"\s*:\s*"(0x)?[0-9a-fA-F]{64}"/, "an inline private key"],
  [/\bitw_[A-Za-z0-9_-]{43}\b/, "a witness admin token"], [/\bnpm_[A-Za-z0-9]{36}\b/, "an npm token"], [/\bgh[pousr]_[A-Za-z0-9]{36}\b/, "a GitHub token"],
  [/\bAKIA[0-9A-Z]{16}\b/, "an AWS key id"], [/\bpypi-[A-Za-z0-9_-]{50,}/, "a PyPI token"],
];
const SIZE_BUDGET = { "@ramex-labs/irontrellis": 8_000_000 }; // unpacked bytes; everything else 1.5 MB. Core 8 MB: format 2 grew the engine source 24,703 → 34,182 lines (6.67 MB packed contents at 1.0.0-rc.2, no test, bench or stale files; KNOWN-ISSUES)
const BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

const bareName = (specifier) => (specifier.startsWith("@") ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0]);
const subpathOf = (specifier) => { const rest = specifier.slice(bareName(specifier).length); return rest === "" ? "." : `.${rest}`; };
const specifiers = (text) => {
  const found = new Set();
  for (const match of text.matchAll(/^\s*(?:import|export)\s(?:[^'";]*?\sfrom\s*)?["']([^"'\n]+)["']/gm)) found.add(match[1]);
  for (const match of text.matchAll(/\bimport\(\s*["']([^"'\n]+)["']\s*\)/g)) found.add(match[1]);
  return [...found];
};

function contentsProblems(name, files) {
  const pkg = byName.get(name), listed = new Set((pkg.manifest.files ?? []).map((entry) => entry.replace(/^\.\//, "").replace(/(\/\*\*)?(\/\*[^/]*)?\/?$/, "")));
  const allowed = [ALWAYS, ...OPTIONAL.filter(({ entry }) => listed.has(entry)).map(({ pattern }) => pattern)];
  const list = [];
  for (const path of files.keys()) {
    if (!allowed.some((pattern) => pattern.test(path))) list.push(`unexpected file ${path}`);
    for (const [pattern, what] of FORBIDDEN) if (pattern.test(path)) list.push(`${path}: ${what} must not ship`);
  }
  for (const required of ["package.json", "README.md", "LICENSE", "NOTICE"]) if (!files.has(required)) list.push(`missing ${required}`);
  if (files.has("LICENSE") && !files.get("LICENSE").data.equals(LICENSE)) list.push("LICENSE differs from the repository LICENSE");
  // The repository NOTICE, optionally followed by the package's own third-party attribution lines (founder, 2026-10-13).
  if (files.has("NOTICE") && !files.get("NOTICE").data.subarray(0, NOTICE.length).equals(NOTICE)) list.push("NOTICE does not begin with the repository NOTICE");
  if (rootModules(pkg.manifest)) { if (![...files.keys()].some((path) => /^[^/]+\.mjs$/.test(path))) list.push("no ES module at the package root"); }
  else if (![...files.keys()].some((path) => path.startsWith("dist/") && /\.m?js$/.test(path))) list.push("dist/ has no JavaScript (build first)");
  // Stale output: tsc never deletes, so a renamed or removed source leaves its old .js behind in dist/.
  for (const path of files.keys()) {
    const match = /^dist\/(.+)\.js$/.exec(path);
    if (match && !existsSync(join(pkg.dir, "src", `${match[1]}.ts`))) list.push(`${path} has no source (stale build output; rm -rf dist and rebuild)`);
    // A hand-written module copied (or passed through tsc with allowJs) into dist/ keeps its src/ original.
    const copied = /^dist\/(.+)\.(mjs|d\.mts)$/.exec(path);
    if (copied && !existsSync(join(pkg.dir, "src", `${copied[1]}.${copied[2]}`)) && !(copied[2] === "d.mts" && existsSync(join(pkg.dir, "src", `${copied[1]}.mjs`)))) list.push(`${path} has no source in src/ (stale build output; rm -rf dist and rebuild)`);
    if (/^dist\/.+\.js$/.test(path) && !files.has(path.replace(/\.js$/, ".d.ts"))) list.push(`${path} has no declaration file`);
  }
  // Source maps must be usable where they ship: every source packed or inlined (sourcesContent).
  for (const [path, entry] of files) {
    if (!path.endsWith(".map")) continue;
    const map = JSON.parse(entry.data.toString("utf8"));
    map.sources.forEach((source, index) => {
      const target = posix.normalize(posix.join(posix.dirname(path), map.sourceRoot ?? "", source));
      if (!files.has(target) && typeof map.sourcesContent?.[index] !== "string") list.push(`${path}: source ${source} is neither packed nor inlined (a bundler warns "points to missing source files")`);
    });
  }
  for (const [path, entry] of files) {
    const text = entry.data.toString("utf8");
    for (const [pattern, what] of SECRETS) if (pattern.test(text)) list.push(`${path} contains ${what}`);
    if (text.includes(ROOT)) list.push(`${path} contains the build machine path ${ROOT}`);
  }
  const unpacked = [...files.values()].reduce((sum, entry) => sum + entry.size, 0);
  const budget = SIZE_BUDGET[name] ?? 1_500_000;
  if (unpacked > budget) list.push(`unpacked size ${unpacked} bytes exceeds the budget of ${budget}`);
  return { list, summary: `${files.size} files, ${(unpacked / 1024).toFixed(0)} KiB unpacked (budget ${(budget / 1024).toFixed(0)} KiB)` };
}

function manifestProblems(name, manifest, files) {
  const list = [], notes = [];
  const exportTarget = (target) => target.replace(/^\.\//, "");
  if (manifest.version !== VERSION) list.push(`version ${manifest.version} is not the shared ${VERSION}`);
  if (JSON.stringify(manifest.engines) !== JSON.stringify(rootManifest.engines)) list.push(`engines ${JSON.stringify(manifest.engines)} differ from the workspace's ${JSON.stringify(rootManifest.engines)}`);
  if (manifest.type !== "module") list.push('"type" is not "module"');
  if (manifest.license !== "Apache-2.0") list.push(`license is ${manifest.license}`);
  for (const script of ["preinstall", "install", "postinstall", "prepare", "prepublish"]) if (manifest.scripts?.[script]) list.push(`install-time script "${script}" would run on every consumer`);
  for (const field of ["dependencies", "peerDependencies", "optionalDependencies", "devDependencies"]) {
    for (const [dep, spec] of Object.entries(manifest[field] ?? {})) {
      if (/^(workspace|file|link|portal):/.test(spec)) list.push(`${field}.${dep} is "${spec}" in the packed manifest`);
      if (field !== "devDependencies" && byName.has(dep)) {
        const source = byName.get(name).manifest[field]?.[dep];
        if (spec !== byName.get(dep).manifest.version) list.push(`${field}.${dep} is "${spec}", not the packed ${byName.get(dep).manifest.version}`);
        else notes.push(`${dep}: ${source} → ${spec}`);
      }
    }
  }
  // exports: every target packed, "types" first and "default" last in every condition object.
  const exportsMap = manifest.exports;
  if (typeof exportsMap !== "object" || exportsMap === null) list.push("no exports map");
  else {
    if (exportsMap["./package.json"] !== "./package.json") list.push('exports lacks "./package.json"');
    for (const [subpath, target] of Object.entries(exportsMap)) {
      if (typeof target === "string") { if (!files.has(exportTarget(target))) list.push(`exports["${subpath}"] → ${target} is not packed`); continue; }
      const keys = Object.keys(target);
      if (keys[0] !== "types") list.push(`exports["${subpath}"]: "types" must come first (has ${keys.join(", ")})`);
      if (keys.at(-1) !== "default") list.push(`exports["${subpath}"]: "default" must come last`);
      for (const [condition, file] of Object.entries(target)) {
        if (!files.has(exportTarget(file))) list.push(`exports["${subpath}"].${condition} → ${file} is not packed`);
        if (condition === "types" && !/\.d\.m?ts$/.test(file)) list.push(`exports["${subpath}"].types → ${file} is not a .d.ts or .d.mts`);
      }
    }
    const dot = exportsMap["."];
    if (manifest.main && exportTarget(manifest.main) !== exportTarget(dot?.default ?? "")) list.push(`main ${manifest.main} is not exports["."].default`);
    if (manifest.types && exportTarget(manifest.types) !== exportTarget(dot?.types ?? "")) list.push(`types ${manifest.types} is not exports["."].types`);
  }
  // bin: packed, a node shebang, executable in the tarball.
  const bins = typeof manifest.bin === "string" ? { [manifest.name]: manifest.bin } : (manifest.bin ?? {});
  for (const [bin, target] of Object.entries(bins)) {
    const entry = files.get(exportTarget(target));
    if (!entry) { list.push(`bin ${bin} → ${target} is not packed`); continue; }
    if (!entry.data.toString("utf8").startsWith("#!/usr/bin/env node\n")) list.push(`bin ${bin} → ${target} does not start with "#!/usr/bin/env node"`);
    if ((entry.mode & 0o111) !== 0o111) list.push(`bin ${bin} → ${target} is mode ${entry.mode.toString(8)} in the tarball, not executable`);
  }
  // MCP registry metadata must name this package and version.
  if (files.has("server.json")) {
    const server = JSON.parse(files.get("server.json").data.toString("utf8"));
    if (server.name !== manifest.mcpName) list.push(`server.json name ${server.name} is not mcpName ${manifest.mcpName}`);
    if (server.version !== manifest.version) list.push(`server.json version ${server.version} is not ${manifest.version}`);
    for (const entry of server.packages ?? []) {
      if (entry.identifier !== manifest.name) list.push(`server.json package ${entry.identifier} is not ${manifest.name}`);
      if (entry.version !== manifest.version) list.push(`server.json package version ${entry.version} is not ${manifest.version}`);
    }
  } else if (manifest.mcpName) list.push("mcpName is set but server.json is not packed");
  return { list, summary: `${Object.keys(exportsMap ?? {}).length} exports, ${Object.keys(bins).length} bins${notes.length ? `; workspace deps rewritten: ${notes.join(", ")}` : ""}` };
}

function importProblems(name, manifest, files) {
  const list = [];
  const declared = new Set([...Object.keys(manifest.dependencies ?? {}), ...Object.keys(manifest.peerDependencies ?? {}), ...Object.keys(manifest.optionalDependencies ?? {})]);
  const used = new Set();
  let scanned = 0;
  for (const [path, entry] of files) {
    const isJs = /\.(m?js)$/.test(path) && (path.startsWith("dist/") || path.startsWith("bin/") || /^[^/]+\.mjs$/.test(path));
    const isDts = /\.d\.m?ts$/.test(path);
    if (!isJs && !isDts) continue;
    scanned += 1;
    for (const specifier of specifiers(entry.data.toString("utf8"))) {
      if (specifier.startsWith(".")) {
        const target = posix.normalize(posix.join(posix.dirname(path), specifier));
        const candidates = isDts ? [target.replace(/\.(ts|js)$/, ".d.ts"), target.replace(/\.(mts|mjs)$/, ".d.mts"), target] : [target];
        if (!candidates.some((candidate) => files.has(candidate))) list.push(`${path} imports ${specifier}, which is not packed`);
        continue;
      }
      if (BUILTINS.has(specifier) || BUILTINS.has(specifier.split("/")[0])) continue;
      const dep = bareName(specifier);
      if (dep === name) continue;
      used.add(dep);
      if (!declared.has(dep)) { list.push(`${path} imports ${specifier}, but ${dep} is not a dependency`); continue; }
      const ours = packed.get(dep)?.manifest;
      if (ours && !(ours.exports ?? {})[subpathOf(specifier)]) list.push(`${path} imports ${specifier}, which ${dep} does not export`);
    }
  }
  const unused = [...declared].filter((dep) => !used.has(dep));
  return { list, summary: `${scanned} modules scanned; imports ${[...used].sort().join(", ") || "only node: builtins"}${unused.length ? `; declared but not imported: ${unused.join(", ")}` : ""}` };
}

// ------------------------------------------------------------------ the local registry

/** Serves the packed tarballs as a registry; every other package is redirected to the upstream registry. */
async function startRegistry() {
  const packuments = new Map();
  const server = createServer((request, response) => {
    const path = decodeURIComponent(new URL(request.url, "http://registry").pathname);
    if (path.startsWith("/-/tarballs/")) {
      const file = join(dirs.tarballs, posix.basename(path));
      if (!existsSync(file)) { response.writeHead(404).end(); return; }
      response.writeHead(200, { "content-type": "application/octet-stream" }).end(readFileSync(file));
      return;
    }
    const name = path.slice(1);
    const packument = packuments.get(name);
    if (packument) { response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(packument)); return; }
    if (byName.has(name)) { response.writeHead(404, { "content-type": "application/json" }).end('{"error":"not packed"}'); return; }
    response.writeHead(302, { location: `${OPT.upstream}${request.url}` }).end();
  });
  servers.add(server);
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const url = `http://127.0.0.1:${server.address().port}`;
  for (const [name, entry] of packed) {
    // As release.yml publishes: a pre-release under the `next` dist-tag, a stable version under `latest`.
    const tag = entry.manifest.version.includes("-") ? "next" : "latest";
    packuments.set(name, {
      _id: name, name, "dist-tags": { [tag]: entry.manifest.version },
      versions: { [entry.manifest.version]: { ...entry.manifest, _id: `${name}@${entry.manifest.version}`, dist: { tarball: `${url}/-/tarballs/${posix.basename(entry.file)}`, shasum: entry.shasum, integrity: entry.integrity } } },
    });
  }
  return url;
}

// ------------------------------------------------------------------ consumer helpers

/**
 * The exact version pnpm-lock.yaml resolved for `dependency` of the workspace package at `importer` (installing these
 * third-party packages from ranges would let an upstream release on the day fail the gate or run new code in it). Throws when the lockfile does not name it: no fallback to a range.
 */
function lockedVersion(importer, dependency) {
  const lines = readFileSync(join(ROOT, "pnpm-lock.yaml"), "utf8").split("\n");
  const start = lines.indexOf(`  ${importer}:`);
  const keys = [`      ${dependency}:`, `      '${dependency}':`];
  for (let i = start + 1; start >= 0 && i < lines.length && (lines[i] === "" || lines[i].startsWith("    ")); i += 1) {
    if (!keys.includes(lines[i])) continue;
    for (let j = i + 1; j < lines.length && lines[j].startsWith("        "); j += 1) {
      const match = /^ {8}version: ([^\s(]+)/.exec(lines[j]);
      if (match) return match[1];
    }
  }
  throw new Error(`pnpm-lock.yaml has no locked version of ${dependency} for ${importer}`);
}
// Exact versions (the consumer installs `name@<version>`, never a range).
const MCP_CLIENT_VERSION = lockedVersion("packages/mcp-evidence", "@modelcontextprotocol/client");
const TS_RANGE = lockedVersion("packages/core", "typescript");
const TYPES_NODE_RANGE = lockedVersion("packages/core", "@types/node");
const RELEASE_REQUIREMENTS = join(ROOT, "scripts", "requirements-release.txt");
/** The workspace's `overrides:` (pnpm-workspace.yaml, flat `name: version` lines), applied in every consumer project. */
const WORKSPACE_OVERRIDES = (() => {
  const lines = readFileSync(join(ROOT, "pnpm-workspace.yaml"), "utf8").split("\n"), out = {};
  for (let i = lines.indexOf("overrides:") + 1; i > 0 && i < lines.length && /^\s+\S/.test(lines[i]); i += 1) {
    const match = /^\s+(['"]?)([^'":]+)\1:\s*(['"]?)([^'"\s]+)\3\s*$/.exec(lines[i]);
    if (match === null) throw new Error(`pnpm-workspace.yaml: cannot read override line "${lines[i]}"`);
    out[match[2]] = match[4];
  }
  return out;
})();
/** The optional peers our publishable packages declare (exact versions only: a consumer installs exactly these). */
const PEER_SPECS = (() => {
  const peers = new Map();
  for (const { manifest } of workspace) for (const [name, spec] of Object.entries(manifest.peerDependencies ?? {})) {
    if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(spec)) throw new Error(`${manifest.name}: peer ${name} "${spec}" is not an exact version`);
    if (peers.has(name) && peers.get(name) !== spec) throw new Error(`peer ${name} is ${peers.get(name)} and ${spec} in different packages`);
    peers.set(name, spec);
  }
  return [...peers].map(([name, spec]) => `${name}@${spec}`);
})();

/** Every public subpath of every packed package, as import specifiers. */
const subpaths = () => [...packed.values()].flatMap(({ manifest }) => Object.keys(manifest.exports).filter((key) => key !== "./package.json").map((key) => (key === "." ? manifest.name : `${manifest.name}${key.slice(1)}`)));
const allBins = () => [...packed.values()].flatMap(({ manifest }) => Object.keys(manifest.bin ?? {}).map((bin) => ({ bin, pkg: manifest.name, version: manifest.version })));

/**
 * A consumer project: `.npmrc` carries the registry and npm's settings, `pnpm-workspace.yaml` pnpm's (pnpm 11 reads only
 * registry and auth settings from .npmrc). Both refuse a Node outside the packages' `engines`.
 */
function makeProject(dir, npmrc = {}, pnpmSettings = {}) {
  mkdirSync(dir, { recursive: true });
  const overrides = Object.keys(WORKSPACE_OVERRIDES).length ? { overrides: WORKSPACE_OVERRIDES } : {};
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `verify-${posix.basename(dir)}`, version: "0.0.0", private: true, type: "module", ...overrides }, null, 2) + "\n");
  writeFileSync(join(dir, ".npmrc"), Object.entries({ "engine-strict": "true", ...npmrc }).map(([k, v]) => `${k}=${v}\n`).join(""));
  writeFileSync(join(dir, "pnpm-workspace.yaml"), Object.entries({ engineStrict: true, ...overrides, ...pnpmSettings }).map(([k, v]) => `${k}: ${JSON.stringify(v)}\n`).join(""));
  writeFileSync(join(dir, "mcp-probe.mjs"), MCP_PROBE);
  return realpathSync(dir);
}

/** A real MCP client over stdio: connect (2025 era, or pinned to `spec.protocol`), list the tools, make the calls given, print JSON. */
const MCP_PROBE = `import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
const spec = JSON.parse(process.argv[2]);
const client = new Client({ name: "irontrellis-verify-install", version: "1.0.0" }, spec.protocol ? { versionNegotiation: { mode: { pin: spec.protocol } } } : {});
const transport = new StdioClientTransport({ command: spec.command, args: spec.args ?? [], ...(spec.env ? { env: spec.env } : {}), stderr: "pipe" });
let stderr = "";
transport.stderr?.on("data", (chunk) => { stderr += chunk; });
const timer = setTimeout(() => { console.error("timed out; server stderr:\\n" + stderr); process.exit(3); }, 60000);
try {
  await client.connect(transport);
  const out = { server: client.getServerVersion(), protocol: client.getNegotiatedProtocolVersion(), protocolTools: (await client.listTools()).tools.map((tool) => tool.name), calls: [] };
  for (const call of spec.calls ?? []) {
    const result = await client.callTool({ name: call.name, arguments: call.arguments ?? {} });
    out.calls.push({ name: call.name, isError: result.isError === true, structuredContent: result.structuredContent ?? null, text: String(result.content?.[0]?.text ?? "").slice(0, 600) });
  }
  await client.close();
  clearTimeout(timer);
  console.log(JSON.stringify(out));
} catch (error) {
  console.error(String(error?.stack ?? error) + "\\nserver stderr:\\n" + stderr);
  process.exit(2);
}
`;
const probe = async (project, spec, env = BASE_ENV) => parseJson((await run(process.execPath, [join(project, "mcp-probe.mjs"), JSON.stringify(spec)], { cwd: project, env, timeout: 90_000 })).stdout, "MCP probe output");

/** A README line, verbatim (whitespace runs collapsed), or the check fails: the docs must say what we run. */
function docLine(file, line) {
  const text = readFileSync(join(ROOT, file), "utf8").replace(/[ \t]+/g, " ");
  expect(text.includes(line.replace(/[ \t]+/g, " ")), `${file} no longer contains "${line}"; update verify-install to what the docs say`);
  return line;
}
/** Split a shell command line (single and double quotes, no expansion) into argv. */
function argvOf(line) {
  const out = [];
  let current = "", quote = null, has = false;
  for (const char of line) {
    if (quote) { if (char === quote) quote = null; else current += char; continue; }
    if (char === "'" || char === '"') { quote = char; has = true; continue; }
    if (/\s/.test(char)) { if (has || current) { out.push(current); current = ""; has = false; } continue; }
    current += char;
  }
  if (has || current) out.push(current);
  return out;
}
const substitute = (argv, map) => argv.map((arg) => Object.entries(map).reduce((value, [from, to]) => value.replaceAll(from, to), arg));
const codeBlock = (file, after, lang) => {
  const text = readFileSync(join(ROOT, file), "utf8");
  const from = text.indexOf(after);
  expect(from >= 0, `${file}: "${after}" not found`);
  const match = new RegExp("```" + lang + "\\n([\\s\\S]*?)```").exec(text.slice(from));
  expect(match, `${file}: no \`\`\`${lang} block after "${after}"`);
  return match[1];
};

// ------------------------------------------------------------------ flows run inside an installed project

async function binsRespond(binDir, env) {
  const list = [];
  for (const { bin, version } of allBins()) {
    const path = join(binDir, bin);
    if (!existsSync(path)) { list.push(`${bin} is not installed in ${binDir}`); continue; }
    const help = await run(path, ["--help"], { env, codes: [0, 1, 2] });
    if (help.code !== 0 || help.stdout.trim() === "") list.push(`${bin} --help exited ${help.code}${help.stdout.trim() ? "" : " with nothing on stdout"}`);
    const ver = await run(path, ["--version"], { env, codes: [0, 1, 2] });
    if (ver.code !== 0 || !ver.stdout.includes(version)) list.push(`${bin} --version exited ${ver.code}: ${tail(ver.stdout || ver.stderr, 2)}`);
  }
  return problems(list, `${allBins().length} bins: --help and --version exit 0 and print ${VERSION}`);
}

async function importsWork(project, env) {
  const list = [];
  const specs = subpaths();
  const esm = `const out = {};\nfor (const s of ${JSON.stringify(specs)}) { try { out[s] = Object.keys(await import(s)).length; } catch (e) { out[s] = "ERROR " + e.message; } }\nfor (const s of ${JSON.stringify([...packed.keys()].map((n) => `${n}/package.json`))}) { try { out[s] = (await import(s, { with: { type: "json" } })).default.version; } catch (e) { out[s] = "ERROR " + e.message; } }\nconsole.log(JSON.stringify(out));\n`;
  writeFileSync(join(project, "imports.mjs"), esm);
  const esmOut = parseJson((await run(process.execPath, ["imports.mjs"], { cwd: project, env })).stdout, "import results");
  for (const [spec, value] of Object.entries(esmOut)) if (typeof value === "string" && value.startsWith("ERROR")) list.push(`import("${spec}"): ${value}`); else if (value === 0) list.push(`import("${spec}") has no exports`);
  // require(esm) works unflagged on every Node the engines field allows (>= 22.12); nothing may need top-level await.
  const cjs = `const out = {};\nfor (const s of ${JSON.stringify(specs)}) { try { out[s] = Object.keys(require(s)).length; } catch (e) { out[s] = "ERROR " + (e.code ?? e.message); } }\nconsole.log(JSON.stringify(out));\n`;
  writeFileSync(join(project, "requires.cjs"), cjs);
  const cjsOut = parseJson((await run(process.execPath, ["--no-warnings", "requires.cjs"], { cwd: project, env })).stdout, "require results");
  for (const [spec, value] of Object.entries(cjsOut)) if (typeof value === "string") list.push(`require("${spec}"): ${value}`);
  return problems(list, `${specs.length} subpaths import (ESM) and require() cleanly; ${packed.size} package.json exports`);
}

/** The subpaths whose export names a `types` file (a string export, such as remote-tools' internal modules, ships no declarations). */
const typedSubpaths = () => [...packed.values()].flatMap(({ manifest }) => Object.entries(manifest.exports).filter(([key, target]) => key !== "./package.json" && typeof target === "object" && target !== null && "types" in target).map(([key]) => (key === "." ? manifest.name : `${manifest.name}${key.slice(1)}`)));

async function typesResolve(project, env) {
  const specs = typedSubpaths(), untyped = subpaths().length - specs.length;
  const lines = specs.map((spec, i) => `import * as m${i} from "${spec}";`);
  lines.push(`export const all = [${specs.map((_, i) => `m${i}`).join(", ")}] as const;`);
  lines.push(`import { createLocalOwner } from "@ramex-labs/irontrellis/local";\nexport type Owner = Awaited<ReturnType<typeof createLocalOwner>>;`);
  // The outbox's observed connector carries verifyAnchor in its type, so a TypeScript caller needs no cast.
  lines.push(`import { createObservedConnector, type Connector, type ObservedConnector } from "@ramex-labs/irontrellis-anchor-outbox";\nexport type VerifyAnchor = ReturnType<typeof createObservedConnector>["verifyAnchor"];\nexport const optionalOnConnector: Connector["verifyAnchor"] = undefined;\nexport type Observed = ObservedConnector;`);
  writeFileSync(join(project, "consumer.ts"), lines.join("\n") + "\n");
  const done = [];
  for (const resolution of ["nodenext", "bundler"]) {
    const module = resolution === "nodenext" ? "nodenext" : "preserve";
    writeFileSync(join(project, `tsconfig.${resolution}.json`), JSON.stringify({ compilerOptions: { module, moduleResolution: resolution, target: "es2023", strict: true, noEmit: true, skipLibCheck: false, types: ["node"] }, files: ["consumer.ts"] }, null, 2));
    await run(join(project, "node_modules", ".bin", "tsc"), ["-p", `tsconfig.${resolution}.json`], { cwd: project, env, timeout: 180_000 });
    done.push(resolution);
  }
  return `tsc --noEmit (skipLibCheck off) over ${specs.length} subpaths with moduleResolution ${done.join(" and ")}${untyped ? `; ${untyped} subpaths publish no declarations` : ""}`;
}

const HOOK_SESSION = "verify-install-session-1";
/** Claude Code hook payloads as the host sends them (https://code.claude.com/docs/en/hooks). */
const claudePayload = (event, cwd, extra = {}, session = HOOK_SESSION) => JSON.stringify({
  session_id: session, transcript_path: join(cwd, ".claude", "transcripts", `${session}.jsonl`), cwd, hook_event_name: event,
  ...(event === "PreToolUse" || event === "PostToolUse" ? { permission_mode: "default", tool_use_id: "toolu_01VerifyInstall000000000" } : {}),
  ...extra,
});

/** Feed SessionStart, PreToolUse (allow, deny, protected, read-only, unmapped), PostToolUse, Stop and SessionEnd through `command`. */
async function hookSession(label, command, project, env, session) {
  const hook = (event, extra = {}, codes = [0]) => run("/bin/sh", ["-c", `${command} claude-code ${event}`], { cwd: project, env, input: claudePayload(event, project, extra, session), codes });
  const config = JSON.parse(readFileSync(join(project, "irontrellis-hook.json"), "utf8"));
  const list = [];
  // A deny is exit 2 with the reason on stderr and nothing on stdout; ask and allow are JSON at exit 0; no output is no decision.
  const decision = (r) => (r.code === 2 && r.stdout.trim() === "" ? "deny" : r.stdout.trim() === "" ? "none" : JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision);
  const start = await hook("SessionStart", { source: "startup" });
  const context = start.stdout.trim() ? JSON.parse(start.stdout).hookSpecificOutput : undefined;
  if (context?.hookEventName !== "SessionStart" || !/IronTrellis: session/.test(context.additionalContext ?? "")) list.push(`${label}: SessionStart answered ${tail(start.stdout || start.stderr, 3)}`);
  const write = await hook("PreToolUse", { tool_name: "Write", tool_input: { file_path: join(project, "notes", "a.txt"), content: "hello\n" } });
  if (decision(write) !== "none") list.push(`${label}: PreToolUse Write (granted) answered ${write.stdout.trim()} instead of no decision`);
  const bash = await hook("PreToolUse", { tool_name: "Bash", tool_input: { command: "npm test", description: "Run the tests" } }, [0, 2]);
  if (decision(bash) !== "deny" || !/^\nIronTrellis · DENY: .*ACTION_NOT_ALLOWED/.test(bash.stderr)) list.push(`${label}: PreToolUse Bash (not granted) answered exit ${bash.code} ${bash.stdout.trim() || bash.stderr.trim() || "nothing"}`);
  const key = await hook("PreToolUse", { tool_name: "Read", tool_input: { file_path: `${config.history}.owner-key.json` } }, [0, 2]);
  if (decision(key) !== "deny" || !/^\nIronTrellis · DENY: .*PROTECTED_PATH/.test(key.stderr)) list.push(`${label}: PreToolUse Read of the owner key answered exit ${key.code} ${key.stdout.trim() || key.stderr.trim() || "nothing"}`);
  const read = await hook("PreToolUse", { tool_name: "Read", tool_input: { file_path: join(project, "package.json") } });
  if (decision(read) !== "none") list.push(`${label}: PreToolUse Read (read-only) answered ${read.stdout.trim()}`);
  const unknown = await hook("PreToolUse", { tool_name: "Deploy", tool_input: { target: "prod" } });
  if (decision(unknown) !== "ask") list.push(`${label}: PreToolUse of an unmapped tool answered ${unknown.stdout.trim() || "nothing"} instead of ask`);
  const post = await hook("PostToolUse", { tool_name: "Write", tool_input: { file_path: join(project, "notes", "a.txt"), content: "hello\n" }, tool_response: { filePath: join(project, "notes", "a.txt"), success: true } });
  if (post.stdout.trim() !== "") list.push(`${label}: PostToolUse answered ${post.stdout.trim()}`);
  const broken = await run("/bin/sh", ["-c", `${command} claude-code PreToolUse`], { cwd: project, env, input: "not json", codes: [0, 1, 2] });
  if (broken.code !== 2) list.push(`${label}: a malformed PreToolUse exited ${broken.code}, not 2 (fail closed)`);
  await hook("Stop", { stop_hook_active: false });
  const handover = join(`${config.history}.handovers`, `${createHash("sha256").update(session).digest("hex")}.json`);
  if (!existsSync(handover) || JSON.parse(readFileSync(handover, "utf8")).final !== false) list.push(`${label}: Stop wrote no interim handover record`);
  await hook("SessionEnd", { reason: "prompt_input_exit" });
  if (!existsSync(handover) || JSON.parse(readFileSync(handover, "utf8")).final !== true) list.push(`${label}: SessionEnd wrote no final handover record`);
  return list;
}

async function mcpFlows(project, bin, env, label) {
  const list = [];
  // Gateway, exactly-once: the README quickstart through a real MCP client.
  const gatewayCase = join(TMP, `${label}-gateway-case`);
  const setup = docLine("packages/mcp-gateway/README.md", "irontrellis-mcp-gateway setup /absolute/new-case");
  await run(bin("irontrellis-mcp-gateway"), substitute(argvOf(setup), { "/absolute/new-case": gatewayCase }).slice(1), { env });
  const config = join(gatewayCase, "gateway.json");
  const serve = docLine("packages/mcp-gateway/README.md", "irontrellis-mcp-gateway --config /absolute/new-case/gateway.json");
  const serveArgs = substitute(argvOf(serve), { "/absolute/new-case": gatewayCase }).slice(1);
  const first = await probe(project, { command: bin("irontrellis-mcp-gateway"), args: serveArgs, calls: [
    { name: "read_incident", arguments: { document: "incident" } },
    { name: "create_incident_ticket", arguments: { title: "Investigate incident 42" } },
    { name: "create_incident_ticket", arguments: { title: "Investigate incident 42" } },
    { name: "irontrellis_why", arguments: { job: "create_incident_ticket" } },
  ] }, env);
  const expectedTools = ["create_incident_ticket", "irontrellis_status", "irontrellis_why", "read_incident"];
  if (JSON.stringify([...first.protocolTools].sort()) !== JSON.stringify(expectedTools)) list.push(`gateway tools ${first.protocolTools.join(", ")}, expected ${expectedTools.join(", ")}`);
  if (first.server?.name !== "irontrellis-mcp-gateway" || first.server?.version !== VERSION) list.push(`gateway serverInfo ${JSON.stringify(first.server)}`);
  const statuses = first.calls.map((call) => call.structuredContent?.status ?? (call.isError ? "ERROR" : "?"));
  if (statuses[0] !== "RESPONSE_RETAINED" || statuses[1] !== "RESPONSE_RETAINED" || statuses[2] !== "RECONCILIATION_ONLY" || first.calls[3].isError) list.push(`gateway calls answered ${statuses.join(", ")}: ${first.calls.map((call) => call.text.slice(0, 160)).join(" | ")}`);
  const inspect = docLine("packages/mcp-gateway/README.md", "irontrellis-mcp-ops inspect --config /absolute/new-case/gateway.json");
  parseJson((await run(bin("irontrellis-mcp-ops"), substitute(argvOf(inspect), { "/absolute/new-case": gatewayCase }).slice(1), { env })).stdout, "irontrellis-mcp-ops inspect");
  const revoke = docLine("packages/mcp-gateway/README.md", "irontrellis-mcp-ops revoke --config /absolute/new-case/gateway.json --authority write");
  await run(bin("irontrellis-mcp-ops"), substitute(argvOf(revoke), { "/absolute/new-case": gatewayCase }).slice(1), { env });
  // README: after the revoke, a job that already ran answers RECONCILIATION_ONLY with the retained reply.
  const after = await probe(project, { command: bin("irontrellis-mcp-gateway"), args: ["--config", config], calls: [{ name: "create_incident_ticket", arguments: { title: "Investigate incident 42" } }] }, env);
  if (after.calls[0].structuredContent?.status !== "RECONCILIATION_ONLY") list.push(`gateway after revoke answered ${after.calls[0].text.slice(0, 200)}`);
  // Per-call mode.
  const perCallCase = join(TMP, `${label}-gateway-per-call`);
  await run(bin("irontrellis-mcp-gateway"), ["setup", perCallCase, "--mode", "per-call"], { env });
  const perCall = await probe(project, { command: bin("irontrellis-mcp-gateway"), args: ["--config", join(perCallCase, "gateway.json")], calls: [{ name: "create_incident_ticket", arguments: { title: "one" } }] }, env);
  if (perCall.calls[0].structuredContent?.status !== "FORWARDED") list.push(`per-call gateway answered ${perCall.calls[0].text.slice(0, 200)}`);
  const modern = await probe(project, { command: bin("irontrellis-mcp-gateway"), args: ["--config", join(perCallCase, "gateway.json")], protocol: "2026-07-28", calls: [{ name: "create_incident_ticket", arguments: { title: "two" } }] }, env);
  if (modern.protocol !== "2026-07-28" || modern.calls[0].structuredContent?.status !== "FORWARDED") list.push(`per-call gateway at 2026-07-28 (${modern.protocol}) answered ${modern.calls[0].text.slice(0, 200)}`);

  // Evidence server: README quickstart (setup + demo), then our own client against both bin names.
  const evidenceCase = join(TMP, `${label}-evidence-case`);
  const evSetup = docLine("packages/mcp-evidence/README.md", "irontrellis-evidence-setup /absolute/new-case");
  await run(bin("irontrellis-evidence-setup"), substitute(argvOf(evSetup), { "/absolute/new-case": evidenceCase }).slice(1), { env });
  const evDemo = docLine("packages/mcp-evidence/README.md", "irontrellis-evidence-demo /absolute/new-case/gateway.json");
  const demo = await run(bin("irontrellis-evidence-demo"), substitute(argvOf(evDemo), { "/absolute/new-case": evidenceCase }).slice(1), { env, timeout: 90_000 });
  for (const expected of ["Tools: irontrellis_collect_evidence", '"RECORDED"', '"RECONCILIATION_ONLY"', '"packetVerified": true']) if (!demo.stdout.includes(expected)) list.push(`evidence demo output lacks ${expected}`);
  for (const name of ["irontrellis-evidence", "irontrellis-mcp"]) for (const protocol of [undefined, "2026-07-28"]) {
    const operationId = `verify-install:${name}:${protocol ?? "2025"}`;
    const out = await probe(project, { command: bin(name), args: ["--config", join(evidenceCase, "gateway.json")], ...(protocol ? { protocol } : {}), calls: [
      { name: "irontrellis_collect_evidence", arguments: { operationId, resource: "incident:42" } },
      { name: "irontrellis_collect_evidence", arguments: { operationId, resource: "incident:42" } },
    ] }, env);
    if (out.protocolTools.join(",") !== "irontrellis_collect_evidence") list.push(`${name} tools: ${out.protocolTools.join(", ")}`);
    if (protocol && out.protocol !== protocol) list.push(`${name} negotiated ${out.protocol}, expected ${protocol}`);
    const got = out.calls.map((call) => `${call.structuredContent?.status}/${call.structuredContent?.packetVerified}`);
    if (got.join(",") !== "RECORDED/true,RECONCILIATION_ONLY/true") list.push(`${name} (${out.protocol}) calls answered ${got.join(", ")}: ${out.calls.map((call) => call.text.slice(0, 160)).join(" | ")}`);
  }
  return problems(list, `gateway (exactly-once: RESPONSE_RETAINED, RECONCILIATION_ONLY, revoke; per-call: FORWARDED, also at 2026-07-28) and evidence server (irontrellis-evidence and irontrellis-mcp, 2025 era and 2026-07-28: RECORDED, RECONCILIATION_ONLY) over stdio with @modelcontextprotocol/client ${MCP_CLIENT_VERSION}`);
}

// ------------------------------------------------------------------ Python

const PYTHON = process.env.PYTHON ?? "python3";
// The Python package is frozen at format 1 and keeps the version it was frozen at (BUILD §8; scripts/check-versions.mjs).
const PYTHON_VERSION = "1.0.0rc1";
const venvBin = (venv, name) => join(venv, "bin", name);

// ------------------------------------------------------------------ main

console.log(`verify-install: ${workspace.length} publishable packages at ${VERSION}, node ${process.version} on ${process.platform}/${process.arch}; temporary directory ${TMP}\n`);
const state = {};

const built = await check("build", "pnpm -r build", async () => {
  if (OPT.skipBuild) return "skipped (--skip-build)";
  await run("pnpm", ["-r", "build"], { cwd: ROOT, env: { ...BASE_ENV, TMPDIR: tmpdir() }, timeout: 600_000 });
  return "all packages built";
});

const pnpmVersion = built ? (await run("pnpm", ["--version"], { cwd: ROOT }).catch(() => ({ stdout: "?" }))).stdout.trim() : "?";
// The workspace pins its package manager (`packageManager`, also PNPM_VERSION in the workflows and corepack in the
// witness image): the tarballs are packed by exactly that pnpm.
const pinnedPnpm = /^pnpm@(\d+\.\d+\.\d+)$/.exec(rootManifest.packageManager ?? "")?.[1];
await check("build", `pnpm ${pinnedPnpm ?? "?"} (the packageManager pin) packs`, () => {
  expect(pinnedPnpm !== undefined, `package.json packageManager ${JSON.stringify(rootManifest.packageManager)} is not pnpm@<x.y.z>`);
  expect(pnpmVersion === pinnedPnpm, `pnpm --version is ${pnpmVersion}, the workspace pins ${pinnedPnpm}`);
  return `pnpm ${pnpmVersion}`;
}, built);
const packTitle = OPT.tarballs === undefined ? `pnpm pack (pnpm ${pnpmVersion}) of ${workspace.length} packages` : `the ${workspace.length} tarballs in ${OPT.tarballs} (packed earlier; not rebuilt, not repacked)`;
const didPack = await check("pack", packTitle, async () => {
  const list = [];
  if (OPT.tarballs !== undefined) {
    // Exactly one tarball per publishable package at this version, and nothing else: what is verified is what is published.
    const expected = new Set(workspace.map(({ manifest }) => tarballName(manifest.name, manifest.version)));
    const present = readdirSync(OPT.tarballs).filter((file) => file.endsWith(".tgz"));
    for (const file of present) if (!expected.has(file)) list.push(`${file}: not a publishable package at ${VERSION}`);
    for (const file of expected) if (!present.includes(file)) list.push(`${file}: missing`);
    if (list.length) return problems(list, "");
    for (const file of expected) cpSync(join(OPT.tarballs, file), join(dirs.tarballs, file));
  }
  for (const { dir, manifest } of workspace) {
    if (OPT.tarballs === undefined) await run("pnpm", ["pack", "--pack-destination", dirs.tarballs], { cwd: dir, env: { ...BASE_ENV, TMPDIR: tmpdir() }, timeout: 180_000 });
    const file = join(dirs.tarballs, tarballName(manifest.name, manifest.version));
    if (!existsSync(file)) { list.push(`${manifest.name}: ${posix.basename(file)} was not written`); continue; }
    const data = readFileSync(file);
    const entries = readTarGz(file);
    const files = new Map();
    for (const entry of entries) {
      if (!entry.path.startsWith("package/")) { list.push(`${manifest.name}: ${entry.path} is outside package/`); continue; }
      if (entry.type !== undefined) { list.push(`${manifest.name}: ${entry.path} is not a regular file`); continue; }
      files.set(entry.path.slice("package/".length), entry);
    }
    const packedManifest = JSON.parse(files.get("package.json").data.toString("utf8"));
    packed.set(manifest.name, { file, integrity: sha512(data), shasum: sha1(data), manifest: packedManifest, files, bytes: data.length });
  }
  state.tarballs = [...packed.values()].map(({ file, bytes, integrity }) => ({ file: posix.basename(file), bytes, integrity }));
  return problems(list, [...packed.values()].map(({ file, bytes, integrity }) => `${posix.basename(file)} ${(bytes / 1024).toFixed(0)} KiB ${integrity}`).join(", "));
}, built);

for (const name of byName.keys()) {
  const ok = didPack && packed.has(name);
  await check("tarball", `${name}: files`, () => { const { list, summary } = contentsProblems(name, packed.get(name).files); return problems(list, summary); }, ok);
  await check("tarball", `${name}: manifest, exports, bin`, () => { const { manifest, files } = packed.get(name); const { list, summary } = manifestProblems(name, manifest, files); return problems(list, summary); }, ok);
  await check("tarball", `${name}: imports resolve and are declared`, () => { const { manifest, files } = packed.get(name); const { list, summary } = importProblems(name, manifest, files); return problems(list, summary); }, ok);
}

// ---------------------------------------------------------------- npm, tarball files only

const npmProject = join(TMP, "npm-consumer");
const npmBin = (name) => join(npmProject, "node_modules", ".bin", name);
const npmEnv = envWith([join(npmProject, "node_modules", ".bin")]);
const npmInstalled = await check("npm", "npm install <tarball files> (no registry for @ramex-labs)", async () => {
  // A dead registry for our scope: anything of ours that does not come from a tarball fails at once.
  makeProject(npmProject, { "@ramex-labs:registry": "http://127.0.0.1:9/", "fetch-retries": "0" });
  const tarballs = [...packed.values()].map(({ file }) => file);
  await run("npm", ["install", "--no-audit", "--no-fund", ...tarballs, ...PEER_SPECS, `@modelcontextprotocol/client@${MCP_CLIENT_VERSION}`, `typescript@${TS_RANGE}`, `@types/node@${TYPES_NODE_RANGE}`], { cwd: npmProject, env: npmEnv, timeout: 600_000 });
  const lock = JSON.parse(readFileSync(join(npmProject, "package-lock.json"), "utf8"));
  const list = [];
  const ours = Object.entries(lock.packages).filter(([path]) => [...packed.keys()].some((name) => path.endsWith(`node_modules/${name}`)));
  for (const [path, entry] of ours) {
    if (path.split("node_modules/").length > 2) list.push(`${path}: a second, nested copy`);
    if (!String(entry.resolved ?? "").startsWith("file:")) list.push(`${path} resolved from ${entry.resolved}`);
    const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
    if (entry.integrity && entry.integrity !== packed.get(name)?.integrity) list.push(`${path}: integrity differs from the packed tarball`);
  }
  if (ours.length !== packed.size) list.push(`${ours.length} of our packages in the lockfile, expected ${packed.size}`);
  const ls = await run("npm", ["ls", "--all", "--json"], { cwd: npmProject, env: npmEnv, codes: [0, 1] });
  if (ls.code !== 0) list.push(`npm ls --all reports problems: ${JSON.stringify(parseJson(ls.stdout, "npm ls").problems ?? tail(ls.stderr))}`);
  const core = byName.has("@ramex-labs/irontrellis") ? "; the core resolved once, from its tarball, for every dependent" : "";
  return problems(list, `${ours.length} packages from their tarballs${core}; npm ls --all clean`);
}, didPack);

await check("npm", "every bin: --help and --version", () => binsRespond(join(npmProject, "node_modules", ".bin"), npmEnv), npmInstalled);
await check("npm", "ESM import and require() of every public subpath", () => importsWork(npmProject, npmEnv), npmInstalled);
await check("npm", "consumer type-check (tsc --noEmit)", () => typesResolve(npmProject, npmEnv), npmInstalled);

await check("anchor-outbox", "installed public exports, raw-call preparation and closed inputs", async () => {
  writeFileSync(join(npmProject, "anchor-outbox-smoke.mjs"), readFileSync(join(ROOT, "scripts/anchor-outbox-install-smoke.mjs")));
  return (await run(process.execPath, ["anchor-outbox-smoke.mjs"], { cwd: npmProject, env: npmEnv })).stdout.trim();
}, npmInstalled);

await check("docs", "core README quickstart (the JS block, verbatim)", async () => {
  const dir = join(npmProject, "core-quickstart");
  mkdirSync(dir);
  writeFileSync(join(dir, "quickstart.mjs"), codeBlock("packages/core/README.md", "## 60-second quickstart", "js"));
  const out = (await run(process.execPath, ["quickstart.mjs"], { cwd: dir, env: npmEnv })).stdout;
  const expected = ["ALLOW", "[ 'collect' ]", "DENY REVOKED", "true MATCHES VERIFIED"];
  const lines = out.trim().split("\n");
  expect(JSON.stringify(lines) === JSON.stringify(expected), `printed ${JSON.stringify(lines)}, the README says ${JSON.stringify(expected)}`);
  writeFileSync(join(dir, "read-only.mjs"), codeBlock("packages/core/README.md", "## Read-only use", "js") + "\nif (report.ok !== true) { console.error(JSON.stringify(report.failures)); process.exit(1); }\n");
  await run(process.execPath, ["read-only.mjs"], { cwd: dir, env: npmEnv });
  return `printed ${expected.join(" / ")} as documented; the read-only block verifies the history`;
}, npmInstalled);

await check("docs", "README dependency claims match the packed manifests", () => {
  const list = [];
  const deps = (name) => Object.keys(packed.get(name)?.manifest.dependencies ?? {}).sort().join(", ");
  const claims = [
    ["packages/core/README.md", "zero runtime dependencies", "@ramex-labs/irontrellis", ""],
    ["packages/cli/README.md", "one runtime dependency, `@ramex-labs/irontrellis`", "irontrellis", "@ramex-labs/irontrellis"],
    ["packages/mcp-evidence/README.md", "Dependencies: `@ramex-labs/irontrellis`, `@modelcontextprotocol/server` and `@modelcontextprotocol/client`", "@ramex-labs/irontrellis-mcp", "@modelcontextprotocol/client, @modelcontextprotocol/server, @ramex-labs/irontrellis"],
    ["packages/mcp-gateway/README.md", "Dependencies: `@ramex-labs/irontrellis`, `@ramex-labs/irontrellis-remote`, `jose`, `@modelcontextprotocol/server` and `@modelcontextprotocol/client`", "@ramex-labs/irontrellis-mcp-gateway", "@modelcontextprotocol/client, @modelcontextprotocol/server, @ramex-labs/irontrellis, @ramex-labs/irontrellis-remote, jose"],
  ];
  for (const [file, claim, name, expected] of claims) {
    docLine(file, claim);
    if (deps(name) !== expected) list.push(`${file} says "${claim}", but ${name} depends on ${deps(name) || "nothing"}`);
  }
  // The MCP packages pin the SDK exactly; the consumer must have installed those versions.
  const pins = new Set();
  for (const name of ["@ramex-labs/irontrellis-mcp", "@ramex-labs/irontrellis-mcp-gateway"]) {
    for (const [dep, pin] of Object.entries(packed.get(name)?.manifest.dependencies ?? {})) {
      if (!dep.startsWith("@modelcontextprotocol/")) continue;
      if (!/^\d+\.\d+\.\d+$/.test(pin)) list.push(`${name} declares ${dep}@${pin}, not an exact version`);
      const installed = JSON.parse(readFileSync(join(npmProject, "node_modules", ...dep.split("/"), "package.json"), "utf8")).version;
      if (installed !== pin) list.push(`${dep} installed ${installed}, but ${name} pins ${pin}`);
      pins.add(`${dep}@${pin}`);
    }
  }
  return problems(list, `core: none; CLI: the core only; MCP packages: the core and the MCP SDK, pinned exactly (${[...pins].sort().join(", ")})`);
}, npmInstalled);

// The CLI end to end, and the witness from its own tarball.
const cli = npmBin("irontrellis");
const historyA = join(TMP, "cli", "history.jsonl");
const cliRan = await check("cli", "README 'your own history' + owner rotate-key (pre-rotation)", async () => {
  mkdirSync(dirname(historyA), { recursive: true });
  const env = { ...npmEnv, IRONTRELLIS_HISTORY: historyA };
  const cwd = dirname(historyA);
  const doc = "packages/cli/README.md";
  // The README's "Your own history" block, verbatim; `why --json` is run after it (the README lists `why`).
  const lines = [
    "irontrellis init --owner operations",
    "irontrellis agent create bea",
    "irontrellis grant collect --to bea --actions read --resources incident:42 --expires +12h",
    "irontrellis authorize --actor bea --action read --resource incident:42",
    "irontrellis verify",
  ].map((line) => docLine(doc, line));
  lines.splice(4, 0, "irontrellis why --actor bea --action read --resource incident:42 --json");
  docLine(doc, "export IRONTRELLIS_HISTORY=./history.jsonl");
  docLine(doc, "mv history.jsonl.owner-next-key.json /media/offline/");
  await run(cli, argvOf(lines[0]).slice(1), { cwd, env });
  // "mv history.jsonl.owner-next-key.json /media/offline/": the next key leaves the host.
  cpSync(`${historyA}.owner-next-key.json`, join(dirs.offline, "history.jsonl.owner-next-key.json"));
  rmSync(`${historyA}.owner-next-key.json`);
  for (const line of lines.slice(1, 3)) await run(cli, argvOf(line).slice(1), { cwd, env });
  const allow = await run(cli, argvOf(lines[3]).slice(1), { cwd, env });
  expect(/^ALLOW\s+bea: read on incident:42/m.test(allow.stdout), `authorize printed ${tail(allow.stdout, 3)}`);
  const why = parseJson((await run(cli, argvOf(lines[4]).slice(1), { cwd, env })).stdout, "why --json");
  expect(JSON.stringify(why).includes('"collect"'), "why --json does not name the grant collect");
  await run(cli, argvOf(lines[5]).slice(1), { cwd, env });
  const status = parseJson((await run(cli, ["status", "--json"], { cwd, env })).stdout, "status --json");
  const owner = parseJson((await run(cli, ["owner", "status", "--json"], { cwd, env })).stdout, "owner status --json");
  expect(!JSON.stringify(owner.warnings ?? []).includes("next key"), `owner status still warns about the next key: ${JSON.stringify(owner.warnings)}`);
  // Pre-rotation: the committed next key comes back from offline storage for the rotation.
  docLine("docs/OPERATOR.md", "irontrellis owner rotate-key [--next-key <file>] --reason \"<why>\"");
  await run(cli, ["owner", "rotate-key", "--next-key", join(dirs.offline, "history.jsonl.owner-next-key.json"), "--reason", "verify-install scheduled rotation"], { cwd, env });
  const verified = parseJson((await run(cli, ["verify", "--json"], { cwd, env })).stdout, "verify --json");
  expect(verified.ok === true, `verify after rotate-key: ${JSON.stringify(verified.failures)}`);
  const rotated = parseJson((await run(cli, ["owner", "status", "--json"], { cwd, env })).stdout, "owner status --json");
  expect(JSON.stringify(rotated).includes("owner:2"), "owner status does not show owner:2 in force after the rotation");
  state.historyAEvents = (await run(cli, ["export"], { cwd, env }).then((r) => JSON.parse(r.stdout).length));
  return `init, grant, authorize ALLOW, why, verify, status (${status.events ?? status.eventCount ?? "?"} events), owner status (next key offline), rotate-key --next-key: VERIFIED with owner:2`;
}, npmInstalled);

// Owner-key custody from the installed CLI. The owner key behind a command signer (examples/signers/file-signer.mjs)
// and, when OpenSSH is installed, a real ssh-agent; the next key committed by public key only; signer test/ref/list/to-ssh.
await check("cli", "custody: init --owner-key-ref (command signer), signer test/ref/list/to-ssh, doctor, commit by public key, rotate-key --next-key-ref (ssh-agent)", async () => {
  const doc = "packages/cli/README.md";
  const home = join(TMP, "cli-custody");
  mkdirSync(home, { recursive: true });
  const history = join(home, "history.jsonl");
  const env = { ...npmEnv, IRONTRELLIS_HISTORY: history };
  const json = async (args, options = {}) => parseJson((await run(cli, [...args, "--json"], { cwd: home, env, ...options })).stdout, `irontrellis ${args.slice(0, 2).join(" ")} --json`);
  // The CLI README lists the custody commands; docs/CUSTODY.md gives the command lines.
  docLine(doc, "| key custody | `signer test`, `signer ref`, `signer list`, `signer to-ssh`, `doctor` |");
  docLine("docs/CUSTODY.md", "irontrellis --history h.jsonl signer test --key current");
  docLine("docs/CUSTODY.md", "irontrellis owner rotate-key --next-key-ref <file>");
  // A key file only the signing program reads; the history gets a reference to it.
  const keyGen = await json(["init", "--history", join(home, "keysource.jsonl"), "--no-next-key"]);
  expect(keyGen.ownerKeyHolder === "file", `a plain init reports its key file: ${JSON.stringify(keyGen.ownerKeyHolder)}`);
  const secureKey = join(home, "secure-owner-1.json");
  cpSync(join(home, "keysource.jsonl.owner-key.json"), secureKey);
  const signerProgram = join(ROOT, "examples/signers/file-signer.mjs");
  const publicKey = (await run(process.execPath, [signerProgram, "--key", secureKey, "--public-key"])).stdout.trim();
  const ref = join(home, "owner-1.owner-key-ref.json");
  await json(["signer", "ref", "--out", ref, "--signer", "command", "--public-key", publicKey, "--signer-command", JSON.stringify([process.execPath, signerProgram, "--key", secureKey])]);
  await json(["init", "--history", join(home, "nextsource.jsonl"), "--no-next-key"]);
  const nextKey = JSON.parse(readFileSync(join(home, "nextsource.jsonl.owner-key.json"), "utf8")).credential;
  const created = await json(["init", "--owner-key-ref", ref, "--next-public-key", nextKey]);
  expect(created.ownerKeyHolder === "reference" && created.nextKeyCommitted === true && created.nextKeyFile === null, `init --owner-key-ref: ${JSON.stringify({ holder: created.ownerKeyHolder, next: created.nextKeyFile })}`);
  await run(cli, ["agent", "create", "bea"], { cwd: home, env });
  const tested = await json(["signer", "test", "--key", "current"]);
  expect(tested.ok === true && tested.standing === "an owner key in force", `signer test: ${JSON.stringify(tested)}`);
  const status = await json(["owner", "status"]);
  expect(status.custody?.[0]?.code === "OWNER_KEY_REFERENCE" && status.custody?.[1]?.code === "NEXT_KEY_OFF_HOST", `owner status custody: ${JSON.stringify(status.custody?.map((c) => c.code))}`);
  const verified = await json(["verify"]);
  expect(verified.ok === true && verified.report.pinnedAttestation === "VERIFIED", `verify: ${JSON.stringify(verified.failures)}`);
  // doctor (read-only): the command signer is not started, the history verifies, no FAIL.
  const doctor = await json(["doctor", history, "--offline"]);
  const codes = (doctor.findings ?? []).map((f) => f.code);
  expect(doctor.ok === true && codes.includes("OWNER_KEY_REFERENCE") && codes.includes("SIGNER_NOT_CHECKED") && codes.includes("HISTORY_VERIFIES"), `doctor: ${JSON.stringify(codes)}`);
  // signer to-ssh: the next key's file as an OpenSSH key; with OpenSSH installed, it goes into a real agent for the rotation.
  const sshKey = join(home, "next.ssh");
  await json(["signer", "to-ssh", "--from", join(home, "nextsource.jsonl.owner-key.json"), "--out", sshKey]);
  if (!existsSync("/usr/bin/ssh-agent") || !existsSync("/usr/bin/ssh-add")) return "command signer: init, write, signer test, owner status, verify; ssh-agent not installed: rotation skipped";
  // A Unix socket path holds 103 bytes on macOS (107 on Linux): under a deep TMPDIR the agent socket goes to a short folder
  // in /tmp instead (docs/PLATFORMS.md), so the row does not fail on the host's path length.
  let socketHome = home;
  if (Buffer.byteLength(join(home, "agent.sock")) > 103) { socketHome = mkdtempSync("/tmp/itvi-"); socketDirs.push(socketHome); }
  const socket = join(socketHome, "agent.sock");
  const agent = spawn("/usr/bin/ssh-agent", ["-a", socket, "-D"], { stdio: "ignore", detached: true });
  children.add(agent);
  for (let i = 0; i < 200 && !existsSync(socket); i += 1) await new Promise((resolveWait) => setTimeout(resolveWait, 10));
  await run("/usr/bin/ssh-add", [sshKey], { env: { ...BASE_ENV, SSH_AUTH_SOCK: socket } });
  const listed = await json(["signer", "list", "--agent-socket", socket]);
  expect(listed.keys?.[0]?.publicKey === nextKey, `signer list: ${JSON.stringify(listed.keys)}`);
  const nextRef = join(home, "owner-2.owner-next-key-ref.json");
  await json(["signer", "ref", "--out", nextRef, "--next", "--key-id", "owner:2", "--signer", "ssh-agent", "--agent-socket", socket, "--public-key", nextKey]);
  await json(["init", "--history", join(home, "thirdsource.jsonl"), "--no-next-key"]);
  const thirdKey = JSON.parse(readFileSync(join(home, "thirdsource.jsonl.owner-key.json"), "utf8")).credential;
  const rotated = await json(["owner", "rotate-key", "--next-key-ref", nextRef, "--new-next-public-key", thirdKey]);
  expect(rotated.preRotated === true && rotated.keyId === "owner:2", `rotate-key --next-key-ref: ${JSON.stringify({ preRotated: rotated.preRotated, keyId: rotated.keyId })}`);
  await run(cli, ["agent", "create", "cid"], { cwd: home, env });
  const after = await json(["verify"]);
  expect(after.ok === true, `verify after the rotation: ${JSON.stringify(after.failures)}`);
  killTree(agent, "SIGTERM");
  return "command signer: init --owner-key-ref, write, signer test, custody OK, verify, doctor OK; ssh-agent: to-ssh, ssh-add, signer list, rotate-key --next-key-ref onto the agent key: VERIFIED";
}, npmInstalled);

let witness;
const witnessData = join(TMP, "witness-data");
const witnessUp = await check("witness", "README quickstart: init, token create, serve, GET /v1/witness", async () => {
  const doc = "packages/witness/README.md";
  const bin = npmBin("irontrellis-witness");
  const init = argvOf(docLine(doc, "irontrellis-witness init --data ./witness-data --name witness.example.com"));
  const initOut = await run(bin, substitute(init, { "./witness-data": witnessData }).slice(1), { env: npmEnv });
  const verifierKey = /witness\.example\.com\+[0-9a-f]{8}\+[A-Za-z0-9+/=]+/.exec(initOut.stdout)?.[0];
  expect(verifierKey, `init printed no verifier key: ${tail(initOut.stdout, 3)}`);
  const token = argvOf(docLine(doc, "irontrellis-witness token create --data ./witness-data"));
  const tokenOut = await run(bin, substitute(token, { "./witness-data": witnessData }).slice(1), { env: npmEnv });
  const admin = /itw_[A-Za-z0-9_-]+/.exec(tokenOut.stdout)?.[0];
  expect(admin, "token create printed no itw_ token");
  // The README serves on the default 127.0.0.1:8411; a free port is asked for here instead.
  const serve = argvOf(docLine(doc, "irontrellis-witness serve --data ./witness-data"));
  const started = await start(bin, [...substitute(serve, { "./witness-data": witnessData }).slice(1), "--listen", "127.0.0.1:0"], {
    env: npmEnv, ready: (line) => { try { const entry = JSON.parse(line); return entry.msg === "listening" ? entry.url : undefined; } catch { return undefined; } },
  });
  witness = { url: started.value, verifierKey, token: admin, child: started.child, exited: started.exited };
  docLine(doc, "curl -s http://127.0.0.1:8411/v1/witness");
  const info = await (await fetch(`${witness.url}/v1/witness`)).json();
  expect(info.version === "irontrellis-witness/1" && info.origin === "irontrellis-witness/witness.example.com" && info.verifierKey === verifierKey, `/v1/witness answered ${JSON.stringify(info)}`);
  expect(String(info.software).includes(VERSION), `software ${info.software} is not ${VERSION}`);
  return `serving ${info.software} on a free port; verifier key ${verifierKey.split("+").slice(0, 2).join("+")}+…`;
}, npmInstalled);

const historyB = join(TMP, "cli-witnessed", "history.jsonl");
await check("cli", "init --witness (bound from the first write), writes, witness status/sync, verify", async () => {
  mkdirSync(dirname(historyB), { recursive: true });
  const env = { ...npmEnv, IRONTRELLIS_HISTORY: historyB };
  const cwd = dirname(historyB);
  docLine("packages/cli/README.md", "`--witness <url> --verifier-key <key>` binds a remote witness from the first write");
  docLine("docs/WITNESS.md", "irontrellis init --witness <url> --verifier-key <key> [--token <token>] [--mode sync|async]");
  await run(cli, ["init", "--owner", "operations", "--controller", "operator", "--witness", witness.url, "--verifier-key", witness.verifierKey, "--token", witness.token, "--no-next-key"], { cwd, env });
  await run(cli, ["agent", "create", "bea"], { cwd, env });
  await run(cli, ["grant", "collect", "--to", "bea", "--actions", "read", "--resources", "incident:42", "--expires", "+12h"], { cwd, env });
  await run(cli, ["witness", "sync"], { cwd, env });
  const status = parseJson((await run(cli, ["witness", "status", "--json"], { cwd, env })).stdout, "witness status --json");
  const remote = status.witnesses?.[0];
  expect(remote?.bound === true && remote?.registered === true && status.unwitnessedEvents === 0, `witness status: ${JSON.stringify({ bound: remote?.bound, registered: remote?.registered, unwitnessed: status.unwitnessedEvents })}`);
  const verified = parseJson((await run(cli, ["verify", "--json"], { cwd, env })).stdout, "verify --json");
  expect(verified.ok === true, `verify: ${JSON.stringify(verified.failures)}`);
  // A receipt the witness signed, for the Python verifier.
  const answer = await (await fetch(`${witness.url}/v1/histories/${status.historyId}`)).json();
  expect(answer.latest?.receipt, `the witness holds no receipt for ${status.historyId}`);
  writeFileSync(join(TMP, "witness-response.json"), JSON.stringify(answer, null, 2));
  state.receiptReady = true;
  return `bound, registered, witnessed up to position ${status.witnessedPosition}; verify OK against the running witness`;
}, cliRan && witnessUp);

await check("cli", "witness add on an existing history, status, sync; rotate-key again (two-phase with a bound witness)", async () => {
  const env = { ...npmEnv, IRONTRELLIS_HISTORY: historyA };
  const cwd = dirname(historyA);
  docLine("docs/WITNESS.md", "irontrellis witness add https://witness.example.com --verifier-key 'witness.example.com+1a2b3c4d+AX…' --token itw_…");
  docLine("docs/WITNESS.md", "The policy options given to `witness add` (`--quorum`, `--require-on-open`, `--max-unwitnessed`)");
  await run(cli, ["witness", "add", witness.url, "--verifier-key", witness.verifierKey, "--token", witness.token, "--quorum", "1", "--mode", "async"], { cwd, env });
  await run(cli, ["witness", "sync"], { cwd, env });
  // The first rotation left a fresh next key beside the history; the second rotation uses it and must reach the witness first.
  await run(cli, ["owner", "rotate-key", "--reason", "verify-install second rotation"], { cwd, env });
  const status = parseJson((await run(cli, ["witness", "status", "--json"], { cwd, env })).stdout, "witness status --json");
  const remote = status.witnesses?.[0];
  expect(remote?.pendingRotations === 0 && status.rotationIncomplete === false && status.keyRotations === 2, `rotation state: ${JSON.stringify({ keyRotations: status.keyRotations, incomplete: status.rotationIncomplete, pending: remote?.pendingRotations })}`);
  const verified = parseJson((await run(cli, ["verify", "--json"], { cwd, env })).stdout, "verify --json");
  expect(verified.ok === true, `verify: ${JSON.stringify(verified.failures)}`);
  state.historyAEvents = JSON.parse((await run(cli, ["export"], { cwd, env })).stdout).length;
  return `witness add + sync, 2 rotations recorded by the witness, verify OK (${state.historyAEvents} events)`;
}, cliRan && witnessUp);

await check("cli", "demo, and the follow-up commands it prints", async () => {
  const out = await run(cli, ["demo"], { env: npmEnv, timeout: 120_000 });
  const followUps = [...out.stdout.matchAll(/^\s+irontrellis (--history \S+ .+)$/gm)].map((match) => argvOf(match[1]));
  expect(followUps.length >= 4, `demo printed ${followUps.length} follow-up commands`);
  for (const argv of followUps) await run(cli, argv, { env: npmEnv, codes: argv.includes("authorize") ? [0, 2, 3] : [0] });
  state.demoHistory = followUps[0][1];
  return `demo and its ${followUps.length} printed commands ran (history under TMPDIR)`;
}, npmInstalled);

// Hooks: the quickstart, then realistic payloads through the command the host would run.
await check("hooks", "README quickstart: init, install --write, check", async () => {
  const doc = "packages/hooks/README.md";
  const project = npmProject;
  const init = docLine(doc, "irontrellis-hook init --agent claude-code --allow write-file --expires +7d");
  await run(npmBin("irontrellis-hook"), argvOf(init).slice(1), { cwd: project, env: npmEnv });
  const install = docLine(doc, "irontrellis-hook install claude-code --write");
  await run(npmBin("irontrellis-hook"), argvOf(install).slice(1), { cwd: project, env: npmEnv });
  const settings = JSON.parse(readFileSync(join(project, ".claude", "settings.json"), "utf8"));
  const command = settings.hooks?.PreToolUse?.[0]?.hooks?.[0]?.command;
  // install claude-code writes /bin/sh -c '<wrapper>' <node> <launcher>, both by absolute path (no PATH lookup when the hook runs).
  const absolute = /^\/bin\/sh -c '[^']+' ('?)(\/[^']*\bnode(?:\.exe)?)\1 ('?)(\/[^']*\/bin\/irontrellis-hook\.mjs)\3 claude-code PreToolUse$/.exec(command ?? "");
  expect(absolute !== null && existsSync(absolute[2]) && existsSync(absolute[4]), `settings.json PreToolUse command is ${JSON.stringify(command)}`);
  const allowed = docLine(doc, `irontrellis-hook check claude-code Write --input '{"file_path":"/work/app/a.txt"}'`);
  const ok = await run(npmBin("irontrellis-hook"), substitute(argvOf(allowed), { "/work/app": project }).slice(1), { cwd: project, env: npmEnv });
  expect(/^DEFER\s+IronTrellis · ALLOW/.test(ok.stdout), `check Write printed ${tail(ok.stdout, 2)}`);
  const denied = docLine(doc, `irontrellis-hook check claude-code Bash --input '{"command":"npm test"}'`);
  const no = await run(npmBin("irontrellis-hook"), argvOf(denied).slice(1), { cwd: project, env: npmEnv, codes: [2] });
  expect(/^DENY\s+IronTrellis · DENY: .*\(ACTION_NOT_ALLOWED[;)]/.test(no.stdout), `check Bash printed ${tail(no.stdout, 2)}`);
  state.hooksReady = true;
  const settingsEvents = Object.keys(settings.hooks).join(", ");
  return `init + install --write (${settingsEvents}); check Write DEFER, check Bash DENY ACTION_NOT_ALLOWED (exit 2)`;
}, npmInstalled);

await check("hooks", "Claude Code payloads via the settings command, npx --no-install and npx", async () => {
  const project = npmProject;
  const settings = JSON.parse(readFileSync(join(project, ".claude", "settings.json"), "utf8"));
  const base = settings.hooks.PreToolUse[0].hooks[0].command.replace(/ claude-code PreToolUse$/, "");
  const list = await hookSession("settings command", base, project, npmEnv, HOOK_SESSION);
  // The README's alternative for hosts whose PATH lacks the bin: --command "npx --no-install irontrellis-hook".
  const npx = docLine("packages/hooks/README.md", 'Use `--command "npx --no-install irontrellis-hook"`').match(/"(npx[^"]+)"/)[1];
  // Printed for a project without settings yet (install merges and never rewrites an entry that already runs the hook).
  const fresh = join(TMP, "npx-settings");
  mkdirSync(fresh);
  const printed = await run(npmBin("irontrellis-hook"), ["install", "claude-code", "--dir", fresh, "--command", npx], { cwd: project, env: npmEnv });
  expect(printed.stdout.includes(`"${npx} claude-code PreToolUse"`), `install --command printed ${tail(printed.stdout, 4)}`);
  const npxEnv = { ...npmEnv, PATH: BASE_ENV.PATH }; // no node_modules/.bin on PATH: npx must find the local bin itself
  list.push(...await hookSession("npx --no-install", npx, project, npxEnv, "verify-install-session-2"));
  // Plain `npx irontrellis-hook` finds the project's own bin first (outside such a project it would fetch the unscoped npm name irontrellis-hook, which is not ours).
  list.push(...await hookSession("npx", "npx irontrellis-hook", project, { ...npxEnv, npm_config_registry: "http://127.0.0.1:9/", npm_config_fetch_retries: "0" }, "verify-install-session-3"));
  return problems(list, "SessionStart (context), PreToolUse Write (no decision), Bash (deny ACTION_NOT_ALLOWED), owner key (deny PROTECTED_PATH), Read (no decision), unmapped (ask), malformed (exit 2), PostToolUse (ignored), Stop and SessionEnd (handover record) — via the settings command, npx --no-install and npx");
}, npmInstalled && (state.hooksReady ?? false));

await check("mcp", "gateway and evidence servers: README quickstarts and a real MCP client over stdio", () => mcpFlows(npmProject, npmBin, npmEnv, "npm"), npmInstalled);

// ---------------------------------------------------------------- Python

let pythonDist;
if (OPT.python) {
  const pyVersion = PYTHON_VERSION;
  const pyBuilt = await check("python", `sdist + wheel (${pyVersion})`, async () => {
    const source = join(TMP, "python-src");
    cpSync(join(ROOT, "python"), source, { recursive: true, filter: (path) => !/(__pycache__|\.pytest_cache|\.ruff_cache|\.egg-info|\/build$|\/dist$|\.pyc$)/.test(path) });
    const pyproject = readFileSync(join(source, "pyproject.toml"), "utf8");
    const declared = /^version\s*=\s*"([^"]+)"/m.exec(pyproject)?.[1];
    expect(declared === pyVersion, `pyproject version ${declared} is not ${pyVersion} (the npm ${VERSION} in PEP 440 form)`);
    pythonDist = join(TMP, "python-dist");
    const buildVenv = join(TMP, "py-build");
    await run(PYTHON, ["-m", "venv", buildVenv]);
    let how;
    // The pinned tooling (exact versions and hashes): build, twine and the setuptools backend, which the build then
    // uses (--no-isolation) instead of whatever setuptools PyPI serves that day.
    const frontend = await run(venvBin(buildVenv, "python"), ["-m", "pip", "install", "--quiet", "--require-hashes", "--only-binary", ":all:", "-r", RELEASE_REQUIREMENTS], { timeout: 300_000, codes: [0, 1, 2] });
    if (frontend.code !== 0 && process.env.CI !== undefined) fail(`could not install the pinned Python release tooling (${posix.basename(RELEASE_REQUIREMENTS)}): ${tail(frontend.stderr, 6)}`);
    if (frontend.code === 0) {
      // No --sdist/--wheel: build the sdist, then the wheel FROM the sdist, which proves the sdist is complete.
      await run(venvBin(buildVenv, "python"), ["-m", "build", "--no-isolation", "--outdir", pythonDist, source], { timeout: 300_000 });
      const versions = (await run(venvBin(buildVenv, "python"), ["-c", "import importlib.metadata as m; print(' '.join(f'{p} {m.version(p)}' for p in ('build', 'setuptools', 'twine')))"])).stdout.trim();
      how = `python -m build --no-isolation (wheel built from the sdist; pinned ${versions})`;
    } else {
      mkdirSync(pythonDist);
      const script = "import sys, setuptools.build_meta as b; print(b.build_sdist(sys.argv[1])); print(b.build_wheel(sys.argv[1]))";
      await run(PYTHON, ["-c", script, pythonDist], { cwd: source, timeout: 300_000 });
      how = "the project's setuptools backend (UNPINNED: the pinned build frontend could not be installed, offline?; a CI run fails instead)";
    }
    const made = readdirSync(pythonDist);
    const wheel = made.find((file) => file.endsWith(".whl")), sdist = made.find((file) => file.endsWith(".tar.gz"));
    expect(wheel === `irontrellis-${pyVersion}-py3-none-any.whl` && sdist === `irontrellis-${pyVersion}.tar.gz`, `built ${made.join(", ")}`);
    let twine = "";
    if (frontend.code === 0) { await run(venvBin(buildVenv, "twine"), ["check", "--strict", join(pythonDist, wheel), join(pythonDist, sdist)]); twine = "; twine check --strict passes"; }
    return `${sdist}, ${wheel} via ${how}${twine}`;
  });

  await check("python", "sdist and wheel contents", async () => {
    const list = [];
    const dist = readdirSync(pythonDist);
    const wheel = join(pythonDist, dist.find((file) => file.endsWith(".whl")));
    const names = parseJson((await run(PYTHON, ["-c", "import sys, json, zipfile; z = zipfile.ZipFile(sys.argv[1]); print(json.dumps({n: z.read(n).decode('utf8', 'replace') if n.endswith(('METADATA', 'entry_points.txt')) else None for n in z.namelist()}))", wheel])).stdout, "wheel listing");
    const paths = Object.keys(names);
    for (const required of ["irontrellis/__init__.py", "irontrellis/__main__.py", "irontrellis/py.typed", "irontrellis/crypto/__init__.py", "irontrellis/crypto/ed25519.py", "irontrellis/transparency.py"]) if (!paths.includes(required)) list.push(`wheel lacks ${required}`);
    for (const path of paths) if (/__pycache__|\.pyc$|(^|\/)tests?\//.test(path)) list.push(`wheel ships ${path}`);
    const metadata = Object.entries(names).find(([path]) => path.endsWith(".dist-info/METADATA"))?.[1] ?? "";
    if (!metadata.includes(`Version: ${PYTHON_VERSION}`)) list.push("METADATA has another version");
    if (!/Requires-Python: >=3\.11/.test(metadata)) list.push("METADATA lacks Requires-Python >=3.11");
    if (!/Description-Content-Type: text\/markdown/.test(metadata)) list.push("METADATA: the README is not declared as Markdown");
    for (const file of ["LICENSE", "NOTICE"]) if (!paths.some((path) => new RegExp(`\\.dist-info/(licenses/)?${file}$`).test(path))) list.push(`wheel lacks ${file} in its .dist-info`);
    const entryPoints = Object.entries(names).find(([path]) => path.endsWith("entry_points.txt"))?.[1] ?? "";
    if (!/irontrellis-py\s*=\s*irontrellis\.__main__:main/.test(entryPoints)) list.push("wheel lacks the irontrellis-py console script");
    const sdist = readTarGz(join(pythonDist, dist.find((file) => file.endsWith(".tar.gz"))));
    const top = `irontrellis-${PYTHON_VERSION}/`;
    const sdistPaths = sdist.map((entry) => entry.path.slice(top.length));
    for (const required of ["PKG-INFO", "pyproject.toml", "README.md", "LICENSE", "NOTICE", "src/irontrellis/__init__.py", "src/irontrellis/py.typed", "src/irontrellis/crypto/__init__.py"]) if (!sdistPaths.includes(required)) list.push(`sdist lacks ${required}`);
    for (const path of sdistPaths) if (/__pycache__|\.pyc$|\.pytest_cache|\.ruff_cache/.test(path)) list.push(`sdist ships ${path}`);
    for (const [label, entries] of [["wheel", []], ["sdist", sdist]]) for (const entry of entries) for (const [pattern, what] of SECRETS) if (pattern.test(entry.data.toString("utf8"))) list.push(`${label} ${entry.path} contains ${what}`);
    const license = sdist.find((entry) => entry.path === `${top}LICENSE`);
    if (license && !license.data.equals(LICENSE)) list.push("sdist LICENSE differs from the repository LICENSE");
    return problems(list, `wheel: ${paths.length} files (package, crypto/, py.typed, LICENSE, NOTICE, irontrellis-py); sdist: ${sdistPaths.length} files; no caches or tests in the wheel`);
  }, pyBuilt);

  const venv = join(TMP, "py-venv");
  const pyEnv = envWith([join(venv, "bin")], { PIP_NO_INDEX: "1", PIP_FIND_LINKS: pythonDist ?? "" });
  const pyInstalled = await check("python", "fresh venv: README 'pip install --pre irontrellis' from the wheel only", async () => {
    await run(PYTHON, ["-m", "venv", venv]);
    const line = docLine("python/README.md", "pip install --pre irontrellis");
    await run("pip", [...argvOf(line).slice(1), "--only-binary", ":all:"], { env: pyEnv, timeout: 180_000 });
    const shown = await run(venvBin(venv, "python"), ["-m", "pip", "show", "irontrellis"], { env: pyEnv });
    expect(shown.stdout.includes(`Version: ${PYTHON_VERSION}`), `pip show: ${tail(shown.stdout, 3)}`);
    return `irontrellis ${PYTHON_VERSION} installed with --no-index from the built wheel`;
  }, pyBuilt);

  // The Python package is frozen at format 1 (python/README.md): the packed CLI writes format 2 only, so the Python
  // verifier must refuse those histories with UNSUPPORTED_VERSION (BUILD §8) rather than read them.
  await check("python", "python -m irontrellis refuses the format-2 histories the packed CLI wrote (UNSUPPORTED_VERSION; frozen at format 1)", async () => {
    const py = (args) => run(venvBin(venv, "python"), ["-m", "irontrellis", ...args], { env: pyEnv, codes: [1] });
    for (const history of [historyA, historyB, state.demoHistory]) {
      const refused = parseJson((await py(["verify", history])).stdout, "verify");
      expect(refused.code === "UNSUPPORTED_VERSION", `verify ${history}: ${JSON.stringify(refused)}`);
    }
    return "UNSUPPORTED_VERSION for the CLI's, the witnessed and the demo history";
  }, pyInstalled && cliRan && state.demoHistory !== undefined);

  await check("python", "python -m irontrellis verify-receipt on a receipt the packed witness signed", async () => {
    const response = join(TMP, "witness-response.json");
    const line = docLine("python/README.md", "python -m irontrellis verify-receipt receipt.json --verifier-key 'witness.example+1a2b3c4d+AQ…'");
    const argv = substitute(argvOf(line), { "receipt.json": response, "witness.example+1a2b3c4d+AQ…": witness.verifierKey });
    // The witnessed history is format 2; the frozen Python verifier reads format-1 statement domains only (KNOWN-ISSUES).
    const refused = parseJson((await run(venvBin(venv, "python"), argv.slice(1), { env: pyEnv, codes: [1] })).stdout, "verify-receipt");
    expect(refused.status === "INVALID" && refused.reason === "ENTRY_MALFORMED", `verify-receipt: ${JSON.stringify(refused)}`);
    return "INVALID (ENTRY_MALFORMED): the format-1 Python verifier does not read a format-2 statement";
  }, pyInstalled && (state.receiptReady ?? false));

  await check("python", "a second venv installs from the sdist (isolated build)", async () => {
    const venv2 = join(TMP, "py-venv-sdist");
    await run(PYTHON, ["-m", "venv", venv2]);
    const sdist = join(pythonDist, readdirSync(pythonDist).find((file) => file.endsWith(".tar.gz")));
    await run(venvBin(venv2, "python"), ["-m", "pip", "install", "--quiet", sdist], { env: { ...BASE_ENV }, timeout: 300_000 });
    // Frozen at format 1: it verifies a format-1 history (a conformance/v1 fixture) and refuses the CLI's format-2 one.
    const fixture = join(ROOT, "conformance", "v1", "histories", "authority-v1.jsonl");
    const out = parseJson((await run(venvBin(venv2, "python"), ["-m", "irontrellis", "verify", fixture], { env: BASE_ENV })).stdout, "verify");
    expect(out.status === "ACCEPTED" && out.format === "irontrellis-event/1", `verify ${fixture}: ${out.status} ${out.format}`);
    const refused = parseJson((await run(venvBin(venv2, "python"), ["-m", "irontrellis", "verify", historyA], { env: BASE_ENV, codes: [1] })).stdout, "verify");
    expect(refused.code === "UNSUPPORTED_VERSION", `verify ${historyA}: ${JSON.stringify(refused)}`);
    return "built from the sdist; verifies a format-1 history (conformance/v1 authority-v1) and refuses the CLI's format-2 history (UNSUPPORTED_VERSION)";
  }, pyBuilt && cliRan);
}

// Stop the witness: SIGTERM finishes in-flight work and exits 0 (packages/witness/README.md).
if (witness) {
  await check("witness", "SIGTERM stops the server with exit 0", async () => {
    witness.child.kill("SIGTERM");
    const result = await Promise.race([witness.exited, new Promise((resolveTimeout) => setTimeout(() => resolveTimeout({ code: "timeout" }), 15_000))]);
    expect(result.code === 0, `exited ${result.code ?? result.signal}`);
    return "exit 0";
  });
}

// ---------------------------------------------------------------- the local registry: pnpm, global npm, npx, docs

let registry;
const registryUp = await check("registry", "local registry serving only the packed tarballs", async () => {
  registry = await startRegistry();
  const packument = await (await fetch(`${registry}/${encodeURIComponent("@ramex-labs/irontrellis").replace("%40", "@")}`)).json();
  expect(packument["dist-tags"]?.next === VERSION || packument["dist-tags"]?.latest === VERSION, "the core is not served");
  return `${packed.size} packages under dist-tag ${VERSION.includes("-") ? "next" : "latest"} (as release.yml publishes); everything else redirected to ${OPT.upstream}`;
}, didPack);

const pnpmProject = join(TMP, "pnpm-consumer");
const pnpmBin = (name) => join(pnpmProject, "node_modules", ".bin", name);
const pnpmEnv = envWith([join(pnpmProject, "node_modules", ".bin")]);
const pnpmInstalled = await check("pnpm", "pnpm add <every package>@next (strict node_modules)", async () => {
  makeProject(pnpmProject, { registry, "fetch-retries": "0" }, { storeDir: dirs.pnpmStore, cacheDir: dirs.pnpmCache, strictPeerDependencies: true, fetchRetries: 0 });
  const specs = [...packed.keys()].map((name) => `${name}@${VERSION.includes("-") ? "next" : "latest"}`);
  await run("pnpm", ["add", ...specs, ...PEER_SPECS, `@modelcontextprotocol/client@${MCP_CLIENT_VERSION}`, `typescript@${TS_RANGE}`, `@types/node@${TYPES_NODE_RANGE}`], { cwd: pnpmProject, env: pnpmEnv, timeout: 600_000 });
  const lock = readFileSync(join(pnpmProject, "pnpm-lock.yaml"), "utf8");
  const list = [];
  for (const [name, entry] of packed) {
    const match = new RegExp(`\\n  '?${name.replace(/[/.]/g, "\\$&")}@${VERSION.replace(/\./g, "\\.")}'?:\\n    resolution: \\{integrity: ([^,}\\s]+)`).exec(lock);
    if (!match) list.push(`${name}@${VERSION} is not in pnpm-lock.yaml`);
    else if (match[1].trim() !== entry.integrity) list.push(`${name}: installed integrity ${match[1].trim()} is not the packed tarball's`);
  }
  const copies = readdirSync(join(pnpmProject, "node_modules", ".pnpm")).filter((dir) => /^@ramex-labs\+irontrellis@/.test(dir));
  if (copies.length !== 1) list.push(`${copies.length} copies of the core in node_modules/.pnpm: ${copies.join(", ")}`);
  return problems(list, `${packed.size} packages with the packed tarballs' integrity; workspace:* resolved to the one packed core (${copies[0]})`);
}, registryUp);
await check("pnpm", "every bin: --help and --version", () => binsRespond(join(pnpmProject, "node_modules", ".bin"), pnpmEnv), pnpmInstalled);
await check("pnpm", "ESM import and require() of every public subpath", () => importsWork(pnpmProject, pnpmEnv), pnpmInstalled);
await check("pnpm", "consumer type-check (tsc --noEmit)", () => typesResolve(pnpmProject, pnpmEnv), pnpmInstalled);
await check("pnpm", "CLI demo, hooks through pnpm exec, MCP servers", async () => {
  await run(pnpmBin("irontrellis"), ["demo", "--quiet"], { env: pnpmEnv });
  await run(pnpmBin("irontrellis-hook"), ["init", "--agent", "claude-code", "--allow", "write-file", "--expires", "+7d"], { cwd: pnpmProject, env: pnpmEnv });
  const list = await hookSession("pnpm exec", "pnpm exec irontrellis-hook", pnpmProject, { ...pnpmEnv, PATH: BASE_ENV.PATH }, "verify-install-session-pnpm");
  problems(list);
  return `demo; hooks via pnpm exec; ${await mcpFlows(pnpmProject, pnpmBin, pnpmEnv, "pnpm")}`;
}, pnpmInstalled);

// The install commands of the docs, verbatim, against the local registry.
const globalPrefix = join(TMP, "global");
const globalBin = join(globalPrefix, "bin");
let globalEnv;
const docInstalls = [
  ["packages/cli/README.md", "npm install -g irontrellis@next"],
  ["packages/hooks/README.md", "npm install -g @ramex-labs/irontrellis-hooks@next"],
  ["packages/witness/README.md", "npm install -g @ramex-labs/irontrellis-witness@next"],
  ["docs/WITNESS.md", "npm install -g @ramex-labs/irontrellis-witness@next"],
  ["packages/mcp-gateway/README.md", "npm install -g @ramex-labs/irontrellis-mcp-gateway@next"],
  ["packages/mcp-evidence/README.md", "npm install -g @ramex-labs/irontrellis-mcp@next"],
];
const globalInstalled = await check("global", `the docs' ${docInstalls.length} 'npm install -g …@next' commands, verbatim, into a temporary prefix`, async () => {
  globalEnv = envWith([globalBin], { npm_config_registry: registry, npm_config_prefix: globalPrefix });
  for (const [file, line] of docInstalls) await run("npm", argvOf(docLine(file, line)).slice(1), { env: globalEnv, timeout: 600_000 });
  const missing = allBins().filter(({ bin }) => !existsSync(join(globalBin, bin))).map(({ bin }) => bin);
  expect(missing.length === 0, `not on the global PATH: ${missing.join(", ")}`);
  return `${allBins().length} commands on the prefix's PATH`;
}, registryUp && VERSION.includes("-"));
await check("global", "every global bin: --help and --version", () => binsRespond(globalBin, globalEnv), globalInstalled);
await check("global", "irontrellis demo; irontrellis-hook from PATH (the command install writes); witness serve; gateway and evidence setup", async () => {
  await run("irontrellis", ["demo", "--quiet"], { env: globalEnv });
  const project = join(TMP, "global-hook-project");
  mkdirSync(project);
  await run("irontrellis-hook", ["init", "--agent", "claude-code", "--allow", "write-file", "--expires", "+7d"], { cwd: project, env: globalEnv });
  await run("irontrellis-hook", ["install", "claude-code", "--write"], { cwd: project, env: globalEnv });
  const command = JSON.parse(readFileSync(join(project, ".claude", "settings.json"), "utf8")).hooks.PreToolUse[0].hooks[0].command.replace(/ claude-code PreToolUse$/, "");
  problems(await hookSession("global", command, project, globalEnv, "verify-install-session-global"));
  const data = join(TMP, "global-witness");
  await run("irontrellis-witness", ["init", "--data", data, "--name", "global.test"], { env: globalEnv });
  const served = await start(join(globalBin, "irontrellis-witness"), ["serve", "--data", data, "--listen", "127.0.0.1:0"], { env: globalEnv, ready: (line) => { try { const entry = JSON.parse(line); return entry.msg === "listening" ? entry.url : undefined; } catch { return undefined; } } });
  const health = await (await fetch(`${served.value}/healthz`)).json();
  served.child.kill("SIGTERM");
  const stopped = await served.exited;
  expect(health.status === "ok" && stopped.code === 0, `healthz ${JSON.stringify(health)}, exit ${stopped.code}`);
  await run("irontrellis-mcp-gateway", ["setup", join(TMP, "global-gateway-case")], { env: globalEnv });
  await run("irontrellis-mcp-ops", ["inspect", "--config", join(TMP, "global-gateway-case", "gateway.json")], { env: globalEnv });
  await run("irontrellis-evidence-setup", [join(TMP, "global-evidence-case")], { env: globalEnv });
  const demo = await run("irontrellis-evidence-demo", [join(TMP, "global-evidence-case", "gateway.json")], { env: globalEnv, timeout: 90_000 });
  expect(demo.stdout.includes('"RECONCILIATION_ONLY"'), "the global evidence demo did not reconcile");
  const probeOut = await probe(npmProject, { command: join(globalBin, "irontrellis-mcp-gateway"), args: ["--config", join(TMP, "global-gateway-case", "gateway.json")], calls: [{ name: "read_incident", arguments: { document: "incident" } }] }, globalEnv);
  expect(probeOut.calls[0].structuredContent?.status === "RESPONSE_RETAINED", `global gateway answered ${probeOut.calls[0].text.slice(0, 200)}`);
  return "demo; hook session via PATH; witness serve/healthz/SIGTERM; gateway setup + MCP call; evidence setup + demo";
}, globalInstalled);

await check("global", "npm i -g <cli tarball> into a temporary prefix", async () => {
  const prefix = join(TMP, "global-tarball");
  const env = envWith([join(prefix, "bin")], { npm_config_registry: registry, npm_config_prefix: prefix });
  await run("npm", ["i", "-g", packed.get("irontrellis").file], { env, timeout: 600_000 });
  const version = await run(join(prefix, "bin", "irontrellis"), ["--version"], { env });
  expect(version.stdout.trim() === `irontrellis ${VERSION}`, `--version printed ${version.stdout.trim()}`);
  await run(join(prefix, "bin", "irontrellis"), ["demo", "--quiet"], { env });
  return `irontrellis ${VERSION}; its core dependency resolved from the registry to the packed tarball; demo runs`;
}, registryUp && packed.has("irontrellis"));

await check("docs", "'npx irontrellis@next demo', npx -p <hooks>, 'npm install @ramex-labs/irontrellis@next'", async () => {
  const empty = join(TMP, "npx");
  mkdirSync(empty);
  const env = envWith([], { npm_config_registry: registry, npm_config_cache: join(TMP, "npx-cache"), npm_config_yes: "true" });
  docLine("packages/cli/README.md", "npx irontrellis@next demo");
  const npx = await run("npx", argvOf(docLine("packages/cli/README.md", "npx irontrellis@next demo")).slice(1), { cwd: empty, env, timeout: 600_000 });
  expect(/WHY was bea allowed/.test(npx.stdout) && /After the handover/.test(npx.stdout), `npx demo printed ${tail(npx.stdout, 4)}`);
  // Without a local install: npx with the scoped package named explicitly.
  const hookVersion = await run("npx", ["--yes", "-p", "@ramex-labs/irontrellis-hooks@next", "irontrellis-hook", "--version"], { cwd: empty, env, timeout: 600_000 });
  expect(hookVersion.stdout.trim() === VERSION, `npx -p @ramex-labs/irontrellis-hooks@next irontrellis-hook --version printed ${hookVersion.stdout.trim()}`);
  const project = makeProject(join(TMP, "docs-core"), { registry });
  docLine("packages/core/README.md", "npm install @ramex-labs/irontrellis@next");
  await run("npm", argvOf(docLine("packages/core/README.md", "npm install @ramex-labs/irontrellis@next")).slice(1), { cwd: project, env: envWith([], { npm_config_registry: registry }), timeout: 600_000 });
  writeFileSync(join(project, "quickstart.mjs"), codeBlock("packages/core/README.md", "## 60-second quickstart", "js"));
  const out = await run(process.execPath, ["quickstart.mjs"], { cwd: project, env: BASE_ENV });
  expect(out.stdout.includes("DENY REVOKED"), `quickstart printed ${tail(out.stdout, 4)}`);
  const manifest = JSON.parse(readFileSync(join(project, "package.json"), "utf8"));
  expect(Object.keys(manifest.dependencies).join() === "@ramex-labs/irontrellis", `installed ${Object.keys(manifest.dependencies)}`);
  const tree = readdirSync(join(project, "node_modules")).filter((name) => !name.startsWith("."));
  expect(tree.join() === "@ramex-labs", `the core pulled in runtime dependencies: ${tree.join(", ")} (its README says zero)`);
  return "npx demo prints the three answers; npx -p @ramex-labs/irontrellis-hooks@next irontrellis-hook runs; the core installs with zero runtime dependencies and its quickstart runs";
}, registryUp && VERSION.includes("-"));

// ---------------------------------------------------------------- report

const counts = { PASS: 0, FAIL: 0, SKIP: 0 };
for (const result of results) counts[result.status] += 1;
const width = Math.min(90, Math.max(...results.map((result) => result.name.length)));
const clip = (text, length) => (text.length > length ? `${text.slice(0, length - 1)}…` : text);
console.log(`\n${"#".padStart(3)}  ${"section".padEnd(8)}  ${"check".padEnd(width)}  result  ${"time".padStart(6)}`);
console.log(`${"-".repeat(3)}  ${"-".repeat(8)}  ${"-".repeat(width)}  ------  ${"-".repeat(6)}`);
results.forEach((result, index) => {
  console.log(`${String(index + 1).padStart(3)}  ${result.section.padEnd(8)}  ${clip(result.name, width).padEnd(width)}  ${result.status.padEnd(6)}  ${`${(result.ms / 1000).toFixed(1)}s`.padStart(6)}`);
});
for (const result of results.filter((entry) => entry.status === "FAIL")) console.log(`\nFAIL ${result.section} / ${result.name}\n  ${result.detail.split("\n").join("\n  ")}`);
const verdict = counts.FAIL === 0 && counts.SKIP === 0 ? "PASS" : "FAIL";
console.log(`\nverify-install ${verdict}: ${counts.PASS} passed, ${counts.FAIL} failed, ${counts.SKIP} skipped (${packed.size} packages at ${VERSION}, node ${process.version}, ${process.platform})`);
if (OPT.json) writeFileSync(OPT.json, JSON.stringify({ verdict, version: VERSION, node: process.version, platform: process.platform, tarballs: state.tarballs ?? [], results }, null, 2) + "\n");
if (OPT.keep) console.log(`kept ${[TMP, ...socketDirs].join(", ")}`);
cleanup();
process.exit(verdict === "PASS" ? 0 : 1);
