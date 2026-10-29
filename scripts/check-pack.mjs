#!/usr/bin/env node
/**
 * `npm pack --dry-run` every publishable package and refuse anything outside the allow-list:
 * package.json, README.md, LICENSE, NOTICE and dist/** (compiled JS, .d.ts, source maps), plus,
 * only when the package's `files` field lists them: bin/** (bin shims), server.json (MCP
 * registry metadata), Markdown under docs/ (operator docs), ES modules and their declarations at
 * the package root (`*.mjs`, `*.d.mts`: packages shipped without a build step, which then need no
 * dist/) and the LICENSING.md / THIRD-PARTY-NOTICES.md licence notes. Every `bin` target must be
 * packed. Run after `pnpm -r build`. Exit 1 on any unexpected file, missing required file, empty
 * dist, a test file at the package root, or a `files` entry that matches no packed file (npm skips a missing entry
 * without a word, so a listed licence note could silently be absent).
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES = join(ROOT, "packages");
const REQUIRED = ["package.json", "README.md", "LICENSE", "NOTICE"];
const ALWAYS = /^(package\.json|README\.md|LICENSE|NOTICE|dist\/.+\.(js|mjs|cjs|d\.ts|d\.mts|d\.cts|js\.map|d\.ts\.map|json))$/;
// Extra paths a package may ship, each allowed only when its `files` field lists the entry.
const OPTIONAL = [
  { entry: "bin", pattern: /^bin\/.+$/ },
  { entry: "server.json", pattern: /^server\.json$/ },
  { entry: "docs", pattern: /^docs\/.+\.md$/ },
  { entry: "*.mjs", pattern: /^[^/]+\.mjs$/ },
  { entry: "*.d.mts", pattern: /^[^/]+\.d\.mts$/ },
  { entry: "LICENSING.md", pattern: /^LICENSING\.md$/ },
  { entry: "THIRD-PARTY-NOTICES.md", pattern: /^THIRD-PARTY-NOTICES\.md$/ },
];
const normalizeFilesEntry = (entry) => entry.replace(/^\.\//, "").replace(/(\/\*\*)?(\/\*[^/]*)?\/?$/, "");
/** Whether a packed path is matched by a `files` entry: a name, a directory (everything under it) or a glob (`*` within one segment, `**` across). */
const filesEntryMatches = (entry, path) => {
  const e = entry.replace(/^\.\//, "").replace(/\/$/, "");
  if (!e.includes("*")) return path === e || path.startsWith(e + "/");
  const pattern = e.split(/(\*\*|\*)/).map((part) => (part === "**" ? ".*" : part === "*" ? "[^/]*" : part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))).join("");
  return new RegExp(`^${pattern}$`).test(path);
};

let failed = false;
for (const entry of readdirSync(PACKAGES, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const dir = join(PACKAGES, entry.name);
  const manifestPath = join(dir, "package.json");
  if (!existsSync(manifestPath)) continue;
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.private === true) continue;

  let files;
  try {
    // npm is npm.cmd on Windows, which Node runs only through a shell (fixed arguments, nothing to quote).
    const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], shell: process.platform === "win32" });
    files = JSON.parse(out)[0].files.map((file) => file.path);
  } catch (error) {
    console.error(`${manifest.name}: npm pack failed: ${error.stderr ?? error.message}`);
    failed = true;
    continue;
  }
  const listed = new Set((manifest.files ?? []).map(normalizeFilesEntry));
  const allowed = [ALWAYS, ...OPTIONAL.filter(({ entry }) => listed.has(entry)).map(({ pattern }) => pattern)];
  const unexpected = files.filter((path) => !allowed.some((pattern) => pattern.test(path)));
  const bins = typeof manifest.bin === "string" ? { [manifest.name]: manifest.bin } : (manifest.bin ?? {});
  const missingBins = Object.entries(bins).filter(([, target]) => !files.includes(target.replace(/^\.\//, "")));
  const missing = REQUIRED.filter((path) => !files.includes(path));
  const dist = files.filter((path) => path.startsWith("dist/"));
  const problems = [];
  if (unexpected.length) problems.push(`unexpected files: ${unexpected.join(", ")}`);
  if (missing.length) problems.push(`missing: ${missing.join(", ")}`);
  if (missingBins.length) problems.push(`bin targets not packed: ${missingBins.map(([name, target]) => `${name} -> ${target}`).join(", ")}`);
  const rootModules = listed.has("*.mjs") && listed.has("*.d.mts");
  if (dist.length === 0 && !rootModules) problems.push("dist/ is empty (run pnpm -r build first)");
  if (rootModules && !files.some((path) => /^[^/]+\.mjs$/.test(path))) problems.push("no ES module at the package root");
  if (dist.some((path) => path.endsWith(".test.js") || path.includes("/test/"))) problems.push("tests leaked into dist/");
  if (files.some((path) => /^[^/]+\.test\.m?js$/.test(path))) problems.push("tests leaked into the package root");
  const unmatched = (manifest.files ?? []).filter((entry) => !files.some((path) => filesEntryMatches(entry, path)));
  if (unmatched.length) problems.push(`files entries that match no packed file: ${unmatched.join(", ")}`);
  if (problems.length) {
    failed = true;
    console.error(`FAIL ${manifest.name}@${manifest.version} (${files.length} files)`);
    for (const problem of problems) console.error(`  - ${problem}`);
  } else {
    const extras = OPTIONAL.filter(({ entry }) => listed.has(entry)).map(({ entry }) => entry);
    console.log(`OK   ${manifest.name}@${manifest.version}: ${files.length} files, all within dist/, README.md, LICENSE, NOTICE, package.json${extras.length ? `, ${extras.join(", ")}` : ""}`);
  }
}
process.exit(failed ? 1 : 0);
