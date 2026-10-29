#!/usr/bin/env node
/**
 * Every publishable package in the workspace must share one `version` and one `engines`
 * field, carry the same licence, and ship only the files we mean to ship. The same version
 * must also be the one the MCP Registry entries (`packages/<name>/server.json`), the Python
 * package (`python/pyproject.toml` and `irontrellis.__version__`, in its PEP 440 spelling)
 * and the CHANGELOG (the first `## [<version>]` heading, which the release workflow
 * extracts) carry.
 *
 *   node scripts/check-versions.mjs            # exit 1 on any disagreement
 *   node scripts/check-versions.mjs --json     # machine-readable report
 *
 * Private packages (the workspace root, packages/reference-0.2) are listed but not compared.
 */
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES = join(ROOT, "packages");
const REQUIRED_FILES = ["dist", "README.md", "LICENSE", "NOTICE"];
const EXPECTED_LICENSE = "Apache-2.0";

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const canonical = (value) => JSON.stringify(value, Object.keys(value ?? {}).sort());

const packages = readdirSync(PACKAGES, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && existsSync(join(PACKAGES, entry.name, "package.json")))
  .map((entry) => {
    const dir = join(PACKAGES, entry.name);
    const manifest = readJson(join(dir, "package.json"));
    return { dir: `packages/${entry.name}`, manifest };
  });

const publishable = packages.filter(({ manifest }) => manifest.private !== true);
const problems = [];

if (publishable.length === 0) problems.push("no publishable package found under packages/");

const versions = new Set(publishable.map(({ manifest }) => manifest.version));
if (versions.size > 1) problems.push(`versions differ: ${publishable.map(({ dir, manifest }) => `${dir}=${manifest.version}`).join(", ")}`);

const engines = new Set(publishable.map(({ manifest }) => canonical(manifest.engines)));
if (engines.size > 1) problems.push(`engines differ: ${publishable.map(({ dir, manifest }) => `${dir}=${canonical(manifest.engines)}`).join(", ")}`);

for (const { dir, manifest } of publishable) {
  if (!manifest.engines?.node) problems.push(`${dir}: engines.node is missing`);
  if (manifest.license !== EXPECTED_LICENSE) problems.push(`${dir}: license is ${manifest.license ?? "missing"}, expected ${EXPECTED_LICENSE}`);
  if (manifest.type !== "module") problems.push(`${dir}: "type" must be "module"`);
  if (manifest.name?.startsWith("@") && manifest.publishConfig?.access !== "public") problems.push(`${dir}: scoped package needs publishConfig.access = "public"`);
  if (manifest.publishConfig?.provenance !== true) problems.push(`${dir}: publishConfig.provenance must be true`);
  if (!manifest.repository?.url?.includes("github.com/zerohourzulu/irontrellis")) problems.push(`${dir}: repository.url must point at github.com/zerohourzulu/irontrellis`);
  if (manifest.repository?.directory !== dir) problems.push(`${dir}: repository.directory is ${manifest.repository?.directory ?? "missing"}, expected ${dir}`);
  const files = manifest.files ?? [];
  // A package either builds into dist/ or ships its hand-written ES modules and declarations at its root
  // (remote, remote-tools: `"files": ["*.mjs", "*.d.mts", …]`, no build step).
  const rootModules = files.includes("*.mjs") && files.includes("*.d.mts");
  for (const required of REQUIRED_FILES) if (!files.includes(required) && !(required === "dist" && rootModules)) problems.push(`${dir}: "files" must include ${required}${required === "dist" ? ' (or both "*.mjs" and "*.d.mts")' : ""}`);
  for (const required of ["README.md", "LICENSE", "NOTICE"]) {
    if (!existsSync(join(ROOT, dir, required))) problems.push(`${dir}: ${required} is missing from the package directory (it is listed in "files")`);
  }
  for (const [name, spec] of Object.entries(manifest.dependencies ?? {})) {
    if (typeof spec === "string" && spec.startsWith("file:")) problems.push(`${dir}: dependency ${name} uses a file: specifier`);
  }
}

const version = [...versions][0];

/** The PEP 440 spelling of a semver pre-release: 1.0.0-rc.2 → 1.0.0rc2, 1.2.3-beta.2 → 1.2.3b2, 1.0.0 → 1.0.0. */
const pep440 = (semver) => {
  const match = /^(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.(\d+))?$/.exec(semver ?? "");
  if (match === null) return undefined;
  if (match[2] === undefined) return match[1];
  return `${match[1]}${{ alpha: "a", beta: "b", rc: "rc" }[match[2]]}${match[3]}`;
};

// MCP Registry entries: server.json's own version, and the version of the npm package it names.
for (const { dir, manifest } of publishable) {
  const serverPath = join(ROOT, dir, "server.json");
  if (!existsSync(serverPath)) {
    if (manifest.mcpName !== undefined) problems.push(`${dir}: mcpName is set but server.json is missing`);
    continue;
  }
  const server = readJson(serverPath);
  if (server.name !== manifest.mcpName) problems.push(`${dir}/server.json: name ${server.name} is not the package's mcpName ${manifest.mcpName}`);
  if (server.version !== manifest.version) problems.push(`${dir}/server.json: version ${server.version} is not ${manifest.version}`);
  for (const entry of server.packages ?? []) {
    if (entry.registryType !== "npm") continue;
    if (entry.identifier !== manifest.name) problems.push(`${dir}/server.json: package ${entry.identifier} is not ${manifest.name}`);
    if (entry.version !== manifest.version) problems.push(`${dir}/server.json: package version ${entry.version} is not ${manifest.version}`);
  }
}

// The Python package: pyproject.toml and irontrellis.__version__, in PEP 440 form. It is frozen at format 1
// (BUILD §8) and keeps the version it was frozen at until it is ported to format 2; then it moves back into step.
const pythonVersion = "1.0.0rc1"; // the PEP 440 spelling of the first release candidate
const PYTHON_FROZEN_AT = pythonVersion;
const pyproject = join(ROOT, "python", "pyproject.toml");
const pythonInit = join(ROOT, "python", "src", "irontrellis", "__init__.py");
if (versions.size === 1 && pythonVersion === undefined) problems.push(`version ${version} has no PEP 440 spelling this check knows (x.y.z or x.y.z-alpha|beta|rc.n)`);
if (existsSync(pyproject)) {
  const declared = /^version\s*=\s*"([^"]+)"/m.exec(readFileSync(pyproject, "utf8"))?.[1];
  if (declared !== pythonVersion) problems.push(`python/pyproject.toml: version ${declared ?? "missing"}, expected ${pythonVersion} (frozen at ${PYTHON_FROZEN_AT}, BUILD §8)`);
  const runtime = existsSync(pythonInit) ? /^__version__\s*=\s*"([^"]+)"/m.exec(readFileSync(pythonInit, "utf8"))?.[1] : undefined;
  if (runtime !== pythonVersion) problems.push(`python/src/irontrellis/__init__.py: __version__ ${runtime ?? "missing"}, expected ${pythonVersion}`);
} else {
  problems.push("python/pyproject.toml is missing");
}

// The CHANGELOG: the newest entry is this version, under the heading the release workflow greps (`^## \[<version>\]`).
const changelogPath = join(ROOT, "CHANGELOG.md");
const firstEntry = existsSync(changelogPath) ? readFileSync(changelogPath, "utf8").split("\n").find((line) => line.startsWith("## [")) : undefined;
if (firstEntry === undefined) problems.push("CHANGELOG.md has no `## [<version>]` entry");
else if (!firstEntry.startsWith(`## [${version}]`)) problems.push(`CHANGELOG.md: the newest entry is "${firstEntry}", expected "## [${version}] - <date>"`);

// The workspace root's engines must match too, since CI installs with engine-strict.
const rootManifest = readJson(join(ROOT, "package.json"));
if (publishable.length > 0 && canonical(rootManifest.engines) !== canonical(publishable[0].manifest.engines)) {
  problems.push(`workspace root engines ${canonical(rootManifest.engines)} differ from packages ${canonical(publishable[0].manifest.engines)}`);
}

const report = {
  version: version ?? null,
  python: pythonVersion ?? null,
  engines: publishable[0]?.manifest.engines ?? null,
  publishable: publishable.map(({ dir, manifest }) => ({ dir, name: manifest.name, version: manifest.version })),
  private: packages.filter(({ manifest }) => manifest.private === true).map(({ dir, manifest }) => ({ dir, name: manifest.name })),
  problems,
};

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(report, null, 2));
} else {
  for (const entry of report.publishable) console.log(`publishable  ${entry.name.padEnd(40)} ${entry.version}  (${entry.dir})`);
  for (const entry of report.private) console.log(`private      ${entry.name.padEnd(40)} not published  (${entry.dir})`);
  if (problems.length === 0) {
    console.log(`OK: ${publishable.length} publishable package(s) at ${report.version} (Python frozen at ${report.python}, server.json and CHANGELOG in step), engines ${canonical(report.engines)}`);
  } else {
    console.error(`FAIL: ${problems.length} problem(s)`);
    for (const problem of problems) console.error(`  - ${problem}`);
  }
}
process.exit(problems.length === 0 ? 0 : 1);
