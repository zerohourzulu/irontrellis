#!/usr/bin/env node
/**
 * Verify the frozen Continuity v0.3.0-preview.10.2 oracle against its freeze list.
 *
 *   node packages/reference-0.3/verify-freeze.mjs          # exit 1 on any difference
 *   pnpm --filter @ramex-labs/irontrellis-reference-0.3 run verify-freeze
 *
 * FREEZE-LIST.txt is a byte-identical copy of the architect's
 * conformance/reference-0.3-FREEZE-LIST.txt (`sha256  path`, one line per file).
 * Every listed file must exist under this directory at its listed path with its
 * listed sha256, with one relocation: the frozen root `package.json` is kept as
 * `continuity-package.json`, because this directory's `package.json` is the
 * workspace manifest. Files that are neither frozen nor part of the wiring below
 * are reported too, so nothing can be added to the frozen tree unnoticed.
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const LIST = "FREEZE-LIST.txt";
/** sha256 of the freeze list itself, as recorded in the architect package's MANIFEST.json. */
const LIST_SHA256 = "5db4250ada62716f138588ba5de121650358d711fda54c53ba28d18ed8e5b73f";
/** Frozen paths stored under another name in this directory. */
const RELOCATED = { "package.json": "continuity-package.json" };
/**
 * Files in this directory that are wiring, not frozen material. LICENSING.md and THIRD-PARTY-NOTICES.md are the files the
 * frozen NOTICE refers to (they sat at the Continuity repository's root); IronTrellis adds them here, each with the
 * original text.
 */
const WIRING = new Set(["package.json", "README.md", "verify-freeze.mjs", LIST, "LICENSING.md", "THIRD-PARTY-NOTICES.md"]);
const IGNORED_DIRS = new Set(["node_modules"]);
/**
 * Scratch directory that packages/core-0.2/test/common-engine.test.mjs (case 15) creates inside the tree and
 * deliberately retains when it fails; it fails here because it needs the unfrozen integrations/agent-gateway.
 * Reported as a warning (delete it), never counted as frozen material.
 */
const SCRATCH = /^integrations\/\.core02-reader-check-[^/]+\//;

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const problems = [];
const scratch = new Set();

const listPath = join(HERE, LIST);
if (!existsSync(listPath)) {
  console.error(`verify-freeze: FAIL ${LIST} is missing`);
  process.exit(1);
}
const listHash = sha256(listPath);
if (listHash !== LIST_SHA256) problems.push(`${LIST}: sha256 ${listHash}, expected ${LIST_SHA256} (the freeze list itself was changed)`);

const entries = readFileSync(listPath, "utf8").split("\n").filter((line) => line.length > 0).map((line, index) => {
  const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
  if (match === null) throw new Error(`${LIST}:${index + 1}: malformed line ${JSON.stringify(line)}`);
  return { hash: match[1], path: match[2] };
});

const expected = new Set();
let ok = 0;
for (const { hash, path } of entries) {
  const stored = RELOCATED[path] ?? path;
  expected.add(stored);
  const abs = join(HERE, stored);
  if (!existsSync(abs)) { problems.push(`MISSING   ${path}${stored !== path ? ` (stored as ${stored})` : ""}`); continue; }
  const actual = sha256(abs);
  if (actual !== hash) { problems.push(`MODIFIED  ${path}${stored !== path ? ` (stored as ${stored})` : ""}: sha256 ${actual}, frozen ${hash}`); continue; }
  ok += 1;
}

function* walk(rel) {
  for (const entry of readdirSync(join(HERE, rel), { withFileTypes: true })) {
    const child = rel === "" ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) { if (!(rel === "" && IGNORED_DIRS.has(entry.name))) yield* walk(child); }
    else yield child;
  }
}
for (const file of walk("")) {
  if (expected.has(file) || (WIRING.has(file) && !file.includes("/"))) continue;
  const retained = SCRATCH.exec(file);
  if (retained !== null) { scratch.add(retained[0]); continue; }
  problems.push(`UNEXPECTED ${file} (not in the freeze list and not wiring)`);
}

for (const dir of scratch) console.warn(`verify-freeze: warning — ${dir} is a scratch directory retained by common-engine case 15; delete it`);
if (problems.length > 0) {
  console.error(`verify-freeze: FAIL — ${problems.length} problem(s); ${ok}/${entries.length} frozen files match`);
  for (const problem of problems) console.error(`  ${problem}`);
  console.error("The files under packages/reference-0.3 are frozen material (Continuity v0.3.0-preview.10.2). Restore them; never edit them.");
  process.exit(1);
}
console.log(`verify-freeze: OK — ${ok}/${entries.length} frozen files match ${LIST} (sha256 ${listHash})`);
